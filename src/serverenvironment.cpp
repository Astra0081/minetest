/*
Minetest
Copyright (C) 2010-2017 celeron55, Perttu Ahola <celeron55@gmail.com>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation; either version 2.1 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "serverenvironment.h"
#include "content_sao.h"
#include "settings.h"
#include "settings_builtin.h"
#include "log.h"
#include "mapblock.h"
#include "nodedef.h"
#include "nodemetadata.h"
#include "gamedef.h"
#include "map.h"
#include "profiler.h"
#include "raycast.h"
#include "remoteplayer.h"
#include "scripting_server.h"
#include "server.h"
#include "util/serialize.h"
#include "util/basic_macros.h"
#include "util/pointedthing.h"
#include "threading/mutex_auto_lock.h"
#include "filesys.h"
#include "gameparams.h"
#include "database/database-dummy.h"
#include "database/database-files.h"
#include "database/database-sqlite3.h"
#if USE_POSTGRESQL
#include "database/database-postgresql.h"
#endif
#include <algorithm>

#define LBM_NAME_ALLOWED_CHARS "abcdefghijklmnopqrstuvwxyz0123456789_:"

// A number that is much smaller than the timeout for particle spawners should/could ever be
#define PARTICLE_SPAWNER_NO_EXPIRY -1024.f

/*
	ABMWithState
*/

ABMWithState::ABMWithState(ActiveBlockModifier *abm_):
	abm(abm_)
{
	// Initialize timer to random value to spread processing
	float itv = abm->getTriggerInterval();
	itv = MYMAX(0.001, itv); // No less than 1ms
	int minval = MYMAX(-0.51*itv, -60); // Clamp to
	int maxval = MYMIN(0.51*itv, 60);   // +-60 seconds
	timer = myrand_range(minval, maxval);
}

/*
	LBMManager
*/

void LBMContentMapping::deleteContents()
{
	for (auto &it : lbm_list) {
		delete it;
	}
}

void LBMContentMapping::addLBM(LoadingBlockModifierDef *lbm_def, IGameDef *gamedef)
{
	// Add the lbm_def to the LBMContentMapping.
	// Unknown names get added to the global NameIdMapping.
	INodeDefManager *nodedef = gamedef->ndef();

	lbm_list.push_back(lbm_def);

	for (const std::string &nodeTrigger: lbm_def->trigger_contents) {
		std::vector<content_t> c_ids;
		bool found = nodedef->getIds(nodeTrigger, c_ids);
		if (!found) {
			content_t c_id = gamedef->allocateUnknownNodeId(nodeTrigger);
			if (c_id == CONTENT_IGNORE) {
				// Seems it can't be allocated.
				warningstream << "Could not internalize node name \"" << nodeTrigger
					<< "\" while loading LBM \"" << lbm_def->name << "\"." << std::endl;
				continue;
			}
			c_ids.push_back(c_id);
		}

		for (content_t c_id : c_ids) {
			map[c_id].push_back(lbm_def);
		}
	}
}

const std::vector<LoadingBlockModifierDef *> *
LBMContentMapping::lookup(content_t c) const
{
	lbm_map::const_iterator it = map.find(c);
	if (it == map.end())
		return NULL;
	// This first dereferences the iterator, returning
	// a std::vector<LoadingBlockModifierDef *>
	// reference, then we convert it to a pointer.
	return &(it->second);
}

LBMManager::~LBMManager()
{
	for (auto &m_lbm_def : m_lbm_defs) {
		delete m_lbm_def.second;
	}

	for (auto &it : m_lbm_lookup) {
		(it.second).deleteContents();
	}
}

void LBMManager::addLBMDef(LoadingBlockModifierDef *lbm_def)
{
	// Precondition, in query mode the map isn't used anymore
	FATAL_ERROR_IF(m_query_mode,
		"attempted to modify LBMManager in query mode");

	if (!string_allowed(lbm_def->name, LBM_NAME_ALLOWED_CHARS)) {
		throw ModError("Error adding LBM \"" + lbm_def->name +
			"\": Does not follow naming conventions: "
				"Only characters [a-z0-9_:] are allowed.");
	}

	m_lbm_defs[lbm_def->name] = lbm_def;
}

void LBMManager::loadIntroductionTimes(const std::string &times,
	IGameDef *gamedef, u32 now)
{
	m_query_mode = true;

	// name -> time map.
	// Storing it in a map first instead of
	// handling the stuff directly in the loop
	// removes all duplicate entries.
	// TODO make this std::unordered_map
	std::map<std::string, u32> introduction_times;

	/*
	The introduction times string consists of name~time entries,
	with each entry terminated by a semicolon. The time is decimal.
	 */

	size_t idx = 0;
	size_t idx_new;
	while ((idx_new = times.find(';', idx)) != std::string::npos) {
		std::string entry = times.substr(idx, idx_new - idx);
		std::vector<std::string> components = str_split(entry, '~');
		if (components.size() != 2)
			throw SerializationError("Introduction times entry \""
				+ entry + "\" requires exactly one '~'!");
		const std::string &name = components[0];
		u32 time = from_string<u32>(components[1]);
		introduction_times[name] = time;
		idx = idx_new + 1;
	}

	// Put stuff from introduction_times into m_lbm_lookup
	for (std::map<std::string, u32>::const_iterator it = introduction_times.begin();
		it != introduction_times.end(); ++it) {
		const std::string &name = it->first;
		u32 time = it->second;

		std::map<std::string, LoadingBlockModifierDef *>::iterator def_it =
			m_lbm_defs.find(name);
		if (def_it == m_lbm_defs.end()) {
			// This seems to be an LBM entry for
			// an LBM we haven't loaded. Discard it.
			continue;
		}
		LoadingBlockModifierDef *lbm_def = def_it->second;
		if (lbm_def->run_at_every_load) {
			// This seems to be an LBM entry for
			// an LBM that runs at every load.
			// Don't add it just yet.
			continue;
		}

		m_lbm_lookup[time].addLBM(lbm_def, gamedef);

		// Erase the entry so that we know later
		// what elements didn't get put into m_lbm_lookup
		m_lbm_defs.erase(name);
	}

	// Now also add the elements from m_lbm_defs to m_lbm_lookup
	// that weren't added in the previous step.
	// They are introduced first time to this world,
	// or are run at every load (introducement time hardcoded to U32_MAX).

	LBMContentMapping &lbms_we_introduce_now = m_lbm_lookup[now];
	LBMContentMapping &lbms_running_always = m_lbm_lookup[U32_MAX];

	for (auto &m_lbm_def : m_lbm_defs) {
		if (m_lbm_def.second->run_at_every_load) {
			lbms_running_always.addLBM(m_lbm_def.second, gamedef);
		} else {
			lbms_we_introduce_now.addLBM(m_lbm_def.second, gamedef);
		}
	}

	// Clear the list, so that we don't delete remaining elements
	// twice in the destructor
	m_lbm_defs.clear();
}

std::string LBMManager::createIntroductionTimesString()
{
	// Precondition, we must be in query mode
	FATAL_ERROR_IF(!m_query_mode,
		"attempted to query on non fully set up LBMManager");

	std::ostringstream oss;
	for (const auto &it : m_lbm_lookup) {
		u32 time = it.first;
		const std::vector<LoadingBlockModifierDef *> &lbm_list = it.second.lbm_list;
		for (const auto &lbm_def : lbm_list) {
			// Don't add if the LBM runs at every load,
			// then introducement time is hardcoded
			// and doesn't need to be stored
			if (lbm_def->run_at_every_load)
				continue;
			oss << lbm_def->name << "~" << time << ";";
		}
	}
	return oss.str();
}

void LBMManager::applyLBMs(ServerEnvironment *env, MapBlock *block, u32 stamp)
{
	// Precondition, we need m_lbm_lookup to be initialized
	FATAL_ERROR_IF(!m_query_mode,
		"attempted to query on non fully set up LBMManager");
	v3s16 pos_of_block = block->getPosRelative();
	v3s16 pos;
	MapNode n;
	content_t c;
	lbm_lookup_map::const_iterator it = getLBMsIntroducedAfter(stamp);
	for (pos.X = 0; pos.X < MAP_BLOCKSIZE; pos.X++)
		for (pos.Y = 0; pos.Y < MAP_BLOCKSIZE; pos.Y++)
			for (pos.Z = 0; pos.Z < MAP_BLOCKSIZE; pos.Z++)
			{
				n = block->getNodeNoEx(pos);
				c = n.getContent();
				for (LBMManager::lbm_lookup_map::const_iterator iit = it;
					iit != m_lbm_lookup.end(); ++iit) {
					const std::vector<LoadingBlockModifierDef *> *lbm_list =
						iit->second.lookup(c);
					if (!lbm_list)
						continue;
					for (auto lbmdef : *lbm_list) {
						lbmdef->trigger(env, pos + pos_of_block, n);
					}
				}
			}
}

/*
	ActiveBlockList
*/

void fillRadiusBlock(v3s16 p0, s16 r, std::set<v3s16> &list)
{
	v3s16 p;
	for(p.X=p0.X-r; p.X<=p0.X+r; p.X++)
		for(p.Y=p0.Y-r; p.Y<=p0.Y+r; p.Y++)
			for(p.Z=p0.Z-r; p.Z<=p0.Z+r; p.Z++)
			{
				// limit to a sphere
				if (p.getDistanceFrom(p0) <= r) {
					// Set in list
					list.insert(p);
				}
			}
}

void fillViewConeBlock(v3s16 p0,
	const s16 r,
	const v3f camera_pos,
	const v3f camera_dir,
	const float camera_fov,
	std::set<v3s16> &list)
{
	v3s16 p;
	const s16 r_nodes = r * BS * MAP_BLOCKSIZE;
	for (p.X = p0.X - r; p.X <= p0.X+r; p.X++)
	for (p.Y = p0.Y - r; p.Y <= p0.Y+r; p.Y++)
	for (p.Z = p0.Z - r; p.Z <= p0.Z+r; p.Z++) {
		if (isBlockInSight(p, camera_pos, camera_dir, camera_fov, r_nodes)) {
			list.insert(p);
		}
	}
}

void ActiveBlockList::update(std::vector<PlayerSAO*> &active_players,
	s16 active_block_range,
	s16 active_object_range,
	std::set<v3s16> &blocks_removed,
	std::set<v3s16> &blocks_added)
{
	/*
		Create the new list
	*/
	std::set<v3s16> newlist = m_forceloaded_list;
	m_abm_list = m_forceloaded_list;
	for (const PlayerSAO *playersao : active_players) {
		v3s16 pos = getNodeBlockPos(floatToInt(playersao->getBasePosition(), BS));
		fillRadiusBlock(pos, active_block_range, m_abm_list);
		fillRadiusBlock(pos, active_block_range, newlist);

		s16 player_ao_range = std::min(active_object_range, playersao->getWantedRange());
		// only do this if this would add blocks
		if (player_ao_range > active_block_range) {
			v3f camera_dir = v3f(0,0,1);
			camera_dir.rotateYZBy(playersao->getPitch());
			camera_dir.rotateXZBy(playersao->getYaw());
			fillViewConeBlock(pos,
				player_ao_range,
				playersao->getEyePosition(),
				camera_dir,
				playersao->getFov(),
				newlist);
		}
	}

	/*
		Find out which blocks on the old list are not on the new list
	*/
	// Go through old list
	for (v3s16 p : m_list) {
		// If not on new list, it's been removed
		if (newlist.find(p) == newlist.end())
			blocks_removed.insert(p);
	}

	/*
		Find out which blocks on the new list are not on the old list
	*/
	// Go through new list
	for (v3s16 p : newlist) {
		// If not on old list, it's been added
		if(m_list.find(p) == m_list.end())
			blocks_added.insert(p);
	}

	/*
		Update m_list
	*/
	m_list.clear();
	for (v3s16 p : newlist) {
		m_list.insert(p);
	}
}

/*
	ServerEnvironment
*/

ServerEnvironment::ServerEnvironment(ServerMap *map,
	ServerScripting *scriptIface, Server *server,
	const std::string &path_world):
	Environment(server),
	m_map(map),
	m_script(scriptIface),
	m_server(server),
	m_path_world(path_world)
{
	// Determine which database backend to use
	std::string conf_path = path_world + DIR_DELIM + "world.mt";
	Settings conf;
	bool succeeded = conf.readConfigFile(conf_path.c_str());
	if (!succeeded || !conf.exists("player_backend")) {
		// fall back to files
		conf.set("player_backend", "files");
		warningstream << "/!\\ You are using old player file backend. "
				<< "This backend is deprecated and will be removed in next release /!\\"
				<< std::endl << "Switching to SQLite3 or PostgreSQL is advised, "
				<< "please read http://wiki.minetest.net/Database_backends." << std::endl;

		if (!conf.updateConfigFile(conf_path.c_str())) {
			errorstream << "ServerEnvironment::ServerEnvironment(): "
				<< "Failed to update world.mt!" << std::endl;
		}
	}

	std::string name;
	conf.getNoEx("player_backend", name);
	m_player_database = openPlayerDatabase(name, path_world, conf);
}

ServerEnvironment::~ServerEnvironment()
{
	// Clear active block list.
	// This makes the next one delete all active objects.
	m_active_blocks.clear();

	// Convert all objects to static and delete the active objects
	deactivateFarObjects(true);

	// Drop/delete map
	m_map->drop();

	// Delete ActiveBlockModifiers
	for (ABMWithState &m_abm : m_abms) {
		delete m_abm.abm;
	}

	// Deallocate players
	for (RemotePlayer *m_player : m_players) {
		delete m_player;
	}

	delete m_player_database;
}

Map & ServerEnvironment::getMap()
{
	return *m_map;
}

ServerMap & ServerEnvironment::getServerMap()
{
	return *m_map;
}

RemotePlayer *ServerEnvironment::getPlayer(const session_t peer_id)
{
	for (RemotePlayer *player : m_players) {
		if (player->getPeerId() == peer_id)
			return player;
	}
	return NULL;
}

RemotePlayer *ServerEnvironment::getPlayer(const char* name)
{
	for (RemotePlayer *player : m_players) {
		if (strcmp(player->getName(), name) == 0)
			return player;
	}
	return NULL;
}

void ServerEnvironment::addPlayer(RemotePlayer *player)
{
	/*
		Check that peer_ids are unique.
		Also check that names are unique.
		Exception: there can be multiple players with peer_id=0
	*/
	// If peer id is non-zero, it has to be unique.
	if (player->getPeerId() != PEER_ID_INEXISTENT)
		FATAL_ERROR_IF(getPlayer(player->getPeerId()) != NULL, "Peer id not unique");
	// Name has to be unique.
	FATAL_ERROR_IF(getPlayer(player->getName()) != NULL, "Player name not unique");
	// Add.
	m_players.push_back(player);
}

void ServerEnvironment::removePlayer(RemotePlayer *player)
{
	for (std::vector<RemotePlayer *>::iterator it = m_players.begin();
		it != m_players.end(); ++it) {
		if ((*it) == player) {
			delete *it;
			m_players.erase(it);
			return;
		}
	}
}

bool ServerEnvironment::removePlayerFromDatabase(const std::string &name)
{
	return m_player_database->removePlayer(name);
}

bool ServerEnvironment::line_of_sight(v3f pos1, v3f pos2, v3s16 *p)
{
	// Iterate trough nodes on the line
	voxalgo::VoxelLineIterator iterator(pos1 / BS, (pos2 - pos1) / BS);
	do {
		MapNode n = getMap().getNodeNoEx(iterator.m_current_node_pos);

		// Return non-air
		if (n.param0 != CONTENT_AIR) {
			if (p)
				*p = iterator.m_current_node_pos;
			return false;
		}
		iterator.next();
	} while (iterator.m_current_index <= iterator.m_last_index);
	return true;
}

void ServerEnvironment::kickAllPlayers(AccessDeniedCode reason,
	const std::string &str_reason, bool reconnect)
{
	for (RemotePlayer *player : m_players) {
		m_server->DenyAccessVerCompliant(player->getPeerId(),
			player->protocol_version, reason, str_reason, reconnect);
	}
}

void ServerEnvironment::saveLoadedPlayers()
{
	std::string players_path = m_path_world + DIR_DELIM + "players";
	fs::CreateDir(players_path);

	for (RemotePlayer *player : m_players) {
		if (player->checkModified() || (player->getPlayerSAO() &&
				player->getPlayerSAO()->extendedAttributesModified())) {
			try {
				m_player_database->savePlayer(player);
			} catch (DatabaseException &e) {
				errorstream << "Failed to save player " << player->getName() << " exception: "
					<< e.what() << std::endl;
				throw;
			}
		}
	}
}

void ServerEnvironment::savePlayer(RemotePlayer *player)
{
	try {
		m_player_database->savePlayer(player);
	} catch (DatabaseException &e) {
		errorstream << "Failed to save player " << player->getName() << " exception: "
			<< e.what() << std::endl;
		throw;
	}
}

PlayerSAO *ServerEnvironment::loadPlayer(RemotePlayer *player, bool *new_player,
	session_t peer_id, bool is_singleplayer)
{
	PlayerSAO *playersao = new PlayerSAO(this, player, peer_id, is_singleplayer);
	// Create player if it doesn't exist
	if (!m_player_database->loadPlayer(player, playersao)) {
		*new_player = true;
		// Set player position
		infostream << "Server: Finding spawn place for player \""
			<< player->getName() << "\"" << std::endl;
		playersao->setBasePosition(m_server->findSpawnPos());

		// Make sure the player is saved
		player->setModified(true);
	} else {
		// If the player exists, ensure that they respawn inside legal bounds
		// This fixes an assert crash when the player can't be added
		// to the environment
		ServerMap &map = getServerMap();
		if (map.getMapgenParams()->saoPosOverLimit(playersao->getBasePosition())) {
			actionstream << "Respawn position for player \""
				<< player->getName() << "\" outside limits, resetting" << std::endl;
			playersao->setBasePosition(m_server->findSpawnPos());
		}
	}

	// Add player to environment
	addPlayer(player);

	/* Clean up old HUD elements from previous sessions */
	player->clearHud();

	/* Add object to environment */
	addActiveObject(playersao);

	return playersao;
}

void ServerEnvironment::saveMeta()
{
	std::string path = m_path_world + DIR_DELIM "env_meta.txt";

	// Open file and serialize
	std::ostringstream ss(std::ios_base::binary);

	Settings args;
	args.setU64("game_time", m_game_time);
	args.setU64("time_of_day", getTimeOfDay());
	args.setU64("last_clear_objects_time", m_last_clear_objects_time);
	args.setU64("lbm_introduction_times_version", 1);
	args.set("lbm_introduction_times",
		m_lbm_mgr.createIntroductionTimesString());
	args.setU64("day_count", m_day_count);
	args.writeLines(ss);
	ss<<"EnvArgsEnd\n";

	if(!fs::safeWriteToFile(path, ss.str()))
	{
		infostream<<"ServerEnvironment::saveMeta(): Failed to write "
			<<path<<std::endl;
		throw SerializationError("Couldn't save env meta");
	}
}

void ServerEnvironment::loadMeta()
{
	std::string path = m_path_world + DIR_DELIM "env_meta.txt";

	// Open file and deserialize
	std::ifstream is(path.c_str(), std::ios_base::binary);
	if (!is.good()) {
		infostream << "ServerEnvironment::loadMeta(): Failed to open "
			<< path << std::endl;
		throw SerializationError("Couldn't load env meta");
	}

	Settings args;

	if (!args.parseConfigLines(is, "EnvArgsEnd")) {
		throw SerializationError("ServerEnvironment::loadMeta(): "
			"EnvArgsEnd not found!");
	}

	try {
		m_game_time = args.getU64("game_time");
	} catch (SettingNotFoundException &e) {
		// Getting this is crucial, otherwise timestamps are useless
		throw SerializationError("Couldn't load env meta game_time");
	}

	setTimeOfDay(args.exists("time_of_day") ?
		// set day to early morning by default
		args.getU64("time_of_day") : 5250);

	m_last_clear_objects_time = args.exists("last_clear_objects_time") ?
		// If missing, do as if clearObjects was never called
		args.getU64("last_clear_objects_time") : 0;

	std::string lbm_introduction_times;
	try {
		u64 ver = args.getU64("lbm_introduction_times_version");
		if (ver == 1) {
			lbm_introduction_times = args.get("lbm_introduction_times");
		} else {
			infostream << "ServerEnvironment::loadMeta(): Non-supported"
				<< " introduction time version " << ver << std::endl;
		}
	} catch (SettingNotFoundException &e) {
		// No problem, this is expected. Just continue with an empty string
	}
	m_lbm_mgr.loadIntroductionTimes(lbm_introduction_times, m_server, m_game_time);

	m_day_count = args.exists("day_count") ?
		args.getU64("day_count") : 0;
}

void ServerEnvironment::loadDefaultMeta()
{
	m_lbm_mgr.loadIntroductionTimes("", m_server, m_game_time);
}

struct ActiveABM
{
	ActiveBlockModifier *abm;
	int chance;
	std::vector<content_t> required_neighbors;
	bool check_required_neighbors; // false if required_neighbors is known to be empty
};

class ABMHandler
{
private:
	ServerEnvironment *m_env;
	std::vector<std::vector<ActiveABM> *> m_aabms;
public:
	ABMHandler(std::vector<ABMWithState> &abms,
		float dtime_s, ServerEnvironment *env,
		bool use_timers):
		m_env(env)
	{
		if(dtime_s < 0.001)
			return;
		INodeDefManager *ndef = env->getGameDef()->ndef();
		for (ABMWithState &abmws : abms) {
			ActiveBlockModifier *abm = abmws.abm;
			float trigger_interval = abm->getTriggerInterval();
			if(trigger_interval < 0.001)
				trigger_interval = 0.001;
			float actual_interval = dtime_s;
			if(use_timers){
				abmws.timer += dtime_s;
				if(abmws.timer < trigger_interval)
					continue;
				abmws.timer -= trigger_interval;
				actual_interval = trigger_interval;
			}
			float chance = abm->getTriggerChance();
			if(chance == 0)
				chance = 1;
			ActiveABM aabm;
			aabm.abm = abm;
			if (abm->getSimpleCatchUp()) {
				float intervals = actual_interval / trigger_interval;
				if(intervals == 0)
					continue;
				aabm.chance = chance / intervals;
				if(aabm.chance == 0)
					aabm.chance = 1;
			} else {
				aabm.chance = chance;
			}

			// Trigger neighbors
			const std::vector<std::string> &required_neighbors_s =
				abm->getRequiredNeighbors();
			for (const std::string &required_neighbor_s : required_neighbors_s) {
				ndef->getIds(required_neighbor_s, aabm.required_neighbors);
			}
			aabm.check_required_neighbors = !required_neighbors_s.empty();

			// Trigger contents
			const std::vector<std::string> &contents_s = abm->getTriggerContents();
			for (const std::string &content_s : contents_s) {
				std::vector<content_t> ids;
				ndef->getIds(content_s, ids);
				for (content_t c : ids) {
					if (c >= m_aabms.size())
						m_aabms.resize(c + 256, NULL);
					if (!m_aabms[c])
						m_aabms[c] = new std::vector<ActiveABM>;
					m_aabms[c]->push_back(aabm);
				}
			}
		}
	}

	~ABMHandler()
	{
		for (auto &aabms : m_aabms)
			delete aabms;
	}

	// Find out how many objects the given block and its neighbours contain.
	// Returns the number of objects in the block, and also in 'wider' the
	// number of objects in the block and all its neighbours. The latter
	// may an estimate if any neighbours are unloaded.
	u32 countObjects(MapBlock *block, ServerMap * map, u32 &wider)
	{
		wider = 0;
		u32 wider_unknown_count = 0;
		for(s16 x=-1; x<=1; x++)
			for(s16 y=-1; y<=1; y++)
				for(s16 z=-1; z<=1; z++)
				{
					MapBlock *block2 = map->getBlockNoCreateNoEx(
						block->getPos() + v3s16(x,y,z));
					if(block2==NULL){
						wider_unknown_count++;
						continue;
					}
					wider += block2->m_static_objects.m_active.size()
						+ block2->m_static_objects.m_stored.size();
				}
		// Extrapolate
		u32 active_object_count = block->m_static_objects.m_active.size();
		u32 wider_known_count = 3*3*3 - wider_unknown_count;
		wider += wider_unknown_count * wider / wider_known_count;
		return active_object_count;

	}
	void apply(MapBlock *block)
	{
		if(m_aabms.empty() || block->isDummy())
			return;

		ServerMap *map = &m_env->getServerMap();

		u32 active_object_count_wider;
		u32 active_object_count = this->countObjects(block, map, active_object_count_wider);
		m_env->m_added_objects = 0;

		v3s16 p0;
		for(p0.X=0; p0.X<MAP_BLOCKSIZE; p0.X++)
		for(p0.Y=0; p0.Y<MAP_BLOCKSIZE; p0.Y++)
		for(p0.Z=0; p0.Z<MAP_BLOCKSIZE; p0.Z++)
		{
			const MapNode &n = block->getNodeUnsafe(p0);
			content_t c = n.getContent();

			if (c >= m_aabms.size() || !m_aabms[c])
				continue;

			v3s16 p = p0 + block->getPosRelative();
			for (ActiveABM &aabm : *m_aabms[c]) {
				if (myrand() % aabm.chance != 0)
					continue;

				// Check neighbors
				if (aabm.check_required_neighbors) {
					v3s16 p1;
					for(p1.X = p0.X-1; p1.X <= p0.X+1; p1.X++)
					for(p1.Y = p0.Y-1; p1.Y <= p0.Y+1; p1.Y++)
					for(p1.Z = p0.Z-1; p1.Z <= p0.Z+1; p1.Z++)
					{
						if(p1 == p0)
							continue;
						content_t c;
						if (block->isValidPosition(p1)) {
							// if the neighbor is found on the same map block
							// get it straight from there
							const MapNode &n = block->getNodeUnsafe(p1);
							c = n.getContent();
						} else {
							// otherwise consult the map
							MapNode n = map->getNodeNoEx(p1 + block->getPosRelative());
							c = n.getContent();
						}
						if (CONTAINS(aabm.required_neighbors, c))
							goto neighbor_found;
					}
					// No required neighbor found
					continue;
				}
				neighbor_found:

				// Call all the trigger variations
				aabm.abm->trigger(m_env, p, n);
				aabm.abm->trigger(m_env, p, n,
					active_object_count, active_object_count_wider);

				// Count surrounding objects again if the abms added any
				if(m_env->m_added_objects > 0) {
					active_object_count = countObjects(block, map, active_object_count_wider);
					m_env->m_added_objects = 0;
				}
			}
		}
	}
};

void ServerEnvironment::activateBlock(MapBlock *block, u32 additional_dtime)
{
	// Reset usage timer immediately, otherwise a block that becomes active
	// again at around the same time as it would normally be unloaded will
	// get unloaded incorrectly. (I think this still leaves a small possibility
	// of a race condition between this and server::AsyncRunStep, which only
	// some kind of synchronisation will fix, but it at least reduces the window
	// of opportunity for it to break from seconds to nanoseconds)
	block->resetUsageTimer();

	// Get time difference
	u32 dtime_s = 0;
	u32 stamp = block->getTimestamp();
	if (m_game_time > stamp && stamp != BLOCK_TIMESTAMP_UNDEFINED)
		dtime_s = m_game_time - stamp;
	dtime_s += additional_dtime;

	/*infostream<<"ServerEnvironment::activateBlock(): block timestamp: "
			<<stamp<<", game time: "<<m_game_time<<std::endl;*/

	// Remove stored static objects if clearObjects was called since block's timestamp
	if (stamp == BLOCK_TIMESTAMP_UNDEFINED || stamp < m_last_clear_objects_time) {
		block->m_static_objects.m_stored.clear();
		// do not set changed flag to avoid unnecessary mapblock writes
	}

	// Set current time as timestamp
	block->setTimestampNoChangedFlag(m_game_time);

	/*infostream<<"ServerEnvironment::activateBlock(): block is "
			<<dtime_s<<" seconds old."<<std::endl;*/

	// Activate stored objects
	activateObjects(block, dtime_s);

	/* Handle LoadingBlockModifiers */
	m_lbm_mgr.applyLBMs(this, block, stamp);

	// Run node timers
	std::vector<NodeTimer> elapsed_timers =
		block->m_node_timers.step((float)dtime_s);
	if (!elapsed_timers.empty()) {
		MapNode n;
		for (const NodeTimer &elapsed_timer : elapsed_timers) {
			n = block->getNodeNoEx(elapsed_timer.position);
			v3s16 p = elapsed_timer.position + block->getPosRelative();
			if (m_script->node_on_timer(p, n, elapsed_timer.elapsed))
				block->setNodeTimer(NodeTimer(elapsed_timer.timeout, 0,
					elapsed_timer.position));
		}
	}
}

void ServerEnvironment::addActiveBlockModifier(ActiveBlockModifier *abm)
{
	m_abms.emplace_back(abm);
}

void ServerEnvironment::addLoadingBlockModifierDef(LoadingBlockModifierDef *lbm)
{
	m_lbm_mgr.addLBMDef(lbm);
}

bool ServerEnvironment::setNode(v3s16 p, const MapNode &n)
{
	INodeDefManager *ndef = m_server->ndef();
	MapNode n_old = m_map->getNodeNoEx(p);

	const ContentFeatures &cf_old = ndef->get(n_old);

	// Call destructor
	if (cf_old.has_on_destruct)
		m_script->node_on_destruct(p, n_old);

	// Replace node
	if (!m_map->addNodeWithEvent(p, n))
		return false;

	// Update active VoxelManipulator if a mapgen thread
	m_map->updateVManip(p);

	// Call post-destructor
	if (cf_old.has_after_destruct)
		m_script->node_after_destruct(p, n_old);

	// Retrieve node content features
	// if new node is same as old, reuse old definition to prevent a lookup
	const ContentFeatures &cf_new = n_old == n ? cf_old : ndef->get(n);

	// Call constructor
	if (cf_new.has_on_construct)
		m_script->node_on_construct(p, n);

	return true;
}

bool ServerEnvironment::removeNode(v3s16 p)
{
	INodeDefManager *ndef = m_server->ndef();
	MapNode n_old = m_map->getNodeNoEx(p);

	// Call destructor
	if (ndef->get(n_old).has_on_destruct)
		m_script->node_on_destruct(p, n_old);

	// Replace with air
	// This is slightly optimized compared to addNodeWithEvent(air)
	if (!m_map->removeNodeWithEvent(p))
		return false;

	// Update active VoxelManipulator if a mapgen thread
	m_map->updateVManip(p);

	// Call post-destructor
	if (ndef->get(n_old).has_after_destruct)
		m_script->node_after_destruct(p, n_old);

	// Air doesn't require constructor
	return true;
}

bool ServerEnvironment::swapNode(v3s16 p, const MapNode &n)
{
	if (!m_map->addNodeWithEvent(p, n, false))
		return false;

	// Update active VoxelManipulator if a mapgen thread
	m_map->updateVManip(p);

	return true;
}

void ServerEnvironment::getObjectsInsideRadius(std::vector<u16> &objects, v3f pos,
	float radius)
{
	for (auto &activeObject : m_active_objects) {
		ServerActiveObject* obj = activeObject.second;
		u16 id = activeObject.first;
		v3f objectpos = obj->getBasePosition();
		if (objectpos.getDistanceFrom(pos) > radius)
			continue;
		objects.push_back(id);
	}
}

void ServerEnvironment::clearObjects(ClearObjectsMode mode)
{
	infostream << "ServerEnvironment::clearObjects(): "
		<< "Removing all active objects" << std::endl;
	std::vector<u16> objects_to_remove;
	for (auto &it : m_active_objects) {
		u16 id = it.first;
		ServerActiveObject* obj = it.second;
		if (obj->getType() == ACTIVEOBJECT_TYPE_PLAYER)
			continue;

		// Delete static object if block is loaded
		deleteStaticFromBlock(obj, id, MOD_REASON_CLEAR_ALL_OBJECTS, true);

		// If known by some client, don't delete immediately
		if (obj->m_known_by_count > 0) {
			obj->m_pending_removal = true;
			continue;
		}

		// Tell the object about removal
		obj->removingFromEnvironment();
		// Deregister in scripting api
		m_script->removeObjectReference(obj);

		// Delete active object
		if (obj->environmentDeletes())
			delete obj;
		// Id to be removed from m_active_objects
		objects_to_remove.push_back(id);
	}

	// Remove references from m_active_objects
	for (u16 i : objects_to_remove) {
		m_active_objects.erase(i);
	}

	// Get list of loaded blocks
	std::vector<v3s16> loaded_blocks;
	infostream << "ServerEnvironment::clearObjects(): "
		<< "Listing all loaded blocks" << std::endl;
	m_map->listAllLoadedBlocks(loaded_blocks);
	infostream << "ServerEnvironment::clearObjects(): "
		<< "Done listing all loaded blocks: "
		<< loaded_blocks.size()<<std::endl;

	// Get list of loadable blocks
	std::vector<v3s16> loadable_blocks;
	if (mode == CLEAR_OBJECTS_MODE_FULL) {
		infostream << "ServerEnvironment::clearObjects(): "
			<< "Listing all loadable blocks" << std::endl;
		m_map->listAllLoadableBlocks(loadable_blocks);
		infostream << "ServerEnvironment::clearObjects(): "
			<< "Done listing all loadable blocks: "
			<< loadable_blocks.size() << std::endl;
	} else {
		loadable_blocks = loaded_blocks;
	}

	actionstream << "ServerEnvironment::clearObjects(): "
		<< "Now clearing objects in " << loadable_blocks.size()
		<< " blocks" << std::endl;

	// Grab a reference on each loaded block to avoid unloading it
	for (v3s16 p : loaded_blocks) {
		MapBlock *block = m_map->getBlockNoCreateNoEx(p);
		assert(block != NULL);
		block->refGrab();
	}

	// Remove objects in all loadable blocks
	u32 unload_interval = U32_MAX;
	if (mode == CLEAR_OBJECTS_MODE_FULL) {
		unload_interval = g_settings->getS32("max_clearobjects_extra_loaded_blocks");
		unload_interval = MYMAX(unload_interval, 1);
	}
	u32 report_interval = loadable_blocks.size() / 10;
	u32 num_blocks_checked = 0;
	u32 num_blocks_cleared = 0;
	u32 num_objs_cleared = 0;
	for (auto i = loadable_blocks.begin();
		i != loadable_blocks.end(); ++i) {
		v3s16 p = *i;
		MapBlock *block = m_map->emergeBlock(p, false);
		if (!block) {
			errorstream << "ServerEnvironment::clearObjects(): "
				<< "Failed to emerge block " << PP(p) << std::endl;
			continue;
		}
		u32 num_stored = block->m_static_objects.m_stored.size();
		u32 num_active = block->m_static_objects.m_active.size();
		if (num_stored != 0 || num_active != 0) {
			block->m_static_objects.m_stored.clear();
			block->m_static_objects.m_active.clear();
			block->raiseModified(MOD_STATE_WRITE_NEEDED,
				MOD_REASON_CLEAR_ALL_OBJECTS);
			num_objs_cleared += num_stored + num_active;
			num_blocks_cleared++;
		}
		num_blocks_checked++;

		if (report_interval != 0 &&
			num_blocks_checked % report_interval == 0) {
			float percent = 100.0 * (float)num_blocks_checked /
				loadable_blocks.size();
			actionstream << "ServerEnvironment::clearObjects(): "
				<< "Cleared " << num_objs_cleared << " objects"
				<< " in " << num_blocks_cleared << " blocks ("
				<< percent << "%)" << std::endl;
		}
		if (num_blocks_checked % unload_interval == 0) {
			m_map->unloadUnreferencedBlocks();
		}
	}
	m_map->unloadUnreferencedBlocks();

	// Drop references that were added above
	for (v3s16 p : loaded_blocks) {
		MapBlock *block = m_map->getBlockNoCreateNoEx(p);
		assert(block);
		block->refDrop();
	}

	m_last_clear_objects_time = m_game_time;

	actionstream << "ServerEnvironment::clearObjects(): "
		<< "Finished: Cleared " << num_objs_cleared << " objects"
		<< " in " << num_blocks_cleared << " blocks" << std::endl;
}

void ServerEnvironment::step(float dtime)
{
	/* Step time of day */
	stepTimeOfDay(dtime);

	// Update this one
	// NOTE: This is kind of funny on a singleplayer game, but doesn't
	// really matter that much.
	const float server_step =builtin_settings.dedicated_server_step;
	m_recommended_send_interval = server_step;

	/*
		Increment game time
	*/
	{
		m_game_time_fraction_counter += dtime;
		u32 inc_i = (u32)m_game_time_fraction_counter;
		m_game_time += inc_i;
		m_game_time_fraction_counter -= (float)inc_i;
	}

	/*
		Handle players
	*/
	{
		ScopeProfiler sp(g_profiler, "SEnv: handle players avg", SPT_AVG);
		for (RemotePlayer *player : m_players) {
			// Ignore disconnected players
			if (player->getPeerId() == PEER_ID_INEXISTENT)
				continue;

			// Move
			player->move(dtime, this, 100 * BS);
		}
	}

	/*
		Manage active block list
	*/
	if (m_active_blocks_management_interval.step(dtime, m_cache_active_block_mgmt_interval)) {
		ScopeProfiler sp(g_profiler, "SEnv: manage act. block list avg per interval", SPT_AVG);
		/*
			Get player block positions
		*/
		std::vector<PlayerSAO*> players;
		for (RemotePlayer *player: m_players) {
			// Ignore disconnected players
			if (player->getPeerId() == PEER_ID_INEXISTENT)
				continue;

			PlayerSAO *playersao = player->getPlayerSAO();
			assert(playersao);

			players.push_back(playersao);
		}

		/*
			Update list of active blocks, collecting changes
		*/
		// use active_object_send_range_blocks since that is max distance
		// for active objects sent the client anyway
		const s16 active_object_range = builtin_settings.active_object_send_range_blocks;
		const s16 active_block_range = builtin_settings.active_block_range;
		std::set<v3s16> blocks_removed;
		std::set<v3s16> blocks_added;
		m_active_blocks.update(players, active_block_range, active_object_range,
			blocks_removed, blocks_added);

		/*
			Handle removed blocks
		*/

		// Convert active objects that are no more in active blocks to static
		deactivateFarObjects(false);

		for (const v3s16 &p: blocks_removed) {
			MapBlock *block = m_map->getBlockNoCreateNoEx(p);
			if (!block)
				continue;

			// Set current time as timestamp (and let it set ChangedFlag)
			block->setTimestamp(m_game_time);
		}

		/*
			Handle added blocks
		*/

		for (const v3s16 &p: blocks_added) {
			MapBlock *block = m_map->getBlockOrEmerge(p);
			if (!block) {
				m_active_blocks.m_list.erase(p);
				m_active_blocks.m_abm_list.erase(p);
				continue;
			}

			activateBlock(block);
		}
	}

	/*
		Mess around in active blocks
	*/
	if (m_active_blocks_nodemetadata_interval.step(dtime, m_cache_nodetimer_interval)) {
		ScopeProfiler sp(g_profiler, "SEnv: mess in act. blocks avg per interval", SPT_AVG);

		float dtime = m_cache_nodetimer_interval;

		for (const v3s16 &p: m_active_blocks.m_list) {
			MapBlock *block = m_map->getBlockNoCreateNoEx(p);
			if (!block)
				continue;

			// Reset block usage timer
			block->resetUsageTimer();

			// Set current time as timestamp
			block->setTimestampNoChangedFlag(m_game_time);
			// If time has changed much from the one on disk,
			// set block to be saved when it is unloaded
			if(block->getTimestamp() > block->getDiskTimestamp() + 60)
				block->raiseModified(MOD_STATE_WRITE_AT_UNLOAD,
					MOD_REASON_BLOCK_EXPIRED);

			// Run node timers
			std::vector<NodeTimer> elapsed_timers = block->m_node_timers.step(dtime);
			if (!elapsed_timers.empty()) {
				MapNode n;
				v3s16 p2;
				for (const NodeTimer &elapsed_timer: elapsed_timers) {
					n = block->getNodeNoEx(elapsed_timer.position);
					p2 = elapsed_timer.position + block->getPosRelative();
					if (m_script->node_on_timer(p2, n, elapsed_timer.elapsed)) {
						block->setNodeTimer(NodeTimer(
							elapsed_timer.timeout, 0, elapsed_timer.position));
					}
				}
			}
		}
	}

	if (m_active_block_modifier_interval.step(dtime, m_cache_abm_interval))
		do { // breakable
			if (m_active_block_interval_overload_skip > 0) {
				ScopeProfiler sp(g_profiler, "SEnv: ABM overload skips");
				m_active_block_interval_overload_skip--;
				break;
			}
			ScopeProfiler sp(g_profiler, "SEnv: modify in blocks avg per interval", SPT_AVG);
			TimeTaker timer("modify in active blocks per interval");

			// Initialize handling of ActiveBlockModifiers
			ABMHandler abmhandler(m_abms, m_cache_abm_interval, this, true);

			for (const v3s16 &p : m_active_blocks.m_abm_list) {
				MapBlock *block = m_map->getBlockNoCreateNoEx(p);
				if (!block)
					continue;

				// Set current time as timestamp
				block->setTimestampNoChangedFlag(m_game_time);

				/* Handle ActiveBlockModifiers */
				abmhandler.apply(block);
			}

			u32 time_ms = timer.stop(true);
			u32 max_time_ms = 200;
			if (time_ms > max_time_ms) {
				warningstream<<"active block modifiers took "
					<<time_ms<<"ms (longer than "
					<<max_time_ms<<"ms)"<<std::endl;
				m_active_block_interval_overload_skip = (time_ms / max_time_ms) + 1;
			}
		}while(0);

	/*
		Step script environment (run global on_step())
	*/
	m_script->environment_Step(dtime);

	/*
		Step active objects
	*/
	{
		ScopeProfiler sp(g_profiler, "SEnv: step act. objs avg", SPT_AVG);
		//TimeTaker timer("Step active objects");

		g_profiler->avg("SEnv: num of objects", m_active_objects.size());

		// This helps the objects to send data at the same time
		bool send_recommended = false;
		m_send_recommended_timer += dtime;
		if(m_send_recommended_timer > getSendRecommendedInterval())
		{
			m_send_recommended_timer -= getSendRecommendedInterval();
			send_recommended = true;
		}

		for (auto &ao_it : m_active_objects) {
			ServerActiveObject* obj = ao_it.second;
			if (obj->isGone())
				continue;

			// Step object
			obj->step(dtime, send_recommended);
			// Read messages from object
			while (!obj->m_messages_out.empty()) {
				m_active_object_messages.push(obj->m_messages_out.front());
				obj->m_messages_out.pop();
			}
		}
	}

	/*
		Manage active objects
	*/
	if (m_object_management_interval.step(dtime, 0.5)) {
		ScopeProfiler sp(g_profiler, "SEnv: remove removed objs avg /.5s", SPT_AVG);
		removeRemovedObjects();
	}

	/*
		Manage particle spawner expiration
	*/
	if (m_particle_management_interval.step(dtime, 1.0)) {
		for (std::unordered_map<u32, float>::iterator i = m_particle_spawners.begin();
			i != m_particle_spawners.end(); ) {
			//non expiring spawners
			if (i->second == PARTICLE_SPAWNER_NO_EXPIRY) {
				++i;
				continue;
			}

			i->second -= 1.0f;
			if (i->second <= 0.f)
				m_particle_spawners.erase(i++);
			else
				++i;
		}
	}
}

u32 ServerEnvironment::addParticleSpawner(float exptime)
{
	// Timers with lifetime 0 do not expire
	float time = exptime > 0.f ? exptime : PARTICLE_SPAWNER_NO_EXPIRY;

	u32 id = 0;
	for (;;) { // look for unused particlespawner id
		id++;
		std::unordered_map<u32, float>::iterator f = m_particle_spawners.find(id);
		if (f == m_particle_spawners.end()) {
			m_particle_spawners[id] = time;
			break;
		}
	}
	return id;
}

u32 ServerEnvironment::addParticleSpawner(float exptime, u16 attached_id)
{
	u32 id = addParticleSpawner(exptime);
	m_particle_spawner_attachments[id] = attached_id;
	if (ServerActiveObject *obj = getActiveObject(attached_id)) {
		obj->attachParticleSpawner(id);
	}
	return id;
}

void ServerEnvironment::deleteParticleSpawner(u32 id, bool remove_from_object)
{
	m_particle_spawners.erase(id);
	const auto &it = m_particle_spawner_attachments.find(id);
	if (it != m_particle_spawner_attachments.end()) {
		u16 obj_id = it->second;
		ServerActiveObject *sao = getActiveObject(obj_id);
		if (sao != NULL && remove_from_object) {
			sao->detachParticleSpawner(id);
		}
		m_particle_spawner_attachments.erase(id);
	}
}

ServerActiveObject* ServerEnvironment::getActiveObject(u16 id)
{
	ServerActiveObjectMap::const_iterator n = m_active_objects.find(id);
	return (n != m_active_objects.end() ? n->second : NULL);
}

bool isFreeServerActiveObjectId(u16 id, ServerActiveObjectMap &objects)
{
	if (id == 0)
		return false;

	return objects.find(id) == objects.end();
}

u16 getFreeServerActiveObjectId(ServerActiveObjectMap &objects)
{
	//try to reuse id's as late as possible
	static u16 last_used_id = 0;
	u16 startid = last_used_id;
	for(;;)
	{
		last_used_id ++;
		if(isFreeServerActiveObjectId(last_used_id, objects))
			return last_used_id;

		if(last_used_id == startid)
			return 0;
	}
}

u16 ServerEnvironment::addActiveObject(ServerActiveObject *object)
{
	assert(object);	// Pre-condition
	m_added_objects++;
	u16 id = addActiveObjectRaw(object, true, 0);
	return id;
}

/*
	Finds out what new objects have been added to
	inside a radius around a position
*/
void ServerEnvironment::getAddedActiveObjects(PlayerSAO *playersao, s16 radius,
	s16 player_radius,
	std::set<u16> &current_objects,
	std::queue<u16> &added_objects)
{
	f32 radius_f = radius * BS;
	f32 player_radius_f = player_radius * BS;

	if (player_radius_f < 0)
		player_radius_f = 0;
	/*
		Go through the object list,
		- discard removed/deactivated objects,
		- discard objects that are too far away,
		- discard objects that are found in current_objects.
		- add remaining objects to added_objects
	*/
	for (auto &ao_it : m_active_objects) {
		u16 id = ao_it.first;

		// Get object
		ServerActiveObject *object = ao_it.second;
		if (object == NULL)
			continue;

		if (object->isGone())
			continue;

		f32 distance_f = object->getBasePosition().
			getDistanceFrom(playersao->getBasePosition());
		if (object->getType() == ACTIVEOBJECT_TYPE_PLAYER) {
			// Discard if too far
			if (distance_f > player_radius_f && player_radius_f != 0)
				continue;
		} else if (distance_f > radius_f)
			continue;

		// Discard if already on current_objects
		std::set<u16>::iterator n;
		n = current_objects.find(id);
		if(n != current_objects.end())
			continue;
		// Add to added_objects
		added_objects.push(id);
	}
}

/*
	Finds out what objects have been removed from
	inside a radius around a position
*/
void ServerEnvironment::getRemovedActiveObjects(PlayerSAO *playersao, s16 radius,
	s16 player_radius,
	std::set<u16> &current_objects,
	std::queue<u16> &removed_objects)
{
	f32 radius_f = radius * BS;
	f32 player_radius_f = player_radius * BS;

	if (player_radius_f < 0)
		player_radius_f = 0;
	/*
		Go through current_objects; object is removed if:
		- object is not found in m_active_objects (this is actually an
		  error condition; objects should be removed only after all clients
		  have been informed about removal), or
		- object is to be removed or deactivated, or
		- object is too far away
	*/
	for (u16 id : current_objects) {
		ServerActiveObject *object = getActiveObject(id);

		if (object == NULL) {
			infostream << "ServerEnvironment::getRemovedActiveObjects():"
				<< " object in current_objects is NULL" << std::endl;
			removed_objects.push(id);
			continue;
		}

		if (object->isGone()) {
			removed_objects.push(id);
			continue;
		}

		f32 distance_f = object->getBasePosition().getDistanceFrom(playersao->getBasePosition());
		if (object->getType() == ACTIVEOBJECT_TYPE_PLAYER) {
			if (distance_f <= player_radius_f || player_radius_f == 0)
				continue;
		} else if (distance_f <= radius_f)
			continue;

		// Object is no longer visible
		removed_objects.push(id);
	}
}

void ServerEnvironment::setStaticForActiveObjectsInBlock(
	v3s16 blockpos, bool static_exists, v3s16 static_block)
{
	MapBlock *block = m_map->getBlockNoCreateNoEx(blockpos);
	if (!block)
		return;

	for (auto &so_it : block->m_static_objects.m_active) {
		// Get the ServerActiveObject counterpart to this StaticObject
		ServerActiveObjectMap::const_iterator ao_it = m_active_objects.find(so_it.first);
		if (ao_it == m_active_objects.end()) {
			// If this ever happens, there must be some kind of nasty bug.
			errorstream << "ServerEnvironment::setStaticForObjectsInBlock(): "
				"Object from MapBlock::m_static_objects::m_active not found "
				"in m_active_objects";
			continue;
		}

		ServerActiveObject *sao = ao_it->second;
		sao->m_static_exists = static_exists;
		sao->m_static_block  = static_block;
	}
}

ActiveObjectMessage ServerEnvironment::getActiveObjectMessage()
{
	if(m_active_object_messages.empty())
		return ActiveObjectMessage(0);

	ActiveObjectMessage message = m_active_object_messages.front();
	m_active_object_messages.pop();
	return message;
}

void ServerEnvironment::getSelectedActiveObjects(
	const core::line3d<f32> &shootline_on_map,
	std::vector<PointedThing> &objects)
{
	std::vector<u16> objectIds;
	getObjectsInsideRadius(objectIds, shootline_on_map.start,
		shootline_on_map.getLength() + 10.0f);
	const v3f line_vector = shootline_on_map.getVector();

	for (u16 objectId : objectIds) {
		ServerActiveObject* obj = getActiveObject(objectId);

		aabb3f selection_box;
		if (!obj->getSelectionBox(&selection_box))
			continue;

		v3f pos = obj->getBasePosition();

		aabb3f offsetted_box(selection_box.MinEdge + pos,
			selection_box.MaxEdge + pos);

		v3f current_intersection;
		v3s16 current_normal;
		if (boxLineCollision(offsetted_box, shootline_on_map.start, line_vector,
				&current_intersection, &current_normal)) {
			objects.emplace_back(
				(s16) objectId, current_intersection, current_normal,
				(current_intersection - shootline_on_map.start).getLengthSQ());
		}
	}
}

/*
	************ Private methods *************
*/

u16 ServerEnvironment::addActiveObjectRaw(ServerActiveObject *object,
	bool set_changed, u32 dtime_s)
{
	assert(object); // Pre-condition
	if(object->getId() == 0){
		u16 new_id = getFreeServerActiveObjectId(m_active_objects);
		if(new_id == 0)
		{
			errorstream<<"ServerEnvironment::addActiveObjectRaw(): "
				<<"no free ids available"<<std::endl;
			if(object->environmentDeletes())
				delete object;
			return 0;
		}
		object->setId(new_id);
	}
	else{
		verbosestream<<"ServerEnvironment::addActiveObjectRaw(): "
			<<"supplied with id "<<object->getId()<<std::endl;
	}

	if(!isFreeServerActiveObjectId(object->getId(), m_active_objects)) {
		errorstream<<"ServerEnvironment::addActiveObjectRaw(): "
			<<"id is not free ("<<object->getId()<<")"<<std::endl;
		if(object->environmentDeletes())
			delete object;
		return 0;
	}

	if (objectpos_over_limit(object->getBasePosition())) {
		v3f p = object->getBasePosition();
		warningstream << "ServerEnvironment::addActiveObjectRaw(): "
			<< "object position (" << p.X << "," << p.Y << "," << p.Z
			<< ") outside maximum range" << std::endl;
		if (object->environmentDeletes())
			delete object;
		return 0;
	}

	/*infostream<<"ServerEnvironment::addActiveObjectRaw(): "
			<<"added (id="<<object->getId()<<")"<<std::endl;*/

	m_active_objects[object->getId()] = object;

	verbosestream<<"ServerEnvironment::addActiveObjectRaw(): "
		<<"Added id="<<object->getId()<<"; there are now "
		<<m_active_objects.size()<<" active objects."
		<<std::endl;

	// Register reference in scripting api (must be done before post-init)
	m_script->addObjectReference(object);
	// Post-initialize object
	object->addedToEnvironment(dtime_s);

	// Add static data to block
	if(object->isStaticAllowed())
	{
		// Add static object to active static list of the block
		v3f objectpos = object->getBasePosition();
		std::string staticdata;
		object->getStaticData(&staticdata);
		StaticObject s_obj(object->getType(), objectpos, staticdata);
		// Add to the block where the object is located in
		v3s16 blockpos = getNodeBlockPos(floatToInt(objectpos, BS));
		MapBlock *block = m_map->emergeBlock(blockpos);
		if(block){
			block->m_static_objects.m_active[object->getId()] = s_obj;
			object->m_static_exists = true;
			object->m_static_block = blockpos;

			if(set_changed)
				block->raiseModified(MOD_STATE_WRITE_NEEDED,
					MOD_REASON_ADD_ACTIVE_OBJECT_RAW);
		} else {
			v3s16 p = floatToInt(objectpos, BS);
			errorstream<<"ServerEnvironment::addActiveObjectRaw(): "
				<<"could not emerge block for storing id="<<object->getId()
				<<" statically (pos="<<PP(p)<<")"<<std::endl;
		}
	}

	return object->getId();
}

/*
	Remove objects that satisfy (isGone() && m_known_by_count==0)
*/
void ServerEnvironment::removeRemovedObjects()
{
	std::vector<u16> objects_to_remove;
	for (auto &ao_it : m_active_objects) {
		u16 id = ao_it.first;
		ServerActiveObject* obj = ao_it.second;

		// This shouldn't happen but check it
		if (!obj) {
			errorstream << "ServerEnvironment::removeRemovedObjects(): "
					<< "NULL object found. id=" << id << std::endl;
			objects_to_remove.push_back(id);
			continue;
		}

		/*
			We will handle objects marked for removal or deactivation
		*/
		if (!obj->isGone())
			continue;

		/*
			Delete static data from block if removed
		*/
		if (obj->m_pending_removal)
			deleteStaticFromBlock(obj, id, MOD_REASON_REMOVE_OBJECTS_REMOVE, false);

		// If still known by clients, don't actually remove. On some future
		// invocation this will be 0, which is when removal will continue.
		if(obj->m_known_by_count > 0)
			continue;

		/*
			Move static data from active to stored if deactivated
		*/
		if (!obj->m_pending_removal && obj->m_static_exists) {
			MapBlock *block = m_map->emergeBlock(obj->m_static_block, false);
			if (block) {
				std::map<u16, StaticObject>::iterator i =
					block->m_static_objects.m_active.find(id);
				if (i != block->m_static_objects.m_active.end()) {
					block->m_static_objects.m_stored.push_back(i->second);
					block->m_static_objects.m_active.erase(id);
					block->raiseModified(MOD_STATE_WRITE_NEEDED,
						MOD_REASON_REMOVE_OBJECTS_DEACTIVATE);
				} else {
					warningstream << "ServerEnvironment::removeRemovedObjects(): "
							<< "id=" << id << " m_static_exists=true but "
							<< "static data doesn't actually exist in "
							<< PP(obj->m_static_block) << std::endl;
				}
			} else {
				infostream << "Failed to emerge block from which an object to "
						<< "be deactivated was loaded from. id=" << id << std::endl;
			}
		}

		// Tell the object about removal
		obj->removingFromEnvironment();
		// Deregister in scripting api
		m_script->removeObjectReference(obj);

		// Delete
		if(obj->environmentDeletes())
			delete obj;

		objects_to_remove.push_back(id);
	}
	// Remove references from m_active_objects
	for (u16 i : objects_to_remove) {
		m_active_objects.erase(i);
	}
}

static void print_hexdump(std::ostream &o, const std::string &data)
{
	const int linelength = 16;
	for(int l=0; ; l++){
		int i0 = linelength * l;
		bool at_end = false;
		int thislinelength = linelength;
		if(i0 + thislinelength > (int)data.size()){
			thislinelength = data.size() - i0;
			at_end = true;
		}
		for(int di=0; di<linelength; di++){
			int i = i0 + di;
			char buf[4];
			if(di<thislinelength)
				snprintf(buf, 4, "%.2x ", data[i]);
			else
				snprintf(buf, 4, "   ");
			o<<buf;
		}
		o<<" ";
		for(int di=0; di<thislinelength; di++){
			int i = i0 + di;
			if(data[i] >= 32)
				o<<data[i];
			else
				o<<".";
		}
		o<<std::endl;
		if(at_end)
			break;
	}
}

/*
	Convert stored objects from blocks near the players to active.
*/
void ServerEnvironment::activateObjects(MapBlock *block, u32 dtime_s)
{
	if(block == NULL)
		return;

	// Ignore if no stored objects (to not set changed flag)
	if(block->m_static_objects.m_stored.empty())
		return;

	verbosestream<<"ServerEnvironment::activateObjects(): "
		<<"activating objects of block "<<PP(block->getPos())
		<<" ("<<block->m_static_objects.m_stored.size()
		<<" objects)"<<std::endl;
	bool large_amount = (block->m_static_objects.m_stored.size() > g_settings->getU16("max_objects_per_block"));
	if (large_amount) {
		errorstream<<"suspiciously large amount of objects detected: "
			<<block->m_static_objects.m_stored.size()<<" in "
			<<PP(block->getPos())
			<<"; removing all of them."<<std::endl;
		// Clear stored list
		block->m_static_objects.m_stored.clear();
		block->raiseModified(MOD_STATE_WRITE_NEEDED,
			MOD_REASON_TOO_MANY_OBJECTS);
		return;
	}

	// Activate stored objects
	std::vector<StaticObject> new_stored;
	for (const StaticObject &s_obj : block->m_static_objects.m_stored) {
		// Create an active object from the data
		ServerActiveObject *obj = ServerActiveObject::create
			((ActiveObjectType) s_obj.type, this, 0, s_obj.pos, s_obj.data);
		// If couldn't create object, store static data back.
		if(obj == NULL) {
			errorstream<<"ServerEnvironment::activateObjects(): "
				<<"failed to create active object from static object "
				<<"in block "<<PP(s_obj.pos/BS)
				<<" type="<<(int)s_obj.type<<" data:"<<std::endl;
			print_hexdump(verbosestream, s_obj.data);

			new_stored.push_back(s_obj);
			continue;
		}
		verbosestream<<"ServerEnvironment::activateObjects(): "
			<<"activated static object pos="<<PP(s_obj.pos/BS)
			<<" type="<<(int)s_obj.type<<std::endl;
		// This will also add the object to the active static list
		addActiveObjectRaw(obj, false, dtime_s);
	}

	// Clear stored list
	block->m_static_objects.m_stored.clear();
	// Add leftover failed stuff to stored list
	for (const StaticObject &s_obj : new_stored) {
		block->m_static_objects.m_stored.push_back(s_obj);
	}

	/*
		Note: Block hasn't really been modified here.
		The objects have just been activated and moved from the stored
		static list to the active static list.
		As such, the block is essentially the same.
		Thus, do not call block->raiseModified(MOD_STATE_WRITE_NEEDED).
		Otherwise there would be a huge amount of unnecessary I/O.
	*/
}

/*
	Convert objects that are not standing inside active blocks to static.

	If m_known_by_count != 0, active object is not deleted, but static
	data is still updated.

	If force_delete is set, active object is deleted nevertheless. It
	shall only be set so in the destructor of the environment.

	If block wasn't generated (not in memory or on disk),
*/
void ServerEnvironment::deactivateFarObjects(bool _force_delete)
{
	std::vector<u16> objects_to_remove;
	for (auto &ao_it : m_active_objects) {
		// force_delete might be overriden per object
		bool force_delete = _force_delete;

		ServerActiveObject* obj = ao_it.second;
		assert(obj);

		// Do not deactivate if static data creation not allowed
		if(!force_delete && !obj->isStaticAllowed())
			continue;

		// removeRemovedObjects() is responsible for these
		if(!force_delete && obj->isGone())
			continue;

		u16 id = ao_it.first;
		v3f objectpos = obj->getBasePosition();

		// The block in which the object resides in
		v3s16 blockpos_o = getNodeBlockPos(floatToInt(objectpos, BS));

		// If object's static data is stored in a deactivated block and object
		// is actually located in an active block, re-save to the block in
		// which the object is actually located in.
		if(!force_delete &&
			obj->m_static_exists &&
			!m_active_blocks.contains(obj->m_static_block) &&
			m_active_blocks.contains(blockpos_o))
		{
			// Delete from block where object was located
			deleteStaticFromBlock(obj, id, MOD_REASON_STATIC_DATA_REMOVED, false);

			std::string staticdata_new;
			obj->getStaticData(&staticdata_new);
			StaticObject s_obj(obj->getType(), objectpos, staticdata_new);
			// Save to block where object is located
			saveStaticToBlock(blockpos_o, id, obj, s_obj, MOD_REASON_STATIC_DATA_ADDED);

			continue;
		}

		// If block is still active, don't remove
		if(!force_delete && m_active_blocks.contains(blockpos_o))
			continue;

		verbosestream << "ServerEnvironment::deactivateFarObjects(): "
				<< "deactivating object id=" << id << " on inactive block "
				<< PP(blockpos_o) << std::endl;

		// If known by some client, don't immediately delete.
		bool pending_delete = (obj->m_known_by_count > 0 && !force_delete);

		/*
			Update the static data
		*/
		if(obj->isStaticAllowed())
		{
			// Create new static object
			std::string staticdata_new;
			obj->getStaticData(&staticdata_new);
			StaticObject s_obj(obj->getType(), objectpos, staticdata_new);

			bool stays_in_same_block = false;
			bool data_changed = true;

			// Check if static data has changed considerably
			if (obj->m_static_exists) {
				if (obj->m_static_block == blockpos_o)
					stays_in_same_block = true;

				MapBlock *block = m_map->emergeBlock(obj->m_static_block, false);

				if (block) {
					std::map<u16, StaticObject>::iterator n =
						block->m_static_objects.m_active.find(id);
					if (n != block->m_static_objects.m_active.end()) {
						StaticObject static_old = n->second;

						float save_movem = obj->getMinimumSavedMovement();

						if (static_old.data == staticdata_new &&
							(static_old.pos - objectpos).getLength() < save_movem)
							data_changed = false;
					} else {
						warningstream << "ServerEnvironment::deactivateFarObjects(): "
								<< "id=" << id << " m_static_exists=true but "
								<< "static data doesn't actually exist in "
								<< PP(obj->m_static_block) << std::endl;
					}
				}
			}

			/*
				While changes are always saved, blocks are only marked as modified
				if the object has moved or different staticdata. (see above)
			*/
			bool shall_be_written = (!stays_in_same_block || data_changed);
			u32 reason = shall_be_written ? MOD_REASON_STATIC_DATA_CHANGED : MOD_REASON_UNKNOWN;

			// Delete old static object
			deleteStaticFromBlock(obj, id, reason, false);

			// Add to the block where the object is located in
			v3s16 blockpos = getNodeBlockPos(floatToInt(objectpos, BS));
			u16 store_id = pending_delete ? id : 0;
			if (!saveStaticToBlock(blockpos, store_id, obj, s_obj, reason))
				force_delete = true;
		}

		/*
			If known by some client, set pending deactivation.
			Otherwise delete it immediately.
		*/
		if(pending_delete && !force_delete)
		{
			verbosestream << "ServerEnvironment::deactivateFarObjects(): "
					<< "object id=" << id << " is known by clients"
					<< "; not deleting yet" << std::endl;

			obj->m_pending_deactivation = true;
			continue;
		}
		verbosestream << "ServerEnvironment::deactivateFarObjects(): "
				<< "object id=" << id << " is not known by clients"
				<< "; deleting" << std::endl;

		// Tell the object about removal
		obj->removingFromEnvironment();
		// Deregister in scripting api
		m_script->removeObjectReference(obj);

		// Delete active object
		if(obj->environmentDeletes())
			delete obj;
		// Id to be removed from m_active_objects
		objects_to_remove.push_back(id);
	}

	// Remove references from m_active_objects
	for (u16 i : objects_to_remove) {
		m_active_objects.erase(i);
	}
}

void ServerEnvironment::deleteStaticFromBlock(
		ServerActiveObject *obj, u16 id, u32 mod_reason, bool no_emerge)
{
	if (!obj->m_static_exists)
		return;

	MapBlock *block;
	if (no_emerge)
		block = m_map->getBlockNoCreateNoEx(obj->m_static_block);
	else
		block = m_map->emergeBlock(obj->m_static_block, false);
	if (!block) {
		if (!no_emerge)
			errorstream << "ServerEnv: Failed to emerge block " << PP(obj->m_static_block)
					<< " when deleting static data of object from it. id=" << id << std::endl;
		return;
	}

	block->m_static_objects.remove(id);
	if (mod_reason != MOD_REASON_UNKNOWN) // Do not mark as modified if requested
		block->raiseModified(MOD_STATE_WRITE_NEEDED, mod_reason);

	obj->m_static_exists = false;
}

bool ServerEnvironment::saveStaticToBlock(
		v3s16 blockpos, u16 store_id,
		ServerActiveObject *obj, const StaticObject &s_obj,
		u32 mod_reason)
{
	MapBlock *block = nullptr;
	try {
		block = m_map->emergeBlock(blockpos);
	} catch (InvalidPositionException &e) {
		// Handled via NULL pointer
		// NOTE: emergeBlock's failure is usually determined by it
		//       actually returning NULL
	}

	if (!block) {
		errorstream << "ServerEnv: Failed to emerge block " << PP(obj->m_static_block)
				<< " when saving static data of object to it. id=" << store_id << std::endl;
		return false;
	}
	if (block->m_static_objects.m_stored.size() >= g_settings->getU16("max_objects_per_block")) {
		warningstream << "ServerEnv: Trying to store id = " << store_id
				<< " statically but block " << PP(blockpos)
				<< " already contains "
				<< block->m_static_objects.m_stored.size()
				<< " objects." << std::endl;
		return false;
	}

	block->m_static_objects.insert(store_id, s_obj);
	if (mod_reason != MOD_REASON_UNKNOWN) // Do not mark as modified if requested
		block->raiseModified(MOD_STATE_WRITE_NEEDED, mod_reason);

	obj->m_static_exists = true;
	obj->m_static_block = blockpos;

	return true;
}

PlayerDatabase *ServerEnvironment::openPlayerDatabase(const std::string &name,
		const std::string &savedir, const Settings &conf)
{

	if (name == "sqlite3")
		return new PlayerDatabaseSQLite3(savedir);

	if (name == "dummy")
		return new Database_Dummy();
#if USE_POSTGRESQL
	if (name == "postgresql") {
		std::string connect_string;
		conf.getNoEx("pgsql_player_connection", connect_string);
		return new PlayerDatabasePostgreSQL(connect_string);
	}
#endif
	if (name == "files")
		return new PlayerDatabaseFiles(savedir + DIR_DELIM + "players");

	throw BaseException(std::string("Database backend ") + name + " not supported.");
}

bool ServerEnvironment::migratePlayersDatabase(const GameParams &game_params,
		const Settings &cmd_args)
{
	std::string migrate_to = cmd_args.get("migrate-players");
	Settings world_mt;
	std::string world_mt_path = game_params.world_path + DIR_DELIM + "world.mt";
	if (!world_mt.readConfigFile(world_mt_path.c_str())) {
		errorstream << "Cannot read world.mt!" << std::endl;
		return false;
	}

	if (!world_mt.exists("player_backend")) {
		errorstream << "Please specify your current backend in world.mt:"
			<< std::endl
			<< "	player_backend = {files|sqlite3|postgresql}"
			<< std::endl;
		return false;
	}

	std::string backend = world_mt.get("player_backend");
	if (backend == migrate_to) {
		errorstream << "Cannot migrate: new backend is same"
			<< " as the old one" << std::endl;
		return false;
	}

	const std::string players_backup_path = game_params.world_path + DIR_DELIM
		+ "players.bak";

	if (backend == "files") {
		// Create backup directory
		fs::CreateDir(players_backup_path);
	}

	try {
		PlayerDatabase *srcdb = ServerEnvironment::openPlayerDatabase(backend,
			game_params.world_path, world_mt);
		PlayerDatabase *dstdb = ServerEnvironment::openPlayerDatabase(migrate_to,
			game_params.world_path, world_mt);

		std::vector<std::string> player_list;
		srcdb->listPlayers(player_list);
		for (std::vector<std::string>::const_iterator it = player_list.begin();
			it != player_list.end(); ++it) {
			actionstream << "Migrating player " << it->c_str() << std::endl;
			RemotePlayer player(it->c_str(), NULL);
			PlayerSAO playerSAO(NULL, &player, 15000, false);

			srcdb->loadPlayer(&player, &playerSAO);

			playerSAO.finalize(&player, std::set<std::string>());
			player.setPlayerSAO(&playerSAO);

			dstdb->savePlayer(&player);

			// For files source, move player files to backup dir
			if (backend == "files") {
				fs::Rename(
					game_params.world_path + DIR_DELIM + "players" + DIR_DELIM + (*it),
					players_backup_path + DIR_DELIM + (*it));
			}
		}

		actionstream << "Successfully migrated " << player_list.size() << " players"
			<< std::endl;
		world_mt.set("player_backend", migrate_to);
		if (!world_mt.updateConfigFile(world_mt_path.c_str()))
			errorstream << "Failed to update world.mt!" << std::endl;
		else
			actionstream << "world.mt updated" << std::endl;

		// When migration is finished from file backend, remove players directory if empty
		if (backend == "files") {
			fs::DeleteSingleFileOrEmptyDirectory(game_params.world_path + DIR_DELIM
				+ "players");
		}

		delete srcdb;
		delete dstdb;

	} catch (BaseException &e) {
		errorstream << "An error occured during migration: " << e.what() << std::endl;
		return false;
	}
	return true;
}
