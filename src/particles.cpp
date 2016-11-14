/*
Minetest
Copyright (C) 2013 celeron55, Perttu Ahola <celeron55@gmail.com>

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

#include "particles.h"
#include "constants.h"
#include "debug.h"
#include "settings.h"
#include "client/tile.h"
#include "gamedef.h"
#include "collision.h"
#include <stdlib.h>
#include "util/numeric.h"
#include "light.h"
#include "environment.h"
#include "clientmap.h"
#include "mapnode.h"
#include "client.h"

/*
	Utility
*/

v3f random_v3f(v3f min, v3f max)
{
	return v3f( rand()/(float)RAND_MAX*(max.X-min.X)+min.X,
			rand()/(float)RAND_MAX*(max.Y-min.Y)+min.Y,
			rand()/(float)RAND_MAX*(max.Z-min.Z)+min.Z);
}

u32 check_material_type_param(u32 material_type_param)
{
	u32 alphaSource = (material_type_param & 0x0000F000) >> 12;
	u32 modulo  = (material_type_param & 0x00000F00) >> 8;
	u32 srcFact = (material_type_param & 0x000000F0) >> 4;
	u32 dstFact = material_type_param & 0x0000000F;

	if (alphaSource <= 3 && modulo <= 4 && srcFact <= 10 && dstFact <= 10)
		return material_type_param;
	errorstream << "Server sent incorrect material_type_param for particle"
			<< ", ignoring it." << std::endl;
	return 0;
}

Particle::Particle(
	IGameDef *gamedef,
	scene::ISceneManager* smgr,
	LocalPlayer *player,
	ClientEnvironment *env,
	v3f pos,
	v3f velocity,
	v3f acceleration,
	float expirationtime,
	float size,
	bool collisiondetection,
	bool collision_removal,
	bool vertical,
	video::ITexture *texture,
	v2f texpos,
	v2f texsize,
	u32 material_type_param,
	u16 vertical_frame_num,
	u16 horizontal_frame_num,
	u16 first_frame,
	float frame_length,
	bool loop_animation,
	u8 glow
):
	scene::ISceneNode(smgr->getRootSceneNode(), smgr)
{
	// Misc
	m_gamedef = gamedef;
	m_env = env;

	// Texture
	m_material.setFlag(video::EMF_LIGHTING, false);
	m_material.setFlag(video::EMF_BACK_FACE_CULLING, false);
	m_material.setFlag(video::EMF_BILINEAR_FILTER, false);
	m_material.setFlag(video::EMF_FOG_ENABLE, true);
	if (material_type_param != 0) {
		m_material.MaterialType = video::EMT_ONETEXTURE_BLEND;
		m_material.MaterialTypeParam = irr::core::FR(material_type_param);
		// We must disable z-buffer if we want to avoid transparent pixels
		// to overlap pixels with lower z-value.
		m_material.setFlag(video::EMF_ZWRITE_ENABLE, false); 
	} else {
		m_material.MaterialType = video::EMT_TRANSPARENT_ALPHA_CHANNEL;
	}
	m_material.setTexture(0, texture);

	m_texpos = texpos;
	m_texsize = texsize;
	m_vertical_frame_num = vertical_frame_num;
	m_horizontal_frame_num = horizontal_frame_num;
	m_first_frame = first_frame;
	m_frame_length = frame_length;
	m_loop_animation = loop_animation;
	m_texsize.Y /= m_vertical_frame_num;
	m_texsize.X /= m_horizontal_frame_num;

	// Particle related
	m_pos = pos;
	m_velocity = velocity;
	m_acceleration = acceleration;
	m_expiration = expirationtime;
	m_time = 0;
	m_player = player;
	m_size = size;
	m_collisiondetection = collisiondetection;
	m_collision_removal = collision_removal;
	m_vertical = vertical;
	m_glow = glow;

	// Irrlicht stuff
	m_collisionbox = aabb3f
			(-size/2,-size/2,-size/2,size/2,size/2,size/2);
	this->setAutomaticCulling(scene::EAC_OFF);

	// Init lighting
	updateLight();

	// Init model
	updateVertices();
}

Particle::~Particle()
{
}

void Particle::OnRegisterSceneNode()
{
	if (IsVisible)
		SceneManager->registerNodeForRendering(this, scene::ESNRP_TRANSPARENT_EFFECT);

	ISceneNode::OnRegisterSceneNode();
}

void Particle::render()
{
	video::IVideoDriver* driver = SceneManager->getVideoDriver();
	driver->setMaterial(m_material);
	driver->setTransform(video::ETS_WORLD, AbsoluteTransformation);

	u16 indices[] = {0,1,2, 2,3,0};
	driver->drawVertexPrimitiveList(m_vertices, 4,
			indices, 2, video::EVT_STANDARD,
			scene::EPT_TRIANGLES, video::EIT_16BIT);
}

void Particle::step(float dtime)
{
	m_time += dtime;
	if (m_collisiondetection) {
		aabb3f box = m_collisionbox;
		v3f p_pos = m_pos * BS;
		v3f p_velocity = m_velocity * BS;
		collisionMoveResult r = collisionMoveSimple(m_env,
			m_gamedef, BS * 0.5, box, 0, dtime, &p_pos,
			&p_velocity, m_acceleration * BS);
		if (m_collision_removal && r.collides) {
			// force expiration of the particle
			m_expiration = -1.0;
		} else {
			m_pos = p_pos / BS;
			m_velocity = p_velocity / BS;
		}
	} else {
		m_velocity += m_acceleration * dtime;
		m_pos += m_velocity * dtime;
	}

	// Update lighting
	updateLight();

	// Update model
	updateVertices();
}

void Particle::updateLight()
{
	u8 light = 0;
	bool pos_ok;

	v3s16 p = v3s16(
		floor(m_pos.X+0.5),
		floor(m_pos.Y+0.5),
		floor(m_pos.Z+0.5)
	);
	MapNode n = m_env->getClientMap().getNodeNoEx(p, &pos_ok);
	if (pos_ok)
		light = n.getLightBlend(m_env->getDayNightRatio(), m_gamedef->ndef());
	else
		light = blend_light(m_env->getDayNightRatio(), LIGHT_SUN, 0);

	m_light = decode_light(light + m_glow);
}

void Particle::updateVertices()
{
	video::SColor c(255, m_light, m_light, m_light);
	u16 frame = m_first_frame;
	if (m_frame_length > 0) {
		if (m_loop_animation)
			frame = m_first_frame + (u32)(m_time / m_frame_length)
					% (m_vertical_frame_num * 
					m_horizontal_frame_num - m_first_frame);
		else if (m_time >= 
				(m_vertical_frame_num * m_horizontal_frame_num 
				- m_first_frame) * m_frame_length)
			frame = m_vertical_frame_num * m_horizontal_frame_num - 1;
		else
			frame = m_first_frame + (u16)(m_time / m_frame_length);
	}
	f32 tx0 = m_texpos.X + m_texsize.X * (frame % m_horizontal_frame_num);
	f32 tx1 = m_texpos.X + m_texsize.X * (frame % m_horizontal_frame_num + 1);
	f32 ty0 = m_texpos.Y + m_texsize.Y * (frame / m_horizontal_frame_num);
	f32 ty1 = m_texpos.Y + m_texsize.Y * (frame / m_horizontal_frame_num + 1);

	m_vertices[0] = video::S3DVertex(-m_size/2,-m_size/2,0, 0,0,0,
			c, tx0, ty1);
	m_vertices[1] = video::S3DVertex(m_size/2,-m_size/2,0, 0,0,0,
			c, tx1, ty1);
	m_vertices[2] = video::S3DVertex(m_size/2,m_size/2,0, 0,0,0,
			c, tx1, ty0);
	m_vertices[3] = video::S3DVertex(-m_size/2,m_size/2,0, 0,0,0,
			c, tx0, ty0);

	v3s16 camera_offset = m_env->getCameraOffset();
	for(u16 i=0; i<4; i++)
	{
		if (m_vertical) {
			v3f ppos = m_player->getPosition()/BS;
			m_vertices[i].Pos.rotateXZBy(atan2(ppos.Z-m_pos.Z, ppos.X-m_pos.X)/core::DEGTORAD+90);
		} else {
			m_vertices[i].Pos.rotateYZBy(m_player->getPitch());
			m_vertices[i].Pos.rotateXZBy(m_player->getYaw());
		}
		m_box.addInternalPoint(m_vertices[i].Pos);
		m_vertices[i].Pos += m_pos*BS - intToFloat(camera_offset, BS);
	}
}

/*
	ParticleSpawner
*/

ParticleSpawner::ParticleSpawner(IGameDef* gamedef, scene::ISceneManager *smgr, LocalPlayer *player,
	u16 amount, float time,
	v3f minpos, v3f maxpos, v3f minvel, v3f maxvel, v3f minacc, v3f maxacc,
	float minexptime, float maxexptime, float minsize, float maxsize,
	bool collisiondetection, bool collision_removal, u16 attached_id, bool vertical,
	video::ITexture *texture, u32 id, 
	u32 material_type_param,
	u16 vertical_frame_num,
	u16 horizontal_frame_num,
	u16 min_first_frame,
	u16 max_first_frame,
	float frame_length,
	bool loop_animation,
	u8 glow,
	ParticleManager *p_manager) :
	m_particlemanager(p_manager)
{
	m_gamedef = gamedef;
	m_smgr = smgr;
	m_player = player;
	m_amount = amount;
	m_spawntime = time;
	m_minpos = minpos;
	m_maxpos = maxpos;
	m_minvel = minvel;
	m_maxvel = maxvel;
	m_minacc = minacc;
	m_maxacc = maxacc;
	m_minexptime = minexptime;
	m_maxexptime = maxexptime;
	m_minsize = minsize;
	m_maxsize = maxsize;
	m_collisiondetection = collisiondetection;
	m_collision_removal = collision_removal;
	m_attached_id = attached_id;
	m_vertical = vertical;
	m_texture = texture;
	m_time = 0;
	m_vertical_frame_num = vertical_frame_num;
	m_horizontal_frame_num = horizontal_frame_num;
	m_min_first_frame = min_first_frame;
	m_max_first_frame = max_first_frame;
	m_frame_length = frame_length;
	m_loop_animation = loop_animation;
	m_material_type_param = material_type_param;
	m_glow = glow;

	for (u16 i = 0; i<=m_amount; i++)
	{
		float spawntime = (float)rand()/(float)RAND_MAX*m_spawntime;
		m_spawntimes.push_back(spawntime);
	}
}

ParticleSpawner::~ParticleSpawner() {}

void ParticleSpawner::step(float dtime, ClientEnvironment* env)
{
	m_time += dtime;
	bool unloaded = false;
	v3f attached_offset = v3f(0,0,0);
	if (m_attached_id != 0) {
		if (ClientActiveObject *attached = env->getActiveObject(m_attached_id))
			attached_offset = attached->getPosition() / BS;
		else
			unloaded = true;
	}

	if (m_spawntime != 0) // Spawner exists for a predefined timespan
	{
		for(std::vector<float>::iterator i = m_spawntimes.begin();
				i != m_spawntimes.end();)
		{
			if ((*i) <= m_time && m_amount > 0)
			{
				m_amount--;

				// Pretend to, but don't actually spawn a
				// particle if it is attached to an unloaded
				// object.
				if (!unloaded) {
					v3f pos = random_v3f(m_minpos, m_maxpos);
					v3f vel = random_v3f(m_minvel, m_maxvel);
					v3f acc = random_v3f(m_minacc, m_maxacc);
					// Make relative to offest
					pos += attached_offset;
					float exptime = rand()/(float)RAND_MAX
							*(m_maxexptime-m_minexptime)
							+m_minexptime;
					float size = rand()/(float)RAND_MAX
							*(m_maxsize-m_minsize)
							+m_minsize;
					u16 first_frame = m_min_first_frame + 
							rand() % 
							(m_max_first_frame - 
							m_min_first_frame + 1);
					Particle* toadd = new Particle(
						m_gamedef,
						m_smgr,
						m_player,
						env,
						pos,
						vel,
						acc,
						exptime,
						size,
						m_collisiondetection,
						m_collision_removal,
						m_vertical,
						m_texture,
						v2f(0.0, 0.0),
						v2f(1.0, 1.0),
						m_material_type_param, 
						m_vertical_frame_num,
						m_horizontal_frame_num,
						first_frame,
						m_frame_length,
						m_loop_animation,
						m_glow);
					m_particlemanager->addParticle(toadd);
				}
				i = m_spawntimes.erase(i);
			}
			else
			{
				++i;
			}
		}
	}
	else // Spawner exists for an infinity timespan, spawn on a per-second base
	{
		// Skip this step if attached to an unloaded object
		if (unloaded)
			return;
		for (int i = 0; i <= m_amount; i++)
		{
			if (rand()/(float)RAND_MAX < dtime)
			{
				v3f pos = random_v3f(m_minpos, m_maxpos)
						+ attached_offset;
				v3f vel = random_v3f(m_minvel, m_maxvel);
				v3f acc = random_v3f(m_minacc, m_maxacc);
				float exptime = rand()/(float)RAND_MAX
						*(m_maxexptime-m_minexptime)
						+m_minexptime;
				float size = rand()/(float)RAND_MAX
						*(m_maxsize-m_minsize)
						+m_minsize;
				u16 first_frame = m_min_first_frame + 
						rand() % 
						(m_max_first_frame - 
						m_min_first_frame + 1);
				Particle* toadd = new Particle(
					m_gamedef,
					m_smgr,
					m_player,
					env,
					pos,
					vel,
					acc,
					exptime,
					size,
					m_collisiondetection,
					m_collision_removal,
					m_vertical,
					m_texture,
					v2f(0.0, 0.0),
					v2f(1.0, 1.0),
					m_material_type_param, 
					m_vertical_frame_num,
					m_horizontal_frame_num,
					first_frame,
					m_frame_length,
					m_loop_animation,
					m_glow);
				m_particlemanager->addParticle(toadd);
			}
		}
	}
}


ParticleManager::ParticleManager(ClientEnvironment* env) :
	m_env(env)
{}

ParticleManager::~ParticleManager()
{
	clearAll();
}

void ParticleManager::step(float dtime)
{
	stepParticles (dtime);
	stepSpawners (dtime);
}

void ParticleManager::stepSpawners (float dtime)
{
	MutexAutoLock lock(m_spawner_list_lock);
	for (std::map<u32, ParticleSpawner*>::iterator i =
			m_particle_spawners.begin();
			i != m_particle_spawners.end();)
	{
		if (i->second->get_expired())
		{
			delete i->second;
			m_particle_spawners.erase(i++);
		}
		else
		{
			i->second->step(dtime, m_env);
			++i;
		}
	}
}

void ParticleManager::stepParticles (float dtime)
{
	MutexAutoLock lock(m_particle_list_lock);
	for(std::vector<Particle*>::iterator i = m_particles.begin();
			i != m_particles.end();)
	{
		if ((*i)->get_expired())
		{
			(*i)->remove();
			delete *i;
			i = m_particles.erase(i);
		}
		else
		{
			(*i)->step(dtime);
			++i;
		}
	}
}

void ParticleManager::clearAll ()
{
	MutexAutoLock lock(m_spawner_list_lock);
	MutexAutoLock lock2(m_particle_list_lock);
	for(std::map<u32, ParticleSpawner*>::iterator i =
			m_particle_spawners.begin();
			i != m_particle_spawners.end();)
	{
		delete i->second;
		m_particle_spawners.erase(i++);
	}

	for(std::vector<Particle*>::iterator i =
			m_particles.begin();
			i != m_particles.end();)
	{
		(*i)->remove();
		delete *i;
		i = m_particles.erase(i);
	}
}

void ParticleManager::handleParticleEvent(ClientEvent *event, IGameDef *gamedef,
		scene::ISceneManager* smgr, LocalPlayer *player)
{
	switch (event->type) {
		case CE_DELETE_PARTICLESPAWNER: {
			MutexAutoLock lock(m_spawner_list_lock);
			if (m_particle_spawners.find(event->delete_particlespawner.id) !=
					m_particle_spawners.end()) {
				delete m_particle_spawners.find(event->delete_particlespawner.id)->second;
				m_particle_spawners.erase(event->delete_particlespawner.id);
			}
			// no allocated memory in delete event
			break;
		}
		case CE_ADD_PARTICLESPAWNER: {
			{
				MutexAutoLock lock(m_spawner_list_lock);
				if (m_particle_spawners.find(event->add_particlespawner.id) !=
						m_particle_spawners.end()) {
					delete m_particle_spawners.find(event->add_particlespawner.id)->second;
					m_particle_spawners.erase(event->add_particlespawner.id);
				}
			}

			video::ITexture *texture =
				gamedef->tsrc()->getTextureForMesh(*(event->add_particlespawner.texture));

			float frame_length = -1;
			u16 vertical_frame_num = 1;
			u16 horizontal_frame_num = 1;
			u32 material_type_param =
				check_material_type_param(event->add_particlespawner.material_type_param);

			switch (event->add_particlespawner.animation_type) {
				case AT_NONE:
					break;
				case AT_VERTICAL_FRAMES: {
					v2u32 size = texture->getOriginalSize();
					int frame_height = (float)size.X /
						(float)event->add_particlespawner.vertical_frame_num *
						(float)event->add_particlespawner.horizontal_frame_num;
					vertical_frame_num = size.Y / frame_height;
					frame_length = 
						event->add_particlespawner.frame_length / 
						vertical_frame_num;
					break;
				}
				case AT_2D_ANIMATION_SHEET: {
					vertical_frame_num =
						event->add_particlespawner.vertical_frame_num;
					horizontal_frame_num =
						event->add_particlespawner.horizontal_frame_num;
					frame_length = 
						event->add_particlespawner.frame_length;
					break;
				}
				default:
					break;
			}

			ParticleSpawner* toadd = new ParticleSpawner(gamedef, smgr, player,
					event->add_particlespawner.amount,
					event->add_particlespawner.spawntime,
					*event->add_particlespawner.minpos,
					*event->add_particlespawner.maxpos,
					*event->add_particlespawner.minvel,
					*event->add_particlespawner.maxvel,
					*event->add_particlespawner.minacc,
					*event->add_particlespawner.maxacc,
					event->add_particlespawner.minexptime,
					event->add_particlespawner.maxexptime,
					event->add_particlespawner.minsize,
					event->add_particlespawner.maxsize,
					event->add_particlespawner.collisiondetection,
					event->add_particlespawner.collision_removal,
					event->add_particlespawner.attached_id,
					event->add_particlespawner.vertical,
					texture,
					event->add_particlespawner.id,
					material_type_param,
					vertical_frame_num,
					horizontal_frame_num,
					event->add_particlespawner.min_first_frame,
					event->add_particlespawner.max_first_frame,
					frame_length,
					event->add_particlespawner.loop_animation,
					event->add_particlespawner.glow,
					this);

			/* delete allocated content of event */
			delete event->add_particlespawner.minpos;
			delete event->add_particlespawner.maxpos;
			delete event->add_particlespawner.minvel;
			delete event->add_particlespawner.maxvel;
			delete event->add_particlespawner.minacc;
			delete event->add_particlespawner.texture;
			delete event->add_particlespawner.maxacc;

			{
				MutexAutoLock lock(m_spawner_list_lock);
				m_particle_spawners.insert(
						std::pair<u32, ParticleSpawner*>(
								event->add_particlespawner.id,
								toadd));
			}
			break;
		}
		case CE_SPAWN_PARTICLE: {
			video::ITexture *texture =
				gamedef->tsrc()->getTextureForMesh(*(event->spawn_particle.texture));

			float frame_length = -1;
			u16 vertical_frame_num = 1;
			u16 horizontal_frame_num = 1;
			u32 material_type_param =
				check_material_type_param(event->spawn_particle.material_type_param);

			switch (event->spawn_particle.animation_type) {
				case AT_NONE:
					break;
				case AT_VERTICAL_FRAMES: {
					v2u32 size = texture->getOriginalSize();
					int frame_height = (float)size.X /
						(float)event->spawn_particle.vertical_frame_num *
						(float)event->spawn_particle.horizontal_frame_num;
					vertical_frame_num = size.Y / frame_height;
					frame_length = 
						event->spawn_particle.frame_length / 
						vertical_frame_num;
					break;
				}
				case AT_2D_ANIMATION_SHEET: {
					vertical_frame_num =
						event->spawn_particle.vertical_frame_num;
					horizontal_frame_num =
						event->spawn_particle.horizontal_frame_num;
					frame_length = 
						event->spawn_particle.frame_length;
					break;
				}
				default:
					break;
			}

			Particle* toadd = new Particle(gamedef, smgr, player, m_env,
					*event->spawn_particle.pos,
					*event->spawn_particle.vel,
					*event->spawn_particle.acc,
					event->spawn_particle.expirationtime,
					event->spawn_particle.size,
					event->spawn_particle.collisiondetection,
					event->spawn_particle.collision_removal,
					event->spawn_particle.vertical,
					texture,
					v2f(0.0, 0.0),
					v2f(1.0, 1.0),
					material_type_param,
					vertical_frame_num,
					horizontal_frame_num,
					event->spawn_particle.first_frame,
					frame_length,
					event->spawn_particle.loop_animation,
					event->spawn_particle.glow);

			addParticle(toadd);

			delete event->spawn_particle.pos;
			delete event->spawn_particle.vel;
			delete event->spawn_particle.acc;
			delete event->spawn_particle.texture;

			break;
		}
		default: break;
	}
}

void ParticleManager::addDiggingParticles(IGameDef* gamedef, scene::ISceneManager* smgr,
		LocalPlayer *player, v3s16 pos, const TileSpec tiles[])
{
	for (u16 j = 0; j < 32; j++) // set the amount of particles here
	{
		addNodeParticle(gamedef, smgr, player, pos, tiles);
	}
}

void ParticleManager::addPunchingParticles(IGameDef* gamedef, scene::ISceneManager* smgr,
		LocalPlayer *player, v3s16 pos, const TileSpec tiles[])
{
	addNodeParticle(gamedef, smgr, player, pos, tiles);
}

void ParticleManager::addNodeParticle(IGameDef* gamedef, scene::ISceneManager* smgr,
		LocalPlayer *player, v3s16 pos, const TileSpec tiles[])
{
	// Texture
	u8 texid = myrand_range(0, 5);
	video::ITexture *texture = tiles[texid].texture;

	// Only use first frame of animated texture
	f32 ymax = 1;
	if(tiles[texid].material_flags & MATERIAL_FLAG_ANIMATION_VERTICAL_FRAMES)
		ymax /= tiles[texid].animation_frame_count;

	float size = rand() % 64 / 512.;
	float visual_size = BS * size;
	v2f texsize(size * 2, ymax * size * 2);
	v2f texpos;
	texpos.X = ((rand() % 64) / 64. - texsize.X);
	texpos.Y = ymax * ((rand() % 64) / 64. - texsize.Y);

	// Physics
	v3f velocity((rand() % 100 / 50. - 1) / 1.5,
			rand() % 100 / 35.,
			(rand() % 100 / 50. - 1) / 1.5);

	v3f acceleration(0,-9,0);
	v3f particlepos = v3f(
		(f32) pos.X + rand() %100 /200. - 0.25,
		(f32) pos.Y + rand() %100 /200. - 0.25,
		(f32) pos.Z + rand() %100 /200. - 0.25
	);

	Particle* toadd = new Particle(
		gamedef,
		smgr,
		player,
		m_env,
		particlepos,
		velocity,
		acceleration,
		rand() % 100 / 100., // expiration time
		visual_size,
		true,
		false,
		false,
		texture,
		texpos,
		texsize,
		0, 1, 1, 0, -1, true, 0);

	addParticle(toadd);
}

void ParticleManager::addParticle(Particle* toadd)
{
	MutexAutoLock lock(m_particle_list_lock);
	m_particles.push_back(toadd);
}
