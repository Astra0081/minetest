/*
Minetest
Copyright (C) 2022 Minetest Authors

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

#include "benchmark_setup.h"
#include "voxelalgorithms.h"
#include "dummygamedef.h"
#include "dummymap.h"

TEST_CASE("benchmark_lighting")
{
	DummyGameDef gamedef;
	NodeDefManager *ndef = gamedef.getWritableNodeDefManager();

	v3s16 pmin(-16, -16, -16);
	v3s16 pmax(15, 15, 15);
	v3s16 bpmin = getNodeBlockPos(pmin), bpmax = getNodeBlockPos(pmax);
	DummyMap map(&gamedef, bpmin, bpmax);

	content_t content_wall;
	{
		ContentFeatures f;
		f.name = "stone";
		content_wall = ndef->set(f.name, f);
	}

	content_t content_light;
	{
		ContentFeatures f;
		f.name = "light";
		f.param_type = CPT_LIGHT;
		f.light_propagates = true;
		f.light_source = 14;
		content_light = ndef->set(f.name, f);
	}

	// Make a platform with a light below it.
	for (s16 z = -10; z <= 10; z++)
	for (s16 x = -10; x <= 10; x++)
		map.setNode(v3s16(x, 1, z), MapNode(content_wall));
	map.setNode(v3s16(0, -10, 0), MapNode(content_light));

	for (s16 z = bpmin.Z; z <= bpmax.Z; z++)
	for (s16 y = bpmin.Y; y <= bpmax.Y; y++)
	for (s16 x = bpmin.X; x <= bpmax.X; x++) {
		std::map<v3s16, MapBlock*> modified_blocks;
		voxalgo::repair_block_light(&map, map.getBlockNoCreate(v3s16(x, y, z)),
				&modified_blocks);
	}

	BENCHMARK_ADVANCED("voxalgo::update_lighting_nodes")(Catch::Benchmark::Chronometer meter) {
		std::map<v3s16, MapBlock*> modified_blocks;
		meter.measure([&] {
			map.addNodeAndUpdate(v3s16(0, 0, 0), MapNode(content_light), modified_blocks);
			map.removeNodeAndUpdate(v3s16(0, 0, 0), modified_blocks);
		});
	};

	BENCHMARK_ADVANCED("voxalgo::blit_back_with_light")(Catch::Benchmark::Chronometer meter) {
		std::map<v3s16, MapBlock*> modified_blocks;
		MMVManip vm(&map);
		vm.initialEmerge(v3s16(0, 0, 0), v3s16(0, 0, 0), false);
		meter.measure([&] {
			vm.setNode(v3s16(0, 0, 0), MapNode(content_light));
			voxalgo::blit_back_with_light(&map, &vm, &modified_blocks);
			vm.setNode(v3s16(0, 0, 0), MapNode(CONTENT_AIR));
			voxalgo::blit_back_with_light(&map, &vm, &modified_blocks);
		});
	};
}
