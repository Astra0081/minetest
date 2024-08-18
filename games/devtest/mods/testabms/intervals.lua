-- test ABMs with different interval

local S = minetest.get_translator("testabms")

-- ABM inteval 1 node
minetest.register_node("testabms:interval_1", {
	description = S("Node for test ABM interval_1"),
	drawtype = "normal",
	tiles = { "testabms_wait_node.png" },

	groups = { dig_immediate = 3 },
	
	on_construct = function (pos)
		local meta = minetest.get_meta(pos)
		meta:set_string("infotext", "Waiting for ABM testabms:interval_1")
	end,
})

minetest.register_abm({
		label = "testabms:interval_1",
		nodenames = "testabms:interval_1",
		interval = 1,
		chance = 1,
		action = function (pos)
			minetest.swap_node(pos, {name="testabms:after_abm"})
			local meta = minetest.get_meta(pos)
			meta:set_string("infotext", "ABM testabsm:interval_1 changed this node.")
		end
	})

-- ABM interval 60 node
minetest.register_node("testabms:interval_60", {
	description = S("Node for test ABM interval_60"),
	drawtype = "normal",
	tiles = { "testabms_wait_node.png" },

	groups = { dig_immediate = 3 },
	
	on_construct = function (pos)
		local meta = minetest.get_meta(pos)
		meta:set_string("infotext", "Waiting for ABM testabms:interval_60")
	end,
})

minetest.register_abm({
		label = "testabms:interval_60",
		nodenames = "testabms:interval_60",
		interval = 60,
		chance = 1,
		action = function (pos)
			minetest.swap_node(pos, {name="testabms:after_abm"})
			local meta = minetest.get_meta(pos)
			meta:set_string("infotext", "ABM testabsm:interval_60 changed this node.")
		end
	})

