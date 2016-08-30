--Minetest
--Copyright (C) 2016 T4im
--
--This program is free software; you can redistribute it and/or modify
--it under the terms of the GNU Lesser General Public License as published by
--the Free Software Foundation; either version 2.1 of the License, or
--(at your option) any later version.
--
--This program is distributed in the hope that it will be useful,
--but WITHOUT ANY WARRANTY; without even the implied warranty of
--MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--GNU Lesser General Public License for more details.
--
--You should have received a copy of the GNU Lesser General Public License along
--with this program; if not, write to the Free Software Foundation, Inc.,
--51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

local profiler_path = core.get_builtin_path() .. "/profiler"
local profiler = {}
local sampler = assert(loadfile(profiler_path .. "/sampling.lua"))(profiler)
local instrumentation  = assert(loadfile(profiler_path .. "/instrumentation.lua"))(profiler, sampler)
local reporter = dofile(profiler_path .. "/reporter.lua")
profiler.instrument = instrumentation.instrument

---
-- Delayed registration of the /profiler chat command
-- Is called later, after `core.register_chatcommand` was set up.
--
function profiler.init_chatcommand()
	local instrument_profiler = core.setting_getbool("instrument.profiler") or false
	if instrument_profiler then
		instrumentation.init_chatcommand()
	end

	local param_usage = "print [filter] | dump [filter] | save [format [filter]] | reset"
	core.register_chatcommand("profiler", {
		description = "handle the profiler and profiling data",
		params = param_usage,
		privs = { server=true },
		func = function(name, param)
			local command, arg0 = string.match(param, "([^ ]+) ?(.*)")
			local args = arg0 and string.split(arg0, " ")

			if command == "dump" then
				core.log("action", reporter.print(sampler.profile, arg0))
				return true, "Statistics written to action log"
			elseif command == "print" then
				return true, reporter.print(sampler.profile, arg0)
			elseif command == "save" then
				return reporter.save(sampler.profile, args[1] or "txt", args[2])
			elseif command == "reset" then
				sampler.reset()
				return true, "Statistics were reset"
			end

			return false, string.format(
				"Usage: %s\n" ..
				"Format can be one of txt, csv, lua, json, json_pretty (structures may be subject to change).",
				param_usage
			)
		end
	})

	if not instrument_profiler then
		instrumentation.init_chatcommand()
	end
end

sampler.init()
instrumentation.init()

return profiler
