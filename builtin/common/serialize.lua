--- Lua module to serialize values as Lua code.
-- From: https://github.com/appgurueu/modlib/blob/master/luon.lua
-- License: MIT

local next, rawget, pairs, pcall, error, type, setfenv, loadstring
	= next, rawget, pairs, pcall, error, type, setfenv, loadstring

local table_concat, string_dump, string_format, string_match, math_huge
	= table.concat, string.dump, string.format, string.match, math.huge

-- Recursively counts occurences of objects (non-primitives including strings) in a table.
local function count_objects(value)
	local counts = {}
	if value == nil then
		-- Early return for nil; tables can't contain nil
		return counts
	end
	local function count_values(val)
		local type_ = type(val)
		if type_ == "boolean" or type_ == "number" then
			return
		end
		local count = counts[val]
		counts[val] = (count or 0) + 1
		if type_ == "table" then
			if not count then
				for k, v in pairs(val) do
					count_values(k)
					count_values(v)
				end
			end
		elseif type_ ~= "string" and type_ ~= "function" then
			error("unsupported type: " .. type_)
		end
	end
	count_values(value)
	return counts
end

-- Build a "set" of Lua keywords. These can't be used as short key names.
-- See https://www.lua.org/manual/5.1/manual.html#2.1
local keywords = {}
for _, keyword in pairs({
	"and", "break", "do", "else", "elseif",
	"end", "false", "for", "function", "if",
	"in", "local", "nil", "not", "or",
	"repeat", "return", "then", "true", "until", "while",
	"goto" -- LuaJIT, Lua 5.2+
}) do
	keywords[keyword] = true
end

local function quote(string)
	return string_format("%q", string)
end

local function dump_func(func)
	return string_format("loadstring(%q)", string_dump(func))
end

-- Serializes Lua nil, booleans, numbers, strings, tables and even functions
-- Tables are referenced by reference, strings are referenced by value. Supports circular tables.
local function serialize(value, write)
	local reference, refnum = "r1", 1
	-- [object] = reference string
	local references = {}
	-- Circular tables that must be filled using `table[key] = value` statements
	local to_fill = {}
	for object, count in pairs(count_objects(value)) do
		local type_ = type(object)
		-- Object must appear more than once. If it is a string, the reference has to be shorter than the string.
		if count >= 2 and (type_ ~= "string" or #reference + 2 < #object) then
			write(reference)
			write("=")
			if type_ == "table" then
				write("{}")
			elseif type_ == "function" then
				write(dump_func(object))
			elseif type_ == "string" then
				write(quote(object))
			end
			write(";")
			references[object] = reference
			if type_ == "table" then
				to_fill[object] = reference
			end
			refnum = refnum + 1
			reference = ("r%X"):format(refnum)
		end
	end
	-- Used to decide whether we should do "key=..."
	local function use_short_key(key)
		return not references[key] and type(key) == "string" and (not keywords[key]) and string_match(key, "^[%a_][%a%d_]*$")
	end
	local function dump(value)
		-- Primitive types
		if value == nil then
			return write("nil")
		end
		if value == true then
			return write("true")
		end
		if value == false then
			return write("false")
		end
		local type_ = type(value)
		if type_ == "number" then
			return write(string_format("%.17g", value))
		end
		-- Reference types: table, function and string
		local ref = references[value]
		if ref then
			return write(ref)
		end
		if type_ == "string" then
			return write(quote(value))
		end
		if type_ == "function" then
			return write(dump_func(value))
		end
		if type_ == "table" then
			write("{")
			-- First write list keys:
			-- Don't use the table length #value here as it may horribly fail
			-- for tables which use large integers as keys in the hash part;
			-- stop at the first "hole" (nil value) instead
			local len = 0
			local first = true -- whether this is the first entry, which may not have a leading comma
			while true do
				local v = rawget(value, len + 1) -- use rawget to avoid metatables like the vector metatable
				if v == nil then break end
				if first then first = false else write(",") end
				dump(v)
				len = len + 1
			end
			-- Now write map keys ([key] = value)
			for k, v in next, value do
				-- We have written all non-float keys in [1, len] already
				if type(k) ~= "number" or k % 1 ~= 0 or k < 1 or k > len then
					if first then first = false else write(",") end
					if use_short_key(k) then
						write(k)
					else
						write("[")
						dump(k)
						write("]")
					end
					write("=")
					dump(v)
				end
			end
			write("}")
			return
		end
	end
	-- Write the statements to fill circular tables
	for table, ref in pairs(to_fill) do
		for k, v in pairs(table) do
			write(ref)
			if use_short_key(k) then
				write(".")
				write(k)
			else
				write("[")
				dump(k)
				write("]")
			end
			write("=")
			dump(v)
			write(";")
		end
	end
	write("return ")
	dump(value)
end

function core.serialize(value)
	local rope = {}
	serialize(value, function(text)
		 -- Faster than table.insert(rope, text) on PUC Lua 5.1
		rope[#rope + 1] = text
	end)
	return table_concat(rope)
end

local function dummy_func() end

local nan = (0/0)^1 -- +nan

function core.deserialize(str, safe)
	-- Backwards compatibility
	if str == nil then
		core.log("warning", debug.traceback("minetest.deserialize called with nil (expected string). This is deprecated."))
		return nil, "Invalid type: Expected a string, got nil"
	end
	local t = type(str)
	if t ~= "string" then
		core.log("warning", debug.traceback(("minetest.deserialize called with %s (expected string). "
				.. "This is deprecated and almost certainly a bug."):format(t)))
		return nil, "Invalid type: Expected a string, got " .. t
	end

	local func, err = loadstring(str)
	if not func then return nil, err end

	-- math.huge is serialized to inf, NaNs are serialized to nan by Lua
	local env = {inf = math_huge, nan = nan}
	if safe then
		env.loadstring = dummy_func
	else
		env.loadstring = function(str, ...)
			local func, err = loadstring(str, ...)
			if func then
				setfenv(func, env)
				return func
			end
			return nil, err
		end
	end
	setfenv(func, env)
	local success, value_or_err = pcall(func)
	if success then
		return value_or_err
	end
	return nil, value_or_err
end
