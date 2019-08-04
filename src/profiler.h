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

#pragma once

#include "irrlichttypes.h"
#include <cassert>
#include <string>
#include <map>
#include <ostream>

#include "threading/mutex_auto_lock.h"
#include "util/timetaker.h"
#include "util/numeric.h"      // paging()

// Global profiler
class Profiler;
extern Profiler *g_profiler;

/*
	Time profiler
*/

class Profiler
{
public:
	Profiler() = default;

	void add(const std::string &name, float value)
	{
		MutexAutoLock lock(m_mutex);
		{
			/* No average shall have been used; mark add used as -2 */
			std::map<std::string, int>::iterator n = m_avgcounts.find(name);
			if(n == m_avgcounts.end())
				m_avgcounts[name] = -2;
			else{
				if(n->second == -1)
					n->second = -2;
				assert(n->second == -2);
			}
		}
		{
			std::map<std::string, float>::iterator n = m_data.find(name);
			if(n == m_data.end())
				m_data[name] = value;
			else
				n->second += value;
		}
	}

	void avg(const std::string &name, float value)
	{
		MutexAutoLock lock(m_mutex);
		int &count = m_avgcounts[name];

		assert(count != -2);
		count = MYMAX(count, 0) + 1;
		m_data[name] += value;
	}

	void clear()
	{
		MutexAutoLock lock(m_mutex);
		for (auto &it : m_data) {
			it.second = 0;
		}
		m_avgcounts.clear();
	}


	float getValue(const std::string &name) const
	{
		std::map<std::string, float>::const_iterator numerator = m_data.find(name);
		if (numerator == m_data.end())
			return 0.f;

		std::map<std::string, int>::const_iterator denominator = m_avgcounts.find(name);
		if (denominator != m_avgcounts.end()){
			if (denominator->second >= 1)
				return numerator->second / denominator->second;
		}

		return numerator->second;
	}

	typedef std::map<std::string, float> GraphValues;

	// Returns the line count
	int print(std::ostream &o, u32 page = 1, u32 pagecount = 1);
	void getPage(GraphValues &o, u32 page, u32 pagecount);


	void graphAdd(const std::string &id, float value)
	{
		MutexAutoLock lock(m_mutex);
		std::map<std::string, float>::iterator i =
				m_graphvalues.find(id);
		if(i == m_graphvalues.end())
			m_graphvalues[id] = value;
		else
			i->second += value;
	}
	void graphGet(GraphValues &result)
	{
		MutexAutoLock lock(m_mutex);
		result = m_graphvalues;
		m_graphvalues.clear();
	}

	void remove(const std::string& name)
	{
		MutexAutoLock lock(m_mutex);
		m_avgcounts.erase(name);
		m_data.erase(name);
	}

private:
	std::mutex m_mutex;
	std::map<std::string, float> m_data;
	std::map<std::string, int> m_avgcounts;
	std::map<std::string, float> m_graphvalues;
};

enum ScopeProfilerType{
	SPT_ADD,
	SPT_AVG,
	SPT_GRAPH_ADD
};

class ScopeProfiler
{
public:
	ScopeProfiler(Profiler *profiler, const std::string &name,
			ScopeProfilerType type = SPT_ADD);
	~ScopeProfiler();
private:
	Profiler *m_profiler = nullptr;
	std::string m_name;
	TimeTaker *m_timer = nullptr;
	enum ScopeProfilerType m_type;
};
