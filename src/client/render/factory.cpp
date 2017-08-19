/*
Minetest
Copyright (C) 2010-2013 celeron55, Perttu Ahola <celeron55@gmail.com>
Copyright (C) 2017 numzero, Lobachesky Vitaly <numzer0@yandex.ru>

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

#include "factory.h"
#include <stdexcept>
#include "plain.h"
#include "anaglyph.h"
#include "interlaced.h"
#include "pageflip.h"
#include "sidebyside.h"

RenderingCore *createRenderingCore(const std::string &stereo_mode, IrrlichtDevice *device)
{
	if (stereo_mode == "none")
		return new RenderingCorePlain(device);
	if (stereo_mode == "anaglyph")
		return new RenderingCoreAnaglyph(device);
	if (stereo_mode == "interlaced")
		return new RenderingCoreInterlaced(device);
	if (stereo_mode == "pageflip")
		return new RenderingCorePageflip(device);
	if (stereo_mode == "sidebyside")
		return new RenderingCoreSideBySide(device);
	throw std::invalid_argument("Invalid rendering mode: " + stereo_mode);
}
