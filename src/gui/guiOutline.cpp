/*
Garud Client
Copyright (C) 2024 Astra0081, 

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation; either version 3.0 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "guiOutline.h"
#include "irrlichttypes_extrabloated.h"

GUIOutline::GUIOutline(gui::IGUIEnvironment* env, gui::IGUIElement* parent,
                                         s32 id, const core::rect<s32> &rect,
                                         video::SColor color)
    : gui::IGUIElement(gui::EGUIET_ELEMENT, env, parent, id, rect),
      m_color(color)
{
}

void GUIOutline::draw()
{
    if (!IsVisible)
        return;

    video::IVideoDriver* driver = Environment->getVideoDriver();
    if (!driver)
        return;

    core::rect<s32> rect = getAbsoluteClippingRect();
    driver->draw2DRectangleOutline(rect, m_color);

    gui::IGUIElement::draw();
}
