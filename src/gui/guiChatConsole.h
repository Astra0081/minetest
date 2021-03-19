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

#include "irrlichttypes_extrabloated.h"
#include "modalMenu.h"
#include "chat.h"
#include "config.h"

class Client;

class GUIChatConsole : public gui::IGUIElement
{
public:
	GUIChatConsole(gui::IGUIEnvironment* env,
			gui::IGUIElement* parent,
			s32 id,
			ChatBackend* backend,
			Client* client,
			IMenuManager* menumgr);
	virtual ~GUIChatConsole();

	// Open the console (height = desired fraction of screen size)
	// This doesn't open immediately but initiates an animation.
	// You should call isOpenInhibited() before this.
	void openConsole(f32 scale);

	bool isOpen() const;

	// Check if the console should not be opened at the moment
	// This is to avoid reopening the console immediately after closing
	bool isOpenInhibited() const;
	// Close the console, equivalent to openConsole(0).
	// This doesn't close immediately but initiates an animation.
	void closeConsole();
	// Close the console immediately, without animation.
	void closeConsoleAtOnce();
	// Set whether to close the console after the user presses enter.
	void setCloseOnEnter(bool close) { m_close_on_enter = close; }

	// Replace actual line when adding the actual to the history (if there is any)
	void replaceAndAddToHistory(const std::wstring &line);

	// Change how the cursor looks
	void setCursor(
		bool visible,
		bool blinking = false,
		f32 blink_speed = 1.0,
		f32 relative_height = 1.0);

	// Irrlicht draw method
	virtual void draw();

	virtual bool OnEvent(const SEvent& event);

	virtual void setVisible(bool visible);

private:
	void reformatConsole();
	void recalculateConsolePosition();

	// These methods are called by draw
	void animate(u32 msec);
	void drawBackground();
	void drawText();
	void drawPrompt();

	// Parse conf and populate "ctrl" keys for clickable chat
	int setupChatClickCtrlKeys(std::string inputline);
	bool isInCtrlKeys(const irr::EKEY_CODE& kc);

private:
	ChatBackend* m_chat_backend;
	Client* m_client;
	IMenuManager* m_menumgr;

	// current screen size
	v2u32 m_screensize;

	// used to compute how much time passed since last animate()
	u64 m_animate_time_old;

	// should the console be opened or closed?
	bool m_open = false;
	// should it close after you press enter?
	bool m_close_on_enter = false;
	// current console height [pixels]
	s32 m_height = 0;
	// desired height [pixels]
	f32 m_desired_height = 0.0f;
	// desired height [screen height fraction]
	f32 m_desired_height_fraction = 0.0f;
	// console open/close animation speed [screen height fraction / second]
	f32 m_height_speed = 5.0f;
	// if nonzero, opening the console is inhibited [milliseconds]
	u32 m_open_inhibited = 0;

	// cursor blink frame (16-bit value)
	// cursor is off during [0,32767] and on during [32768,65535]
	u32 m_cursor_blink = 0;
	// cursor blink speed [on/off toggles / second]
	f32 m_cursor_blink_speed = 0.0f;
	// cursor height [line height]
	f32 m_cursor_height = 0.0f;

	// background texture
	video::ITexture *m_background = nullptr;
	// background color (including alpha)
	video::SColor m_background_color = video::SColor(255, 0, 0, 0);

	// font
	gui::IGUIFont *m_font = nullptr;
	v2u32 m_fontsize;
	
	// Enable clickable chat weblinks
	bool m_cache_clickable_chat_weblinks;
	// Set of "control" keys for weblink mouseclicks
	std::vector<irr::EKEY_CODE> m_cache_chat_weblink_ctrl_keys;
};
