// Copyright (C) 2002-2012 Nikolaus Gebhardt, Modified by Mustapha Tachouct
// This file is part of the "Irrlicht Engine".
// For conditions of distribution and use, see copyright notice in irrlicht.h

#ifndef GUIEDITBOXWITHSCROLLBAR_HEADER
#define GUIEDITBOXWITHSCROLLBAR_HEADER

#include "guiEditBox.h"

class GUIEditBoxWithScrollBar : public GUIEditBox
{
public:

	//! constructor
	GUIEditBoxWithScrollBar(const wchar_t* text, bool border, IGUIEnvironment* environment,
		IGUIElement* parent, s32 id, const core::rect<s32>& rectangle,
		bool writable = true, bool has_vscrollbar = true);

	//! destructor
	virtual ~GUIEditBoxWithScrollBar();

	//! Sets whether to draw the background
	virtual void setDrawBackground(bool draw);

	//! called if an event happened.
	virtual bool OnEvent(const SEvent& event);

	//! draws the element and its children
	virtual void draw();

	//! Updates the absolute position, splits text if required
	virtual void updateAbsolutePosition();

	//! Change the background color
	virtual void setBackgroundColor(const video::SColor &bg_color);

	//! Writes attributes of the element.
	virtual void serializeAttributes(io::IAttributes* out, io::SAttributeReadWriteOptions* options) const;

	//! Reads attributes of the element
	virtual void deserializeAttributes(io::IAttributes* in, io::SAttributeReadWriteOptions* options);

	virtual bool isDrawBackgroundEnabled() const;
	virtual bool isDrawBorderEnabled() const;
	virtual void setCursorChar(const wchar_t cursorChar);
	virtual wchar_t getCursorChar() const;
	virtual void setCursorBlinkTime(irr::u32 timeMs);
	virtual irr::u32 getCursorBlinkTime() const;

protected:
	//! Breaks the single text line.
	virtual void breakText();
	//! sets the area of the given line
	virtual void setTextRect(s32 line);
	//! returns the line number that the cursor is on
	s32 getLineFromPos(s32 pos);
	//! adds a letter to the edit box
	void inputChar(wchar_t c);
	//! calculates the current scroll position
	void calculateScrollPos();
	//! calculated the FrameRect
	void calculateFrameRect();
	//! send some gui event to parent
	void sendGuiEvent(EGUI_EVENT_TYPE type);
	//! set text markers
	void setTextMarkers(s32 begin, s32 end);
	//! create a Vertical ScrollBar
	void createVScrollBar();
	//! update the vertical scrollBar (visibilty & position)
	void updateVScrollBar();

	bool processKey(const SEvent& event);
	bool processMouse(const SEvent& event);
	s32 getCursorPos(s32 x, s32 y);

	bool m_mouse_marking;
	bool m_background;

	s32 m_mark_begin;
	s32 m_mark_end;

	gui::IGUIFont *m_last_break_font;
	IOSOperator* m_operator;



	core::rect<s32> m_frame_rect; // temporary values

	u32 m_scrollbar_width;
	GUIScrollBar *m_vscrollbar;

	bool m_bg_color_used;
	video::SColor m_bg_color;
};


#endif // GUIEDITBOXWITHSCROLLBAR_HEADER

