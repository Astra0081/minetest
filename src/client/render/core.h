/*
Minetest
Copyright (C) 2010-2013 celeron55, Perttu Ahola <celeron55@gmail.com>
Copyright (C) 2017 numzero, Lobachevskiy Vitaliy <numzer0@yandex.ru>

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
#include "pipeline.h"

class ShadowRenderer;
class Camera;
class Client;
class Hud;
class Minimap;

struct PipelineState
{
	bool show_hud {true};
	bool show_minimap {true};
	bool draw_wield_tool {true};
	bool draw_crosshair {true};
};

class Draw3D : public RenderStep
{
public:
	Draw3D(PipelineState *state, scene::ISceneManager *smgr, video::IVideoDriver *driver, Hud *hud, Camera *camera) :
			m_state(state),
			m_smgr(smgr),
			m_driver(driver),
			m_hud(hud),
			m_camera(camera)
	{}

	virtual void run() override;

	virtual void setRenderSource(RenderSource *) override {}
	virtual void setRenderTarget(RenderTarget *) override {}
	virtual void reset() override {}
private:
	PipelineState *m_state;
	scene::ISceneManager *m_smgr;
	video::IVideoDriver *m_driver;
	Hud *m_hud;
	Camera *m_camera;
};

class DrawHUD : public RenderStep
{
public:
	DrawHUD(PipelineState *state, Hud *hud, Camera *camera, Minimap *mapper, Client *client, gui::IGUIEnvironment *guienv, ShadowRenderer *shadow_renderer) :
			m_state(state),
			m_hud(hud),
			m_camera(camera),
			m_mapper(mapper),
			m_client(client),
			m_guienv(guienv),
			m_shadow_renderer(shadow_renderer)
	{}

	virtual void run() override;

	virtual void setRenderSource(RenderSource *) override {}
	virtual void setRenderTarget(RenderTarget *) override {}
	virtual void reset() override {}
private:
	PipelineState *m_state;
	Hud *m_hud;
	Camera *m_camera;
	Minimap *m_mapper;
	Client *m_client;
	gui::IGUIEnvironment *m_guienv;
	ShadowRenderer *m_shadow_renderer;
};

class RenderingCore
{
protected:
	v2u32 screensize;
	v2u32 virtual_size;
	video::SColor skycolor;
	bool show_hud;
	bool show_minimap;
	bool draw_wield_tool;
	bool draw_crosshair;

	IrrlichtDevice *device;
	video::IVideoDriver *driver;
	scene::ISceneManager *smgr;
	gui::IGUIEnvironment *guienv;

	Client *client;
	Camera *camera;
	Minimap *mapper;
	Hud *hud;

	ShadowRenderer *shadow_renderer;

	PipelineState pipelineState;
	RenderStep *step3D;
	RenderStep *stepHUD;
	RenderTarget *screen;


	void updateScreenSize();
	virtual void initTextures() {}
	virtual void clearTextures() {}

	virtual void beforeDraw() {}
	virtual void drawAll() = 0;

	void draw3D();
	void drawHUD();
	void drawPostFx();

public:
	RenderingCore(IrrlichtDevice *_device, Client *_client, Hud *_hud);
	RenderingCore(const RenderingCore &) = delete;
	RenderingCore(RenderingCore &&) = delete;
	virtual ~RenderingCore();

	RenderingCore &operator=(const RenderingCore &) = delete;
	RenderingCore &operator=(RenderingCore &&) = delete;

	void initialize();
	void draw(video::SColor _skycolor, bool _show_hud, bool _show_minimap,
			bool _draw_wield_tool, bool _draw_crosshair);

	inline v2u32 getVirtualSize() const { return virtual_size; }

	ShadowRenderer *get_shadow_renderer() { return shadow_renderer; };
};
