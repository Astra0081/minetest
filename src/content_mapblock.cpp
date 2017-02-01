/*
Minetest
Copyright (C) 2010-2013 celeron55, Perttu Ahola <celeron55@gmail.com>

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

#include "content_mapblock.h"
#include "util/numeric.h"
#include "util/directiontables.h"
#include "mapblock_mesh.h" // For MapBlock_LightColor() and MeshCollector
#include "settings.h"
#include "nodedef.h"
#include "client/tile.h"
#include "mesh.h"
#include <IMeshManipulator.h>
#include "client.h"
#include "log.h"
#include "noise.h"

// Distance of light extrapolation (for oversized nodes)
// After this distance, it gives up and considers light level constant
#define SMOOTH_LIGHTING_OVERSIZE 1.0

struct LightFrame
{
	f32 lightsA[8];
	f32 lightsB[8];
	u8 light_source;
};

static const v3s16 light_dirs[8] = {
	v3s16(-1, -1, -1),
	v3s16(-1, -1,  1),
	v3s16(-1,  1, -1),
	v3s16(-1,  1,  1),
	v3s16( 1, -1, -1),
	v3s16( 1, -1,  1),
	v3s16( 1,  1, -1),
	v3s16( 1,  1,  1),
};

class MapblockMeshGenerator
{
	MeshMakeData *data;
	MeshCollector *collector;

	INodeDefManager *nodedef;
	scene::ISceneManager *smgr;
	scene::IMeshManipulator *meshmanip;

// options
	bool enable_mesh_cache;

// current node
	v3s16 blockpos_nodes;
	v3s16 p;
	core::vector3df origin;
	MapNode n;
	const ContentFeatures *f;
	u16 light;
	LightFrame frame;

// liquid-specific
	bool top_is_same_liquid;
	TileSpec tile_liquid;
	content_t c_flowing;
	content_t c_source;
	video::SColor color;
	struct NeighborData {
		f32 level;
		content_t content;
		bool is_same_liquid;
		bool top_is_same_liquid;
	};
	NeighborData liquid_neighbors[3][3];
	f32 corner_levels[2][2];

	void prepareLiquidNodeDrawing();
	void getLiquidNeighborhood(bool flowing);
	void resetCornerLevels();
	void calculateCornerLevels();
	f32 getCornerLevel(u32 i, u32 k);
	void drawLiquidSides(bool flowing);
	void drawLiquidTop(bool flowing);

// drawtypes
	void drawLiquidNode();
	void drawFlowingLiquidNode();
	void drawGlasslikeNode();
	void drawGlasslikeFramedNode();
	void drawAllfacesNode();
	void drawTorchlikeNode();
	void drawSignlikeNode();
	void drawPlantlikeNode();
	void drawFirelikeNode();
	void drawFencelikeNode();
	void drawRaillikeNode();
	void drawNodeboxNode();
	void drawMeshNode();

	void drawNode();

public:
	MapblockMeshGenerator(MeshMakeData *input, MeshCollector *output);
	void generate();
};

MapblockMeshGenerator::MapblockMeshGenerator(MeshMakeData *input, MeshCollector *output)
{
	data      = input;
	collector = output;

	nodedef   = data->m_client->ndef();
	smgr      = data->m_client->getSceneManager();
	meshmanip = smgr->getMeshManipulator();

	enable_mesh_cache = g_settings->getBool("enable_mesh_cache") &&
		!data->m_smooth_lighting; // Mesh cache is not supported with smooth lighting

	blockpos_nodes = data->m_blockpos * MAP_BLOCKSIZE;
}

// Create a cuboid.
//  collector     - the MeshCollector for the resulting polygons
//  box           - the position and size of the box
//  tiles         - the tiles (materials) to use (for all 6 faces)
//  tilecount     - number of entries in tiles, 1<=tilecount<=6
//  c             - colors of the cuboid's six sides
//  txc           - texture coordinates - this is a list of texture coordinates
//                  for the opposite corners of each face - therefore, there
//                  should be (2+2)*6=24 values in the list. Alternatively,
//                  pass NULL to use the entire texture for each face. The
//                  order of the faces in the list is up-down-right-left-back-
//                  front (compatible with ContentFeatures). If you specified
//                  0,0,1,1 for each face, that would be the same as
//                  passing NULL.
//  light source  - if greater than zero, the box's faces will not be shaded
void makeCuboid(MeshCollector *collector, const aabb3f &box,
	TileSpec *tiles, int tilecount, const video::SColor *c,
	const f32* txc, const u8 light_source)
{
	assert(tilecount >= 1 && tilecount <= 6); // pre-condition

	v3f min = box.MinEdge;
	v3f max = box.MaxEdge;

	if(txc == NULL) {
		static const f32 txc_default[24] = {
			0,0,1,1,
			0,0,1,1,
			0,0,1,1,
			0,0,1,1,
			0,0,1,1,
			0,0,1,1
		};
		txc = txc_default;
	}

	video::SColor c1 = c[0];
	video::SColor c2 = c[1];
	video::SColor c3 = c[2];
	video::SColor c4 = c[3];
	video::SColor c5 = c[4];
	video::SColor c6 = c[5];
	if (!light_source) {
		applyFacesShading(c1, v3f(0, 1, 0));
		applyFacesShading(c2, v3f(0, -1, 0));
		applyFacesShading(c3, v3f(1, 0, 0));
		applyFacesShading(c4, v3f(-1, 0, 0));
		applyFacesShading(c5, v3f(0, 0, 1));
		applyFacesShading(c6, v3f(0, 0, -1));
	}

	video::S3DVertex vertices[24] =
	{
		// up
		video::S3DVertex(min.X,max.Y,max.Z, 0,1,0, c1, txc[0],txc[1]),
		video::S3DVertex(max.X,max.Y,max.Z, 0,1,0, c1, txc[2],txc[1]),
		video::S3DVertex(max.X,max.Y,min.Z, 0,1,0, c1, txc[2],txc[3]),
		video::S3DVertex(min.X,max.Y,min.Z, 0,1,0, c1, txc[0],txc[3]),
		// down
		video::S3DVertex(min.X,min.Y,min.Z, 0,-1,0, c2, txc[4],txc[5]),
		video::S3DVertex(max.X,min.Y,min.Z, 0,-1,0, c2, txc[6],txc[5]),
		video::S3DVertex(max.X,min.Y,max.Z, 0,-1,0, c2, txc[6],txc[7]),
		video::S3DVertex(min.X,min.Y,max.Z, 0,-1,0, c2, txc[4],txc[7]),
		// right
		video::S3DVertex(max.X,max.Y,min.Z, 1,0,0, c3, txc[ 8],txc[9]),
		video::S3DVertex(max.X,max.Y,max.Z, 1,0,0, c3, txc[10],txc[9]),
		video::S3DVertex(max.X,min.Y,max.Z, 1,0,0, c3, txc[10],txc[11]),
		video::S3DVertex(max.X,min.Y,min.Z, 1,0,0, c3, txc[ 8],txc[11]),
		// left
		video::S3DVertex(min.X,max.Y,max.Z, -1,0,0, c4, txc[12],txc[13]),
		video::S3DVertex(min.X,max.Y,min.Z, -1,0,0, c4, txc[14],txc[13]),
		video::S3DVertex(min.X,min.Y,min.Z, -1,0,0, c4, txc[14],txc[15]),
		video::S3DVertex(min.X,min.Y,max.Z, -1,0,0, c4, txc[12],txc[15]),
		// back
		video::S3DVertex(max.X,max.Y,max.Z, 0,0,1, c5, txc[16],txc[17]),
		video::S3DVertex(min.X,max.Y,max.Z, 0,0,1, c5, txc[18],txc[17]),
		video::S3DVertex(min.X,min.Y,max.Z, 0,0,1, c5, txc[18],txc[19]),
		video::S3DVertex(max.X,min.Y,max.Z, 0,0,1, c5, txc[16],txc[19]),
		// front
		video::S3DVertex(min.X,max.Y,min.Z, 0,0,-1, c6, txc[20],txc[21]),
		video::S3DVertex(max.X,max.Y,min.Z, 0,0,-1, c6, txc[22],txc[21]),
		video::S3DVertex(max.X,min.Y,min.Z, 0,0,-1, c6, txc[22],txc[23]),
		video::S3DVertex(min.X,min.Y,min.Z, 0,0,-1, c6, txc[20],txc[23]),
	};

	for(int i = 0; i < 6; i++)
				{
				switch (tiles[MYMIN(i, tilecount-1)].rotation)
				{
				case 0:
					break;
				case 1: //R90
					for (int x = 0; x < 4; x++)
						vertices[i*4+x].TCoords.rotateBy(90,irr::core::vector2df(0, 0));
					break;
				case 2: //R180
					for (int x = 0; x < 4; x++)
						vertices[i*4+x].TCoords.rotateBy(180,irr::core::vector2df(0, 0));
					break;
				case 3: //R270
					for (int x = 0; x < 4; x++)
						vertices[i*4+x].TCoords.rotateBy(270,irr::core::vector2df(0, 0));
					break;
				case 4: //FXR90
					for (int x = 0; x < 4; x++){
						vertices[i*4+x].TCoords.X = 1.0 - vertices[i*4+x].TCoords.X;
						vertices[i*4+x].TCoords.rotateBy(90,irr::core::vector2df(0, 0));
					}
					break;
				case 5: //FXR270
					for (int x = 0; x < 4; x++){
						vertices[i*4+x].TCoords.X = 1.0 - vertices[i*4+x].TCoords.X;
						vertices[i*4+x].TCoords.rotateBy(270,irr::core::vector2df(0, 0));
					}
					break;
				case 6: //FYR90
					for (int x = 0; x < 4; x++){
						vertices[i*4+x].TCoords.Y = 1.0 - vertices[i*4+x].TCoords.Y;
						vertices[i*4+x].TCoords.rotateBy(90,irr::core::vector2df(0, 0));
					}
					break;
				case 7: //FYR270
					for (int x = 0; x < 4; x++){
						vertices[i*4+x].TCoords.Y = 1.0 - vertices[i*4+x].TCoords.Y;
						vertices[i*4+x].TCoords.rotateBy(270,irr::core::vector2df(0, 0));
					}
					break;
				case 8: //FX
					for (int x = 0; x < 4; x++){
						vertices[i*4+x].TCoords.X = 1.0 - vertices[i*4+x].TCoords.X;
					}
					break;
				case 9: //FY
					for (int x = 0; x < 4; x++){
						vertices[i*4+x].TCoords.Y = 1.0 - vertices[i*4+x].TCoords.Y;
					}
					break;
				default:
					break;
				}
			}
	u16 indices[] = {0,1,2,2,3,0};
	// Add to mesh collector
	for (s32 j = 0; j < 24; j += 4) {
		int tileindex = MYMIN(j / 4, tilecount - 1);
		collector->append(tiles[tileindex], vertices + j, 4, indices, 6);
	}
}

// Create a cuboid.
//  collector - the MeshCollector for the resulting polygons
//  box       - the position and size of the box
//  tiles     - the tiles (materials) to use (for all 6 faces)
//  tilecount - number of entries in tiles, 1<=tilecount<=6
//  lights    - vertex light levels. The order is the same as in light_dirs
//  txc       - texture coordinates - this is a list of texture coordinates
//              for the opposite corners of each face - therefore, there
//              should be (2+2)*6=24 values in the list. Alternatively, pass
//              NULL to use the entire texture for each face. The order of
//              the faces in the list is up-down-right-left-back-front
//              (compatible with ContentFeatures). If you specified 0,0,1,1
//              for each face, that would be the same as passing NULL.
//  light_source - node light emission
static void makeSmoothLightedCuboid(MeshCollector *collector, const aabb3f &box,
	TileSpec *tiles, int tilecount, const u16 *lights , const f32 *txc,
	const u8 light_source)
{
	assert(tilecount >= 1 && tilecount <= 6); // pre-condition

	v3f min = box.MinEdge;
	v3f max = box.MaxEdge;

	if (txc == NULL) {
		static const f32 txc_default[24] = {
			0,0,1,1,
			0,0,1,1,
			0,0,1,1,
			0,0,1,1,
			0,0,1,1,
			0,0,1,1
		};
		txc = txc_default;
	}
	static const u8 light_indices[24] = {
		3, 7, 6, 2,
		0, 4, 5, 1,
		6, 7, 5, 4,
		3, 2, 0, 1,
		7, 3, 1, 5,
		2, 6, 4, 0
	};
	video::S3DVertex vertices[24] = {
		// up
		video::S3DVertex(min.X, max.Y, max.Z, 0, 1, 0, video::SColor(), txc[0], txc[1]),
		video::S3DVertex(max.X, max.Y, max.Z, 0, 1, 0, video::SColor(), txc[2], txc[1]),
		video::S3DVertex(max.X, max.Y, min.Z, 0, 1, 0, video::SColor(), txc[2], txc[3]),
		video::S3DVertex(min.X, max.Y, min.Z, 0, 1, 0, video::SColor(), txc[0], txc[3]),
		// down
		video::S3DVertex(min.X, min.Y, min.Z, 0, -1, 0, video::SColor(), txc[4], txc[5]),
		video::S3DVertex(max.X, min.Y, min.Z, 0, -1, 0, video::SColor(), txc[6], txc[5]),
		video::S3DVertex(max.X, min.Y, max.Z, 0, -1, 0, video::SColor(), txc[6], txc[7]),
		video::S3DVertex(min.X, min.Y, max.Z, 0, -1, 0, video::SColor(), txc[4], txc[7]),
		// right
		video::S3DVertex(max.X, max.Y, min.Z, 1, 0, 0, video::SColor(), txc[ 8], txc[9]),
		video::S3DVertex(max.X, max.Y, max.Z, 1, 0, 0, video::SColor(), txc[10], txc[9]),
		video::S3DVertex(max.X, min.Y, max.Z, 1, 0, 0, video::SColor(), txc[10], txc[11]),
		video::S3DVertex(max.X, min.Y, min.Z, 1, 0, 0, video::SColor(), txc[ 8], txc[11]),
		// left
		video::S3DVertex(min.X, max.Y, max.Z, -1, 0, 0, video::SColor(), txc[12], txc[13]),
		video::S3DVertex(min.X, max.Y, min.Z, -1, 0, 0, video::SColor(), txc[14], txc[13]),
		video::S3DVertex(min.X, min.Y, min.Z, -1, 0, 0, video::SColor(), txc[14], txc[15]),
		video::S3DVertex(min.X, min.Y, max.Z, -1, 0, 0, video::SColor(), txc[12], txc[15]),
		// back
		video::S3DVertex(max.X, max.Y, max.Z, 0, 0, 1, video::SColor(), txc[16], txc[17]),
		video::S3DVertex(min.X, max.Y, max.Z, 0, 0, 1, video::SColor(), txc[18], txc[17]),
		video::S3DVertex(min.X, min.Y, max.Z, 0, 0, 1, video::SColor(), txc[18], txc[19]),
		video::S3DVertex(max.X, min.Y, max.Z, 0, 0, 1, video::SColor(), txc[16], txc[19]),
		// front
		video::S3DVertex(min.X, max.Y, min.Z, 0, 0, -1, video::SColor(), txc[20], txc[21]),
		video::S3DVertex(max.X, max.Y, min.Z, 0, 0, -1, video::SColor(), txc[22], txc[21]),
		video::S3DVertex(max.X, min.Y, min.Z, 0, 0, -1, video::SColor(), txc[22], txc[23]),
		video::S3DVertex(min.X, min.Y, min.Z, 0, 0, -1, video::SColor(), txc[20], txc[23]),
	};

	for(int i = 0; i < 6; i++) {
		switch (tiles[MYMIN(i, tilecount-1)].rotation) {
		case 0:
			break;
		case 1: //R90
			for (int x = 0; x < 4; x++)
				vertices[i*4+x].TCoords.rotateBy(90,irr::core::vector2df(0, 0));
			break;
		case 2: //R180
			for (int x = 0; x < 4; x++)
				vertices[i*4+x].TCoords.rotateBy(180,irr::core::vector2df(0, 0));
			break;
		case 3: //R270
			for (int x = 0; x < 4; x++)
				vertices[i*4+x].TCoords.rotateBy(270,irr::core::vector2df(0, 0));
			break;
		case 4: //FXR90
			for (int x = 0; x < 4; x++) {
				vertices[i*4+x].TCoords.X = 1.0 - vertices[i*4+x].TCoords.X;
				vertices[i*4+x].TCoords.rotateBy(90,irr::core::vector2df(0, 0));
			}
			break;
		case 5: //FXR270
			for (int x = 0; x < 4; x++) {
				vertices[i*4+x].TCoords.X = 1.0 - vertices[i*4+x].TCoords.X;
				vertices[i*4+x].TCoords.rotateBy(270,irr::core::vector2df(0, 0));
			}
			break;
		case 6: //FYR90
			for (int x = 0; x < 4; x++) {
				vertices[i*4+x].TCoords.Y = 1.0 - vertices[i*4+x].TCoords.Y;
				vertices[i*4+x].TCoords.rotateBy(90,irr::core::vector2df(0, 0));
			}
			break;
		case 7: //FYR270
			for (int x = 0; x < 4; x++) {
				vertices[i*4+x].TCoords.Y = 1.0 - vertices[i*4+x].TCoords.Y;
				vertices[i*4+x].TCoords.rotateBy(270,irr::core::vector2df(0, 0));
			}
			break;
		case 8: //FX
			for (int x = 0; x < 4; x++) {
				vertices[i*4+x].TCoords.X = 1.0 - vertices[i*4+x].TCoords.X;
			}
			break;
		case 9: //FY
			for (int x = 0; x < 4; x++) {
				vertices[i*4+x].TCoords.Y = 1.0 - vertices[i*4+x].TCoords.Y;
			}
			break;
		default:
			break;
		}
	}
	u16 indices[] = {0,1,2,2,3,0};
	for (s32 j = 0; j < 24; ++j) {
		int tileindex = MYMIN(j / 4, tilecount - 1);
		vertices[j].Color = encode_light_and_color(lights[light_indices[j]],
			tiles[tileindex].color, light_source);
		if (!light_source)
			applyFacesShading(vertices[j].Color, vertices[j].Normal);
	}
	// Add to mesh collector
	for (s32 k = 0; k < 6; ++k) {
		int tileindex = MYMIN(k, tilecount - 1);
		collector->append(tiles[tileindex], vertices + 4 * k, 4, indices, 6);
	}
}

// Create a cuboid.
//  collector     - the MeshCollector for the resulting polygons
//  box           - the position and size of the box
//  tiles         - the tiles (materials) to use (for all 6 faces)
//  tilecount     - number of entries in tiles, 1<=tilecount<=6
//  c             - color of the cuboid
//  txc           - texture coordinates - this is a list of texture coordinates
//                  for the opposite corners of each face - therefore, there
//                  should be (2+2)*6=24 values in the list. Alternatively,
//                  pass NULL to use the entire texture for each face. The
//                  order of the faces in the list is up-down-right-left-back-
//                  front (compatible with ContentFeatures). If you specified
//                  0,0,1,1 for each face, that would be the same as
//                  passing NULL.
//  light source  - if greater than zero, the box's faces will not be shaded
void makeCuboid(MeshCollector *collector, const aabb3f &box, TileSpec *tiles,
	int tilecount, const video::SColor &c, const f32* txc,
	const u8 light_source)
{
	video::SColor color[6];
	for (u8 i = 0; i < 6; i++)
		color[i] = c;
	makeCuboid(collector, box, tiles, tilecount, color, txc, light_source);
}

// Gets the base lighting values for a node
//  frame  - resulting (opaque) data
//  p      - node position (absolute)
//  data   - ...
//  light_source - node light emission level
static void getSmoothLightFrame(LightFrame *frame, const v3s16 &p, MeshMakeData *data, u8 light_source)
{
	for (int k = 0; k < 8; ++k) {
		u16 light = getSmoothLight(p, light_dirs[k], data);
		frame->lightsA[k] = light & 0xff;
		frame->lightsB[k] = light >> 8;
	}
	frame->light_source = light_source;
}

// Calculates vertex light level
//  frame        - light values from getSmoothLightFrame()
//  vertex_pos   - vertex position in the node (coordinates are clamped to [0.0, 1.0] or so)
static u16 blendLight(const LightFrame &frame, const core::vector3df& vertex_pos)
{
	f32 x = core::clamp(vertex_pos.X / BS + 0.5, 0.0 - SMOOTH_LIGHTING_OVERSIZE, 1.0 + SMOOTH_LIGHTING_OVERSIZE);
	f32 y = core::clamp(vertex_pos.Y / BS + 0.5, 0.0 - SMOOTH_LIGHTING_OVERSIZE, 1.0 + SMOOTH_LIGHTING_OVERSIZE);
	f32 z = core::clamp(vertex_pos.Z / BS + 0.5, 0.0 - SMOOTH_LIGHTING_OVERSIZE, 1.0 + SMOOTH_LIGHTING_OVERSIZE);
	f32 lightA = 0.0;
	f32 lightB = 0.0;
	for (int k = 0; k < 8; ++k) {
		f32 dx = (k & 4) ? x : 1 - x;
		f32 dy = (k & 2) ? y : 1 - y;
		f32 dz = (k & 1) ? z : 1 - z;
		lightA += dx * dy * dz * frame.lightsA[k];
		lightB += dx * dy * dz * frame.lightsB[k];
	}
	return
		core::clamp(core::round32(lightA), 0, 255) |
		core::clamp(core::round32(lightB), 0, 255) << 8;
}

// Calculates vertex color to be used in mapblock mesh
//  frame        - light values from getSmoothLightFrame()
//  vertex_pos   - vertex position in the node (coordinates are clamped to [0.0, 1.0] or so)
//  tile_color   - node's tile color
static video::SColor blendLight(const LightFrame &frame,
	const core::vector3df& vertex_pos, video::SColor tile_color)
{
	u16 light = blendLight(frame, vertex_pos);
	return encode_light_and_color(light, tile_color, frame.light_source);
}

static video::SColor blendLight(const LightFrame &frame,
	const core::vector3df& vertex_pos, const core::vector3df& vertex_normal,
	video::SColor tile_color)
{
	video::SColor color = blendLight(frame, vertex_pos, tile_color);
	if (!frame.light_source)
			applyFacesShading(color, vertex_normal);
	return color;
}

static inline void getNeighborConnectingFace(v3s16 p, INodeDefManager *nodedef,
		MeshMakeData *data, MapNode n, int v, int *neighbors)
{
	MapNode n2 = data->m_vmanip.getNodeNoEx(p);
	if (nodedef->nodeboxConnects(n, n2, v))
		*neighbors |= v;
}

static void makeAutoLightedCuboid(MeshCollector *collector, MeshMakeData *data,
	const v3f &pos, aabb3f box, TileSpec &tile,
	/* pre-computed, for non-smooth lighting only */ const video::SColor color,
	/* for smooth lighting only */ const LightFrame &frame)
{
	f32 dx1 = box.MinEdge.X;
	f32 dy1 = box.MinEdge.Y;
	f32 dz1 = box.MinEdge.Z;
	f32 dx2 = box.MaxEdge.X;
	f32 dy2 = box.MaxEdge.Y;
	f32 dz2 = box.MaxEdge.Z;
	box.MinEdge += pos;
	box.MaxEdge += pos;
	f32 tx1 = (box.MinEdge.X / BS) + 0.5;
	f32 ty1 = (box.MinEdge.Y / BS) + 0.5;
	f32 tz1 = (box.MinEdge.Z / BS) + 0.5;
	f32 tx2 = (box.MaxEdge.X / BS) + 0.5;
	f32 ty2 = (box.MaxEdge.Y / BS) + 0.5;
	f32 tz2 = (box.MaxEdge.Z / BS) + 0.5;
	f32 txc[24] = {
		  tx1, 1-tz2,   tx2, 1-tz1, // up
		  tx1,   tz1,   tx2,   tz2, // down
		  tz1, 1-ty2,   tz2, 1-ty1, // right
		1-tz2, 1-ty2, 1-tz1, 1-ty1, // left
		1-tx2, 1-ty2, 1-tx1, 1-ty1, // back
		  tx1, 1-ty2,   tx2, 1-ty1, // front
	};
	if (data->m_smooth_lighting) {
		u16 lights[8];
		for (int j = 0; j < 8; ++j) {
			f32 x = (j & 4) ? dx2 : dx1;
			f32 y = (j & 2) ? dy2 : dy1;
			f32 z = (j & 1) ? dz2 : dz1;
			lights[j] = blendLight(frame, core::vector3df(x, y, z));
		}
		makeSmoothLightedCuboid(collector, box, &tile, 1, lights, txc, frame.light_source);
	} else {
		makeCuboid(collector, box, &tile, 1, color, txc, frame.light_source);
	}
}

static void makeAutoLightedCuboidEx(MeshCollector *collector, MeshMakeData *data,
	const v3f &pos, aabb3f box, TileSpec &tile, f32 *txc,
	/* pre-computed, for non-smooth lighting only */ const video::SColor color,
	/* for smooth lighting only */ const LightFrame &frame)
{
	f32 dx1 = box.MinEdge.X;
	f32 dy1 = box.MinEdge.Y;
	f32 dz1 = box.MinEdge.Z;
	f32 dx2 = box.MaxEdge.X;
	f32 dy2 = box.MaxEdge.Y;
	f32 dz2 = box.MaxEdge.Z;
	box.MinEdge += pos;
	box.MaxEdge += pos;
	if (data->m_smooth_lighting) {
		u16 lights[8];
		for (int j = 0; j < 8; ++j) {
			f32 x = (j & 4) ? dx2 : dx1;
			f32 y = (j & 2) ? dy2 : dy1;
			f32 z = (j & 1) ? dz2 : dz1;
			lights[j] = blendLight(frame, core::vector3df(x, y, z));
		}
		makeSmoothLightedCuboid(collector, box, &tile, 1, lights, txc, frame.light_source);
	} else {
		makeCuboid(collector, box, &tile, 1, color, txc, frame.light_source);
	}
}

/*!
 * Returns the i-th special tile for a map node.
 */
static TileSpec getSpecialTile(const ContentFeatures &f,
	const MapNode &n, u8 i)
{
	TileSpec copy = f.special_tiles[i];
	if (!copy.has_color)
		n.getColor(f, &copy.color);
	return copy;
}

void MapblockMeshGenerator::prepareLiquidNodeDrawing()
{
	tile_liquid = getSpecialTile(*f, n, 0);

	MapNode ntop = data->m_vmanip.getNodeNoEx(blockpos_nodes + v3s16(p.X,p.Y+1,p.Z));
	c_flowing = nodedef->getId(f->liquid_alternative_flowing);
	c_source = nodedef->getId(f->liquid_alternative_source);
	top_is_same_liquid = (ntop.getContent() == c_flowing) || (ntop.getContent() == c_source);

	if (data->m_smooth_lighting)
		return; // don't need to pre-compute anything in this case

	// If this liquid emits light and doesn't contain light, draw
	// it at what it emits, for an increased effect
	if (f->light_source != 0) {
		light = decode_light(f->light_source);
		light = light | (light << 8);
	}
	// Use the light of the node on top if possible
	else if (nodedef->get(ntop).param_type == CPT_LIGHT)
		light = getInteriorLight(ntop, 0, nodedef);

	color = encode_light_and_color(light, tile_liquid.color, f->light_source);
}

void MapblockMeshGenerator::getLiquidNeighborhood(bool flowing)
{
	u8 range = rangelim(nodedef->get(c_flowing).liquid_range, 1, 8);

	for (s32 w = -1; w <= 1; w++)
	for (s32 u = -1; u <= 1; u++)
	{
		// Skip getting unneeded data
		if (!flowing && u && w)
			continue;

		NeighborData &neighbor = liquid_neighbors[w + 1][u + 1];
		v3s16 p2 = p + v3s16(u, 0, w);
		MapNode n2 = data->m_vmanip.getNodeNoExNoEmerge(blockpos_nodes + p2);
		neighbor.content = n2.getContent();
		neighbor.level = -0.5 * BS;
		neighbor.is_same_liquid = false;
		neighbor.top_is_same_liquid = false;

		if (neighbor.content == CONTENT_IGNORE)
			continue;

		if (neighbor.content == c_source) {
			neighbor.is_same_liquid = true;
			neighbor.level = 0.5 * BS;
		} else if (neighbor.content == c_flowing) {
			neighbor.is_same_liquid = true;
			u8 liquid_level = (n2.param2 & LIQUID_LEVEL_MASK);
			if (liquid_level <= LIQUID_LEVEL_MAX + 1 - range)
				liquid_level = 0;
			else
				liquid_level -= (LIQUID_LEVEL_MAX + 1 - range);
			neighbor.level = (-0.5 + (liquid_level + 0.5) / range) * BS;
		}

		// Check node above neighbor.
		// NOTE: This doesn't get executed if neighbor
		//       doesn't exist
		p2.Y += 1;
		n2 = data->m_vmanip.getNodeNoExNoEmerge(blockpos_nodes + p2);
		if (n2.getContent() == c_source || n2.getContent() == c_flowing)
			neighbor.top_is_same_liquid = true;
	}
}

void MapblockMeshGenerator::resetCornerLevels()
{
	for (u32 k = 0; k < 2; k++)
	for (u32 i = 0; i < 2; i++)
		corner_levels[k][i] = 0.5 * BS;
}

void MapblockMeshGenerator::calculateCornerLevels()
{
	for (u32 k = 0; k < 2; k++)
	for (u32 i = 0; i < 2; i++)
		corner_levels[k][i] = getCornerLevel(i, k);
}

f32 MapblockMeshGenerator::getCornerLevel(u32 i, u32 k)
{
	float sum = 0;
	u32 count = 0;
	u32 air_count = 0;
	for (u32 dk = 0; dk < 2; dk++)
	for (u32 di = 0; di < 2; di++)
	{
		NeighborData &neighbor_data = liquid_neighbors[k + dk][i + di];
		content_t content = neighbor_data.content;

		// If top is liquid, draw starting from top of node
		if (neighbor_data.top_is_same_liquid)
			return 0.5 * BS;

		// Source always has the full height
		if(content == c_source)
			return sum = 0.5 * BS;

		// Flowing liquid has level information
		if(content == c_flowing) {
			sum += neighbor_data.level;
			count++;
		}
		else if(content == CONTENT_AIR) {
			air_count++;
			if(air_count >= 2)
				return -0.5 * BS + 0.2;
		}
	}
	if(count > 0)
		return sum / count;
	return 0;
}

void MapblockMeshGenerator::drawLiquidSides(bool flowing)
{
	struct LiquidFaceDesc {
		v3s16 dir; // XZ
		v3s16 p[2]; // XZ only; 1 means +, 0 means -
	};
	struct UV {
		s32 u, v;
	};
	static const LiquidFaceDesc base_faces[4] = {
		{ v3s16( 1, 0,  0), { v3s16(1, 0, 1), v3s16(1, 0, 0) }},
		{ v3s16(-1, 0,  0), { v3s16(0, 0, 0), v3s16(0, 0, 1) }},
		{ v3s16( 0, 0,  1), { v3s16(0, 0, 1), v3s16(1, 0, 1) }},
		{ v3s16( 0, 0, -1), { v3s16(1, 0, 0), v3s16(0, 0, 0) }},
	};
	static const UV base_vertices[4] = {
		{ 0, 1 },
		{ 1, 1 },
		{ 1, 0 },
		{ 0, 0 }
	};
	for (u32 i = 0; i < 4; i++)
	{
		const LiquidFaceDesc &face = base_faces[i];
		NeighborData &neighbor = liquid_neighbors[face.dir.Z + 1][face.dir.X + 1];

		// No face between nodes of the same liquid, unless there is node
		// at the top to which it should be connected. Again, unless the face
		// there would be inside the liquid
		if (neighbor.is_same_liquid) {
			if (!flowing)
				continue;
			if (!top_is_same_liquid)
				continue;
			if (neighbor.top_is_same_liquid)
				continue;
		}

		content_t neighbor_content = neighbor.content;
		if (!flowing && (neighbor_content == CONTENT_IGNORE))
			continue;

		const ContentFeatures &neighbor_features = nodedef->get(neighbor_content);
		// Don't draw face if neighbor is blocking the view
		if (neighbor_features.solidness == 2)
			continue;

		video::S3DVertex vertices[4];
		for (s32 j = 0; j < 4; j++) {
			const UV &vertex = base_vertices[j];
			const v3s16 &base = face.p[vertex.u];
			v3f pos;
			pos.X = (base.X - 0.5) * BS;
			pos.Z = (base.Z - 0.5) * BS;
			if (vertex.v)
				pos.Y = neighbor.is_same_liquid ? corner_levels[base.Z][base.X] : -0.5 * BS;
			else
				pos.Y =     !top_is_same_liquid ? corner_levels[base.Z][base.X] :  0.5 * BS;
			if (data->m_smooth_lighting)
				color = blendLight(frame, pos, tile_liquid.color);
			pos += origin;
			vertices[j] = video::S3DVertex(pos.X, pos.Y, pos.Z, 0, 0, 0, color, vertex.u, vertex.v);
		};
		u16 indices[] = {0,1,2,2,3,0};
		collector->append(tile_liquid, vertices, 4, indices, 6);
	}
}

void MapblockMeshGenerator::drawLiquidTop(bool flowing)
{
	// To get backface culling right, the vertices need to go
	// clockwise around the front of the face. And we happened to
	// calculate corner levels in exact reverse order.
	s32 corner_resolve[4][2] = {{0, 1}, {1, 1}, {1, 0}, {0, 0}};

	video::S3DVertex vertices[4] = {
		video::S3DVertex(-BS/2, 0,  BS/2, 0,0,0, color, 0,1),
		video::S3DVertex( BS/2, 0,  BS/2, 0,0,0, color, 1,1),
		video::S3DVertex( BS/2, 0, -BS/2, 0,0,0, color, 1,0),
		video::S3DVertex(-BS/2, 0, -BS/2, 0,0,0, color, 0,0),
	};

	for (s32 i = 0; i < 4; i++) {
		s32 u = corner_resolve[i][0];
		s32 w = corner_resolve[i][1];
		vertices[i].Pos.Y += corner_levels[w][u];
		if (data->m_smooth_lighting)
			vertices[i].Color = blendLight(frame, vertices[i].Pos, tile_liquid.color);
		vertices[i].Pos += origin;
	}

	if (flowing) {
		// Default downwards-flowing texture animation goes from
		// -Z towards +Z, thus the direction is +Z.
		// Rotate texture to make animation go in flow direction
		// Positive if liquid moves towards +Z
		f32 dz = (corner_levels[0][0] + corner_levels[0][1]) -
				 (corner_levels[1][0] + corner_levels[1][1]);
		// Positive if liquid moves towards +X
		f32 dx = (corner_levels[0][0] + corner_levels[1][0]) -
				 (corner_levels[0][1] + corner_levels[1][1]);
		f32 tcoord_angle = atan2(dz, dx) * core::RADTODEG;
		v2f tcoord_center(0.5, 0.5);
		v2f tcoord_translate(
				blockpos_nodes.Z + p.Z,
				blockpos_nodes.X + p.X);
		tcoord_translate.rotateBy(tcoord_angle);
		tcoord_translate.X -= floor(tcoord_translate.X);
		tcoord_translate.Y -= floor(tcoord_translate.Y);

		for (s32 i = 0; i < 4; i++) {
			vertices[i].TCoords.rotateBy(tcoord_angle, tcoord_center);
			vertices[i].TCoords += tcoord_translate;
		}

		std::swap(vertices[0].TCoords, vertices[2].TCoords);
	}

	u16 indices[] = {0,1,2,2,3,0};
	collector->append(tile_liquid, vertices, 4, indices, 6);
}

void MapblockMeshGenerator::drawLiquidNode()
{
	prepareLiquidNodeDrawing();
	getLiquidNeighborhood(false);
	resetCornerLevels();
	drawLiquidSides(false);
	if (!top_is_same_liquid)
		drawLiquidTop(false);
}

void MapblockMeshGenerator::drawFlowingLiquidNode()
{
	prepareLiquidNodeDrawing();
	getLiquidNeighborhood(true);
	calculateCornerLevels();
	drawLiquidSides(true);
	if (!top_is_same_liquid)
		drawLiquidTop(true);
}

void MapblockMeshGenerator::drawGlasslikeNode()
{
	TileSpec tile = getNodeTile(n, p, v3s16(0,0,0), data);

	u16 l = getInteriorLight(n, 1, nodedef);
	video::SColor c = encode_light_and_color(l, tile.color,
		f->light_source);
	for(u32 j=0; j<6; j++)
	{
		// Check this neighbor
		v3s16 dir = g_6dirs[j];
		v3s16 n2p = blockpos_nodes + p + dir;
		MapNode n2 = data->m_vmanip.getNodeNoEx(n2p);
		// Don't make face if neighbor is of same type
		if(n2.getContent() == n.getContent())
			continue;
		video::SColor c2=c;
		if(!f->light_source)
			applyFacesShading(c2, v3f(dir.X, dir.Y, dir.Z));


		// The face at Z+
		video::S3DVertex vertices[4] = {
			video::S3DVertex(-BS/2,-BS/2,BS/2, dir.X,dir.Y,dir.Z, c2, 1,1),
			video::S3DVertex(BS/2,-BS/2,BS/2, dir.X,dir.Y,dir.Z, c2, 0,1),
			video::S3DVertex(BS/2,BS/2,BS/2, dir.X,dir.Y,dir.Z, c2, 0,0),
			video::S3DVertex(-BS/2,BS/2,BS/2, dir.X,dir.Y,dir.Z, c2, 1,0),
		};

		// Rotations in the g_6dirs format
		if(j == 0) // Z+
			for(u16 i=0; i<4; i++)
				vertices[i].Pos.rotateXZBy(0);
		else if(j == 1) // Y+
			for(u16 i=0; i<4; i++)
				vertices[i].Pos.rotateYZBy(-90);
		else if(j == 2) // X+
			for(u16 i=0; i<4; i++)
				vertices[i].Pos.rotateXZBy(-90);
		else if(j == 3) // Z-
			for(u16 i=0; i<4; i++)
				vertices[i].Pos.rotateXZBy(180);
		else if(j == 4) // Y-
			for(u16 i=0; i<4; i++)
				vertices[i].Pos.rotateYZBy(90);
		else if(j == 5) // X-
			for(u16 i=0; i<4; i++)
				vertices[i].Pos.rotateXZBy(90);

		for (u16 i = 0; i < 4; i++) {
			if (data->m_smooth_lighting)
				vertices[i].Color = blendLight(frame, vertices[i].Pos, vertices[i].Normal, tile.color);
			vertices[i].Pos += origin;
		}

		u16 indices[] = {0,1,2,2,3,0};
		// Add to mesh collector
		collector->append(tile, vertices, 4, indices, 6);
	}
}

void MapblockMeshGenerator::drawGlasslikeFramedNode()
{
	static const v3s16 dirs[6] = {
		v3s16( 0, 1, 0),
		v3s16( 0,-1, 0),
		v3s16( 1, 0, 0),
		v3s16(-1, 0, 0),
		v3s16( 0, 0, 1),
		v3s16( 0, 0,-1)
	};

	u16 l = getInteriorLight(n, 1, nodedef);
	u8 i;
	TileSpec tiles[6];
	for (i = 0; i < 6; i++)
		tiles[i] = getNodeTile(n, p, dirs[i], data);

	video::SColor tile0color = encode_light_and_color(l,
		tiles[0].color, f->light_source);

	TileSpec glass_tiles[6];
	video::SColor glasscolor[6];
	if (tiles[1].texture && tiles[2].texture && tiles[3].texture) {
		glass_tiles[0] = tiles[2];
		glass_tiles[1] = tiles[3];
		glass_tiles[2] = tiles[1];
		glass_tiles[3] = tiles[1];
		glass_tiles[4] = tiles[1];
		glass_tiles[5] = tiles[1];
	} else {
		for (i = 0; i < 6; i++)
			glass_tiles[i] = tiles[1];
	}
	for (i = 0; i < 6; i++)
		glasscolor[i] = encode_light_and_color(l, glass_tiles[i].color,
			f->light_source);

	u8 param2 = n.getParam2();
	bool H_merge = ! bool(param2 & 128);
	bool V_merge = ! bool(param2 & 64);
	param2  = param2 & 63;

	static const float a = BS / 2;
	static const float g = a - 0.003;
	static const float b = .876 * ( BS / 2 );

	static const aabb3f frame_edges[12] = {
		aabb3f( b, b,-a, a, a, a), // y+
		aabb3f(-a, b,-a,-b, a, a), // y+
		aabb3f( b,-a,-a, a,-b, a), // y-
		aabb3f(-a,-a,-a,-b,-b, a), // y-
		aabb3f( b,-a, b, a, a, a), // x+
		aabb3f( b,-a,-a, a, a,-b), // x+
		aabb3f(-a,-a, b,-b, a, a), // x-
		aabb3f(-a,-a,-a,-b, a,-b), // x-
		aabb3f(-a, b, b, a, a, a), // z+
		aabb3f(-a,-a, b, a,-b, a), // z+
		aabb3f(-a,-a,-a, a,-b,-b), // z-
		aabb3f(-a, b,-a, a, a,-b)  // z-
	};
	static const aabb3f glass_faces[6] = {
		aabb3f(-g, g,-g, g, g, g), // y+
		aabb3f(-g,-g,-g, g,-g, g), // y-
		aabb3f( g,-g,-g, g, g, g), // x+
		aabb3f(-g,-g,-g,-g, g, g), // x-
		aabb3f(-g,-g, g, g, g, g), // z+
		aabb3f(-g,-g,-g, g, g,-g)  // z-
	};

	// table of node visible faces, 0 = invisible
	int visible_faces[6] = {0,0,0,0,0,0};

	// table of neighbours, 1 = same type, checked with g_26dirs
	int nb[18] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

	// g_26dirs to check when only horizontal merge is allowed
	int nb_H_dirs[8] = {0,2,3,5,10,11,12,13};

	content_t current = n.getContent();
	content_t n2c;
	MapNode n2;
	v3s16 n2p;

	// neighbours checks for frames visibility

	if (!H_merge && V_merge) {
		n2p = blockpos_nodes + p + g_26dirs[1];
		n2 = data->m_vmanip.getNodeNoEx(n2p);
		n2c = n2.getContent();
		if (n2c == current || n2c == CONTENT_IGNORE)
			nb[1] = 1;
		n2p = blockpos_nodes + p + g_26dirs[4];
		n2 = data->m_vmanip.getNodeNoEx(n2p);
		n2c = n2.getContent();
		if (n2c == current || n2c == CONTENT_IGNORE)
			nb[4] = 1;
	} else if (H_merge && !V_merge) {
		for(i = 0; i < 8; i++) {
			n2p = blockpos_nodes + p + g_26dirs[nb_H_dirs[i]];
			n2 = data->m_vmanip.getNodeNoEx(n2p);
			n2c = n2.getContent();
			if (n2c == current || n2c == CONTENT_IGNORE)
				nb[nb_H_dirs[i]] = 1;
		}
	} else if (H_merge && V_merge) {
		for(i = 0; i < 18; i++)	{
			n2p = blockpos_nodes + p + g_26dirs[i];
			n2 = data->m_vmanip.getNodeNoEx(n2p);
			n2c = n2.getContent();
			if (n2c == current || n2c == CONTENT_IGNORE)
				nb[i] = 1;
		}
	}

	// faces visibility checks

	if (!V_merge) {
		visible_faces[0] = 1;
		visible_faces[1] = 1;
	} else {
		for(i = 0; i < 2; i++) {
			n2p = blockpos_nodes + p + dirs[i];
			n2 = data->m_vmanip.getNodeNoEx(n2p);
			n2c = n2.getContent();
			if (n2c != current)
				visible_faces[i] = 1;
		}
	}

	if (!H_merge) {
		visible_faces[2] = 1;
		visible_faces[3] = 1;
		visible_faces[4] = 1;
		visible_faces[5] = 1;
	} else {
		for(i = 2; i < 6; i++) {
			n2p = blockpos_nodes + p + dirs[i];
			n2 = data->m_vmanip.getNodeNoEx(n2p);
			n2c = n2.getContent();
			if (n2c != current)
				visible_faces[i] = 1;
		}
	}

	static const u8 nb_triplet[12*3] = {
		1,2, 7,  1,5, 6,  4,2,15,  4,5,14,
		2,0,11,  2,3,13,  5,0,10,  5,3,12,
		0,1, 8,  0,4,16,  3,4,17,  3,1, 9
	};

	aabb3f box;

	for(i = 0; i < 12; i++)
	{
		int edge_invisible;
		if (nb[nb_triplet[i*3+2]])
			edge_invisible = nb[nb_triplet[i*3]] & nb[nb_triplet[i*3+1]];
		else
			edge_invisible = nb[nb_triplet[i*3]] ^ nb[nb_triplet[i*3+1]];
		if (edge_invisible)
			continue;
		box = frame_edges[i];
		makeAutoLightedCuboid(collector, data, origin, box, tiles[0], tile0color, frame);
	}

	for(i = 0; i < 6; i++)
	{
		if (!visible_faces[i])
			continue;
		box = glass_faces[i];
		makeAutoLightedCuboid(collector, data, origin, box, glass_tiles[i], glasscolor[i], frame);
	}

	if (param2 > 0 && f->special_tiles[0].texture) {
		// Interior volume level is in range 0 .. 63,
		// convert it to -0.5 .. 0.5
		float vlev = (((float)param2 / 63.0 ) * 2.0 - 1.0);
		TileSpec tile = getSpecialTile(*f, n, 0);
		video::SColor special_color = encode_light_and_color(l,
			tile.color, f->light_source);
		float offset = 0.003;
		box = aabb3f(visible_faces[3] ? -b : -a + offset,
						visible_faces[1] ? -b : -a + offset,
						visible_faces[5] ? -b : -a + offset,
						visible_faces[2] ? b : a - offset,
						visible_faces[0] ? b * vlev : a * vlev - offset,
						visible_faces[4] ? b : a - offset);
		makeAutoLightedCuboid(collector, data, origin, box, tile, special_color, frame);
	}
}

void MapblockMeshGenerator::drawAllfacesNode()
{
	TileSpec tile_leaves = getNodeTile(n, p,
			v3s16(0,0,0), data);
	u16 l = getInteriorLight(n, 1, nodedef);
	video::SColor c = encode_light_and_color(l,
		tile_leaves.color, f->light_source);

	aabb3f box(-BS/2,-BS/2,-BS/2,BS/2,BS/2,BS/2);
	makeAutoLightedCuboid(collector, data, origin, box, tile_leaves, c, frame);
}

void MapblockMeshGenerator::drawTorchlikeNode()
{
	v3s16 dir = n.getWallMountedDir(nodedef);

	u8 tileindex = 0;
	if(dir == v3s16(0,-1,0)){
		tileindex = 0; // floor
	} else if(dir == v3s16(0,1,0)){
		tileindex = 1; // ceiling
	// For backwards compatibility
	} else if(dir == v3s16(0,0,0)){
		tileindex = 0; // floor
	} else {
		tileindex = 2; // side
	}

	TileSpec tile = getNodeTileN(n, p, tileindex, data);
	tile.material_flags &= ~MATERIAL_FLAG_BACKFACE_CULLING;
	tile.material_flags |= MATERIAL_FLAG_CRACK_OVERLAY;

	u16 l = getInteriorLight(n, 1, nodedef);
	video::SColor c = encode_light_and_color(l, tile.color,
		f->light_source);

	float s = BS/2*f->visual_scale;
	// Wall at X+ of node
	video::S3DVertex vertices[4] =
	{
		video::S3DVertex(-s,-s,0, 0,0,0, c, 0,1),
		video::S3DVertex( s,-s,0, 0,0,0, c, 1,1),
		video::S3DVertex( s, s,0, 0,0,0, c, 1,0),
		video::S3DVertex(-s, s,0, 0,0,0, c, 0,0),
	};

	for (s32 i = 0; i < 4; i++)
	{
		if(dir == v3s16(1,0,0))
			vertices[i].Pos.rotateXZBy(0);
		if(dir == v3s16(-1,0,0))
			vertices[i].Pos.rotateXZBy(180);
		if(dir == v3s16(0,0,1))
			vertices[i].Pos.rotateXZBy(90);
		if(dir == v3s16(0,0,-1))
			vertices[i].Pos.rotateXZBy(-90);
		if(dir == v3s16(0,-1,0))
			vertices[i].Pos.rotateXZBy(45);
		if(dir == v3s16(0,1,0))
			vertices[i].Pos.rotateXZBy(-45);

		if (data->m_smooth_lighting)
			vertices[i].Color = blendLight(frame, vertices[i].Pos, tile.color);
		vertices[i].Pos += origin;
	}

	u16 indices[] = {0,1,2,2,3,0};
	// Add to mesh collector
	collector->append(tile, vertices, 4, indices, 6);
}

void MapblockMeshGenerator::drawSignlikeNode()
{
	TileSpec tile = getNodeTileN(n, p, 0, data);
	tile.material_flags &= ~MATERIAL_FLAG_BACKFACE_CULLING;
	tile.material_flags |= MATERIAL_FLAG_CRACK_OVERLAY;

	u16 l = getInteriorLight(n, 0, nodedef);
	video::SColor c = encode_light_and_color(l, tile.color,
		f->light_source);

	float d = (float)BS/16;
	float s = BS/2*f->visual_scale;
	// Wall at X+ of node
	video::S3DVertex vertices[4] =
	{
		video::S3DVertex(BS/2-d,  s,  s, 0,0,0, c, 0,0),
		video::S3DVertex(BS/2-d,  s, -s, 0,0,0, c, 1,0),
		video::S3DVertex(BS/2-d, -s, -s, 0,0,0, c, 1,1),
		video::S3DVertex(BS/2-d, -s,  s, 0,0,0, c, 0,1),
	};

	v3s16 dir = n.getWallMountedDir(nodedef);

	for (s32 i = 0; i < 4; i++)
	{
		if(dir == v3s16(1,0,0))
			vertices[i].Pos.rotateXZBy(0);
		if(dir == v3s16(-1,0,0))
			vertices[i].Pos.rotateXZBy(180);
		if(dir == v3s16(0,0,1))
			vertices[i].Pos.rotateXZBy(90);
		if(dir == v3s16(0,0,-1))
			vertices[i].Pos.rotateXZBy(-90);
		if(dir == v3s16(0,-1,0))
			vertices[i].Pos.rotateXYBy(-90);
		if(dir == v3s16(0,1,0))
			vertices[i].Pos.rotateXYBy(90);

		if (data->m_smooth_lighting)
			vertices[i].Color = blendLight(frame, vertices[i].Pos, tile.color);
		vertices[i].Pos += origin;
	}

	u16 indices[] = {0,1,2,2,3,0};
	// Add to mesh collector
	collector->append(tile, vertices, 4, indices, 6);
}

void MapblockMeshGenerator::drawPlantlikeNode()
{
	PseudoRandom rng(p.X<<8 | p.Z | p.Y<<16);

	TileSpec tile = getNodeTileN(n, p, 0, data);
	tile.material_flags |= MATERIAL_FLAG_CRACK_OVERLAY;

	u16 l = getInteriorLight(n, 1, nodedef);
	video::SColor c = encode_light_and_color(l, tile.color,
		f->light_source);

	float s = BS / 2 * f->visual_scale;
	// add sqrt(2) visual scale
	if ((f->param_type_2 == CPT2_MESHOPTIONS) && ((n.param2 & 0x10) != 0))
		s *= 1.41421;

	float random_offset_X = .0;
	float random_offset_Z = .0;
	if ((f->param_type_2 == CPT2_MESHOPTIONS) && ((n.param2 & 0x8) != 0)) {
		random_offset_X = BS * ((rng.next() % 16 / 16.0) * 0.29 - 0.145);
		random_offset_Z = BS * ((rng.next() % 16 / 16.0) * 0.29 - 0.145);
	}

	for (int j = 0; j < 4; j++) {
		video::S3DVertex vertices[4] =
		{
			video::S3DVertex(-s,-BS/2, 0, 0,0,0, c, 0,1),
			video::S3DVertex( s,-BS/2, 0, 0,0,0, c, 1,1),
			video::S3DVertex( s,-BS/2 + s*2,0, 0,0,0, c, 1,0),
			video::S3DVertex(-s,-BS/2 + s*2,0, 0,0,0, c, 0,0),
		};

		float rotate_degree = 0;
		u8 p2mesh = 0;
		if (f->param_type_2 == CPT2_DEGROTATE)
			rotate_degree = n.param2 * 2;
		if (f->param_type_2 != CPT2_MESHOPTIONS) {
			if (j == 0) {
				for (u16 i = 0; i < 4; i++)
					vertices[i].Pos.rotateXZBy(46 + rotate_degree);
			} else if (j == 1) {
				for (u16 i = 0; i < 4; i++)
					vertices[i].Pos.rotateXZBy(-44 + rotate_degree);
			}
		} else {
			p2mesh = n.param2 & 0x7;
			switch (p2mesh) {
			case 0:
				// p.X
				if (j == 0) {
					for (u16 i = 0; i < 4; i++)
						vertices[i].Pos.rotateXZBy(46);
				} else if (j == 1) {
					for (u16 i = 0; i < 4; i++)
						vertices[i].Pos.rotateXZBy(-44);
				}
				break;
			case 1:
				// +
				if (j == 0) {
					for (u16 i = 0; i < 4; i++)
						vertices[i].Pos.rotateXZBy(91);
				} else if (j == 1) {
					for (u16 i = 0; i < 4; i++)
						vertices[i].Pos.rotateXZBy(1);
				}
				break;
			case 2:
				// *
				if (j == 0) {
					for (u16 i = 0; i < 4; i++)
						vertices[i].Pos.rotateXZBy(121);
				} else if (j == 1) {
					for (u16 i = 0; i < 4; i++)
						vertices[i].Pos.rotateXZBy(241);
				} else { // (j == 2)
					for (u16 i = 0; i < 4; i++)
						vertices[i].Pos.rotateXZBy(1);
				}
				break;
			case 3:
				// #
				switch (j) {
				case 0:
					for (u16 i = 0; i < 4; i++) {
						vertices[i].Pos.rotateXZBy(1);
						vertices[i].Pos.Z += BS / 4;
					}
					break;
				case 1:
					for (u16 i = 0; i < 4; i++) {
						vertices[i].Pos.rotateXZBy(91);
						vertices[i].Pos.X += BS / 4;
					}
					break;
				case 2:
					for (u16 i = 0; i < 4; i++) {
						vertices[i].Pos.rotateXZBy(181);
						vertices[i].Pos.Z -= BS / 4;
					}
					break;
				case 3:
					for (u16 i = 0; i < 4; i++) {
						vertices[i].Pos.rotateXZBy(271);
						vertices[i].Pos.X -= BS / 4;
					}
					break;
				}
				break;
			case 4:
				// outward leaning #-like
				switch (j) {
				case 0:
					for (u16 i = 2; i < 4; i++)
						vertices[i].Pos.Z -= BS / 2;
					for (u16 i = 0; i < 4; i++)
						vertices[i].Pos.rotateXZBy(1);
					break;
				case 1:
					for (u16 i = 2; i < 4; i++)
						vertices[i].Pos.Z -= BS / 2;
					for (u16 i = 0; i < 4; i++)
						vertices[i].Pos.rotateXZBy(91);
					break;
				case 2:
					for (u16 i = 2; i < 4; i++)
						vertices[i].Pos.Z -= BS / 2;
					for (u16 i = 0; i < 4; i++)
						vertices[i].Pos.rotateXZBy(181);
					break;
				case 3:
					for (u16 i = 2; i < 4; i++)
						vertices[i].Pos.Z -= BS / 2;
					for (u16 i = 0; i < 4; i++)
						vertices[i].Pos.rotateXZBy(271);
					break;
				}
				break;
			}
		}

		for (int i = 0; i < 4; i++) {
			if (data->m_smooth_lighting)
				vertices[i].Color = blendLight(frame, vertices[i].Pos, tile.color);
			vertices[i].Pos += origin;
			// move to a random spot to avoid moire
			if ((f->param_type_2 == CPT2_MESHOPTIONS) && ((n.param2 & 0x8) != 0)) {
				vertices[i].Pos.X += random_offset_X;
				vertices[i].Pos.Z += random_offset_Z;
			}
			// randomly move each face up/down
			if ((f->param_type_2 == CPT2_MESHOPTIONS) && ((n.param2 & 0x20) != 0)) {
				PseudoRandom yrng(j | p.X<<16 | p.Z<<8 | p.Y<<24 );
				vertices[i].Pos.Y -= BS * ((yrng.next() % 16 / 16.0) * 0.125);
			}
		}

		u16 indices[] = {0, 1, 2, 2, 3, 0};
		// Add to mesh collector
		collector->append(tile, vertices, 4, indices, 6);

		// stop adding faces for meshes with less than 4 faces
		if (f->param_type_2 == CPT2_MESHOPTIONS) {
			if (((p2mesh == 0) || (p2mesh == 1)) && (j == 1))
				break;
			else if ((p2mesh == 2) && (j == 2))
				break;
		} else if (j == 1) {
			break;
		}

	}
}

void MapblockMeshGenerator::drawFirelikeNode()
{
	TileSpec tile = getNodeTileN(n, p, 0, data);
	tile.material_flags |= MATERIAL_FLAG_CRACK_OVERLAY;

	u16 l = getInteriorLight(n, 1, nodedef);
	video::SColor c = encode_light_and_color(l, tile.color,
		f->light_source);

	float s = BS / 2 * f->visual_scale;

	content_t current = n.getContent();
	content_t n2c;
	MapNode n2;
	v3s16 n2p;

	static const v3s16 dirs[6] = {
		v3s16( 0,  1,  0),
		v3s16( 0, -1,  0),
		v3s16( 1,  0,  0),
		v3s16(-1,  0,  0),
		v3s16( 0,  0,  1),
		v3s16( 0,  0, -1)
	};

	int doDraw[6] = {0, 0, 0, 0, 0, 0};

	bool drawAllFaces = true;

	// Check for adjacent nodes
	for (int i = 0; i < 6; i++) {
		n2p = blockpos_nodes + p + dirs[i];
		n2 = data->m_vmanip.getNodeNoEx(n2p);
		n2c = n2.getContent();
		if (n2c != CONTENT_IGNORE && n2c != CONTENT_AIR && n2c != current) {
			doDraw[i] = 1;
			if (drawAllFaces)
				drawAllFaces = false;

		}
	}

	for (int j = 0; j < 6; j++) {

		video::S3DVertex vertices[4] = {
			video::S3DVertex(-s, -BS / 2,         0, 0, 0, 0, c, 0, 1),
			video::S3DVertex( s, -BS / 2,         0, 0, 0, 0, c, 1, 1),
			video::S3DVertex( s, -BS / 2 + s * 2, 0, 0, 0, 0, c, 1, 0),
			video::S3DVertex(-s, -BS / 2 + s * 2, 0, 0, 0, 0, c, 0, 0),
		};

		// Calculate which faces should be drawn, (top or sides)
		if (j == 0 && (drawAllFaces ||
				(doDraw[3] == 1 || doDraw[1] == 1))) {
			for (int i = 0; i < 4; i++) {
				vertices[i].Pos.rotateXZBy(90);
				vertices[i].Pos.rotateXYBy(-10);
				vertices[i].Pos.X -= 4.0;
			}
		} else if (j == 1 && (drawAllFaces ||
				(doDraw[5] == 1 || doDraw[1] == 1))) {
			for (int i = 0; i < 4; i++) {
				vertices[i].Pos.rotateXZBy(180);
				vertices[i].Pos.rotateYZBy(10);
				vertices[i].Pos.Z -= 4.0;
			}
		} else if (j == 2 && (drawAllFaces ||
				(doDraw[2] == 1 || doDraw[1] == 1))) {
			for (int i = 0; i < 4; i++) {
				vertices[i].Pos.rotateXZBy(270);
				vertices[i].Pos.rotateXYBy(10);
				vertices[i].Pos.X += 4.0;
			}
		} else if (j == 3 && (drawAllFaces ||
				(doDraw[4] == 1 || doDraw[1] == 1))) {
			for (int i = 0; i < 4; i++) {
				vertices[i].Pos.rotateYZBy(-10);
				vertices[i].Pos.Z += 4.0;
			}
		// Center cross-flames
		} else if (j == 4 && (drawAllFaces || doDraw[1] == 1)) {
			for (int i = 0; i < 4; i++) {
				vertices[i].Pos.rotateXZBy(45);
			}
		} else if (j == 5 && (drawAllFaces || doDraw[1] == 1)) {
			for (int i = 0; i < 4; i++) {
				vertices[i].Pos.rotateXZBy(-45);
			}
		// Render flames on bottom of node above
		} else if (j == 0 && doDraw[0] == 1 && doDraw[1] == 0) {
			for (int i = 0; i < 4; i++) {
				vertices[i].Pos.rotateYZBy(70);
				vertices[i].Pos.rotateXZBy(90);
				vertices[i].Pos.Y += 4.84;
				vertices[i].Pos.X -= 4.7;
			}
		} else if (j == 1 && doDraw[0] == 1 && doDraw[1] == 0) {
			for (int i = 0; i < 4; i++) {
				vertices[i].Pos.rotateYZBy(70);
				vertices[i].Pos.rotateXZBy(180);
				vertices[i].Pos.Y += 4.84;
				vertices[i].Pos.Z -= 4.7;
			}
		} else if (j == 2 && doDraw[0] == 1 && doDraw[1] == 0) {
			for (int i = 0; i < 4; i++) {
				vertices[i].Pos.rotateYZBy(70);
				vertices[i].Pos.rotateXZBy(270);
				vertices[i].Pos.Y += 4.84;
				vertices[i].Pos.X += 4.7;
			}
		} else if (j == 3 && doDraw[0] == 1 && doDraw[1] == 0) {
			for (int i = 0; i < 4; i++) {
				vertices[i].Pos.rotateYZBy(70);
				vertices[i].Pos.Y += 4.84;
				vertices[i].Pos.Z += 4.7;
			}
		} else {
			// Skip faces that aren't adjacent to a node
			continue;
		}

		for (int i = 0; i < 4; i++) {
			vertices[i].Pos *= f->visual_scale;
			if (data->m_smooth_lighting)
				vertices[i].Color = blendLight(frame, vertices[i].Pos, tile.color);
			vertices[i].Pos += origin;
		}

		u16 indices[] = {0, 1, 2, 2, 3, 0};
		// Add to mesh collector
		collector->append(tile, vertices, 4, indices, 6);
	}
}

void MapblockMeshGenerator::drawFencelikeNode()
{
	TileSpec tile = getNodeTile(n, p, v3s16(0,0,0), data);
	TileSpec tile_nocrack = tile;
	tile_nocrack.material_flags &= ~MATERIAL_FLAG_CRACK;

	// Put wood the right way around in the posts
	TileSpec tile_rot = tile;
	tile_rot.rotation = 1;

	u16 l = getInteriorLight(n, 1, nodedef);
	video::SColor c = encode_light_and_color(l, tile.color,
		f->light_source);

	const f32 post_rad=(f32)BS/8;
	const f32 bar_rad=(f32)BS/16;
	const f32 bar_len=(f32)(BS/2)-post_rad;

	// The post - always present
	aabb3f post(-post_rad,-BS/2,-post_rad,post_rad,BS/2,post_rad);
	f32 postuv[24]={
			6/16.,6/16.,10/16.,10/16.,
			6/16.,6/16.,10/16.,10/16.,
			0/16.,0,4/16.,1,
			4/16.,0,8/16.,1,
			8/16.,0,12/16.,1,
			12/16.,0,16/16.,1};
	makeAutoLightedCuboidEx(collector, data, origin, post, tile_rot, postuv, c, frame);

	// Now a section of fence, +X, if there's a post there
	v3s16 p2 = p;
	p2.X++;
	MapNode n2 = data->m_vmanip.getNodeNoEx(blockpos_nodes + p2);
	const ContentFeatures *f2 = &nodedef->get(n2);
	if(f2->drawtype == NDT_FENCELIKE)
	{
		aabb3f bar(-bar_len+BS/2,-bar_rad+BS/4,-bar_rad,
				bar_len+BS/2,bar_rad+BS/4,bar_rad);
		f32 xrailuv[24]={
			0/16.,2/16.,16/16.,4/16.,
			0/16.,4/16.,16/16.,6/16.,
			6/16.,6/16.,8/16.,8/16.,
			10/16.,10/16.,12/16.,12/16.,
			0/16.,8/16.,16/16.,10/16.,
			0/16.,14/16.,16/16.,16/16.};
		makeAutoLightedCuboidEx(collector, data, origin, bar, tile_nocrack, xrailuv, c, frame);
		bar.MinEdge.Y -= BS/2;
		bar.MaxEdge.Y -= BS/2;
		makeAutoLightedCuboidEx(collector, data, origin, bar, tile_nocrack, xrailuv, c, frame);
	}

	// Now a section of fence, +Z, if there's a post there
	p2 = p;
	p2.Z++;
	n2 = data->m_vmanip.getNodeNoEx(blockpos_nodes + p2);
	f2 = &nodedef->get(n2);
	if(f2->drawtype == NDT_FENCELIKE)
	{
		aabb3f bar(-bar_rad,-bar_rad+BS/4,-bar_len+BS/2,
				bar_rad,bar_rad+BS/4,bar_len+BS/2);
		f32 zrailuv[24]={
			3/16.,1/16.,5/16.,5/16., // cannot rotate; stretch
			4/16.,1/16.,6/16.,5/16., // for wood texture instead
			0/16.,9/16.,16/16.,11/16.,
			0/16.,6/16.,16/16.,8/16.,
			6/16.,6/16.,8/16.,8/16.,
			10/16.,10/16.,12/16.,12/16.};
		makeAutoLightedCuboidEx(collector, data, origin, bar, tile_nocrack, zrailuv, c, frame);
		bar.MinEdge.Y -= BS/2;
		bar.MaxEdge.Y -= BS/2;
		makeAutoLightedCuboidEx(collector, data, origin, bar, tile_nocrack, zrailuv, c, frame);
	}
}

void MapblockMeshGenerator::drawRaillikeNode()
{
	bool is_rail_x[6]; /* (-1,-1,0) X (1,-1,0) (-1,0,0) X (1,0,0) (-1,1,0) X (1,1,0) */
	bool is_rail_z[6];

	content_t thiscontent = n.getContent();
	std::string groupname = "connect_to_raillike"; // name of the group that enables connecting to raillike nodes of different kind
	int self_group = ((ItemGroupList) nodedef->get(n).groups)[groupname];

	u8 index = 0;
	for (s8 y0 = -1; y0 <= 1; y0++) {
		// Prevent from indexing never used coordinates
		for (s8 xz = -1; xz <= 1; xz++) {
			if (xz == 0)
				continue;
			MapNode n_xy = data->m_vmanip.getNodeNoEx(blockpos_nodes + v3s16(p.X + xz, p.Y + y0, p.Z));
			MapNode n_zy = data->m_vmanip.getNodeNoEx(blockpos_nodes + v3s16(p.X, p.Y + y0, p.Z + xz));
			const ContentFeatures &def_xy = nodedef->get(n_xy);
			const ContentFeatures &def_zy = nodedef->get(n_zy);

			// Check if current node would connect with the rail
			is_rail_x[index] = ((def_xy.drawtype == NDT_RAILLIKE
					&& ((ItemGroupList) def_xy.groups)[groupname] == self_group)
					|| n_xy.getContent() == thiscontent);

			is_rail_z[index] = ((def_zy.drawtype == NDT_RAILLIKE
					&& ((ItemGroupList) def_zy.groups)[groupname] == self_group)
					|| n_zy.getContent() == thiscontent);
			index++;
		}
	}

	bool is_rail_x_all[2]; // [0] = negative p.X, [1] = positive p.X coordinate from the current node position
	bool is_rail_z_all[2];
	is_rail_x_all[0] = is_rail_x[0] || is_rail_x[2] || is_rail_x[4];
	is_rail_x_all[1] = is_rail_x[1] || is_rail_x[3] || is_rail_x[5];
	is_rail_z_all[0] = is_rail_z[0] || is_rail_z[2] || is_rail_z[4];
	is_rail_z_all[1] = is_rail_z[1] || is_rail_z[3] || is_rail_z[5];

	// reasonable default, flat straight unrotated rail
	bool is_straight = true;
	int adjacencies = 0;
	int angle = 0;
	u8 tileindex = 0;

	// check for sloped rail
	if (is_rail_x[4] || is_rail_x[5] || is_rail_z[4] || is_rail_z[5]) {
		adjacencies = 5; // 5 means sloped
		is_straight = true; // sloped is always straight
	} else {
		// is really straight, rails on both sides
		is_straight = (is_rail_x_all[0] && is_rail_x_all[1]) || (is_rail_z_all[0] && is_rail_z_all[1]);
		adjacencies = is_rail_x_all[0] + is_rail_x_all[1] + is_rail_z_all[0] + is_rail_z_all[1];
	}

	switch (adjacencies) {
	case 1:
		if (is_rail_x_all[0] || is_rail_x_all[1])
			angle = 90;
		break;
	case 2:
		if (!is_straight)
			tileindex = 1; // curved
		if (is_rail_x_all[0] && is_rail_x_all[1])
			angle = 90;
		if (is_rail_z_all[0] && is_rail_z_all[1]) {
			if (is_rail_z[4])
				angle = 180;
		}
		else if (is_rail_x_all[0] && is_rail_z_all[0])
			angle = 270;
		else if (is_rail_x_all[0] && is_rail_z_all[1])
			angle = 180;
		else if (is_rail_x_all[1] && is_rail_z_all[1])
			angle = 90;
		break;
	case 3:
		// here is where the potential to 'switch' a junction is, but not implemented at present
		tileindex = 2; // t-junction
		if(!is_rail_x_all[1])
			angle = 180;
		if(!is_rail_z_all[0])
			angle = 90;
		if(!is_rail_z_all[1])
			angle = 270;
		break;
	case 4:
		tileindex = 3; // crossing
		break;
	case 5: //sloped
		if (is_rail_z[4])
			angle = 180;
		if (is_rail_x[4])
			angle = 90;
		if (is_rail_x[5])
			angle = -90;
		break;
	default:
		break;
	}

	TileSpec tile = getNodeTileN(n, p, tileindex, data);
	tile.material_flags &= ~MATERIAL_FLAG_BACKFACE_CULLING;
	tile.material_flags |= MATERIAL_FLAG_CRACK_OVERLAY;

	u16 l = getInteriorLight(n, 0, nodedef);
	video::SColor c = encode_light_and_color(l, tile.color,
		f->light_source);

	float d = (float)BS/64;
	float s = BS/2;

	short g = -1;
	if (is_rail_x[4] || is_rail_x[5] || is_rail_z[4] || is_rail_z[5])
		g = 1; //Object is at a slope

	video::S3DVertex vertices[4] =
	{
			video::S3DVertex(-s,  -s+d, -s, 0, 0, 0, c, 0, 1),
			video::S3DVertex( s,  -s+d, -s, 0, 0, 0, c, 1, 1),
			video::S3DVertex( s, g*s+d,  s, 0, 0, 0, c, 1, 0),
			video::S3DVertex(-s, g*s+d,  s, 0, 0, 0, c, 0, 0),
	};

	for(s32 i=0; i<4; i++)
	{
		if(angle != 0)
			vertices[i].Pos.rotateXZBy(angle);
		if (data->m_smooth_lighting)
			vertices[i].Color = blendLight(frame, vertices[i].Pos, tile.color);
		vertices[i].Pos += origin;
	}

	u16 indices[] = {0,1,2,2,3,0};
	collector->append(tile, vertices, 4, indices, 6);
}

void MapblockMeshGenerator::drawNodeboxNode()
{
	static const v3s16 tile_dirs[6] = {
		v3s16(0, 1, 0),
		v3s16(0, -1, 0),
		v3s16(1, 0, 0),
		v3s16(-1, 0, 0),
		v3s16(0, 0, 1),
		v3s16(0, 0, -1)
	};

	TileSpec tiles[6];
	video::SColor colors[6];
	for (int j = 0; j < 6; j++) {
		// Handles facedir rotation for textures
		tiles[j] = getNodeTile(n, p, tile_dirs[j], data);
	}
	if (!data->m_smooth_lighting) {
		u16 l = getInteriorLight(n, 1, nodedef);
		for (int j = 0; j < 6; j++)
			colors[j] = encode_light_and_color(l, tiles[j].color, f->light_source);
	}

	int neighbors = 0;

	// locate possible neighboring nodes to connect to
	if (f->node_box.type == NODEBOX_CONNECTED) {
		v3s16 p2 = p;

		p2.Y++;
		getNeighborConnectingFace(blockpos_nodes + p2, nodedef, data, n, 1, &neighbors);

		p2 = p;
		p2.Y--;
		getNeighborConnectingFace(blockpos_nodes + p2, nodedef, data, n, 2, &neighbors);

		p2 = p;
		p2.Z--;
		getNeighborConnectingFace(blockpos_nodes + p2, nodedef, data, n, 4, &neighbors);

		p2 = p;
		p2.X--;
		getNeighborConnectingFace(blockpos_nodes + p2, nodedef, data, n, 8, &neighbors);

		p2 = p;
		p2.Z++;
		getNeighborConnectingFace(blockpos_nodes + p2, nodedef, data, n, 16, &neighbors);

		p2 = p;
		p2.X++;
		getNeighborConnectingFace(blockpos_nodes + p2, nodedef, data, n, 32, &neighbors);
	}

	std::vector<aabb3f> boxes;
	n.getNodeBoxes(nodedef, &boxes, neighbors);
	for (std::vector<aabb3f>::iterator
			i = boxes.begin();
			i != boxes.end(); ++i) {
		aabb3f box = *i;

		f32 dx1 = box.MinEdge.X;
		f32 dy1 = box.MinEdge.Y;
		f32 dz1 = box.MinEdge.Z;
		f32 dx2 = box.MaxEdge.X;
		f32 dy2 = box.MaxEdge.Y;
		f32 dz2 = box.MaxEdge.Z;

		box.MinEdge += origin;
		box.MaxEdge += origin;

		if (box.MinEdge.X > box.MaxEdge.X)
			std::swap(box.MinEdge.X, box.MaxEdge.X);
		if (box.MinEdge.Y > box.MaxEdge.Y)
			std::swap(box.MinEdge.Y, box.MaxEdge.Y);
		if (box.MinEdge.Z > box.MaxEdge.Z)
			std::swap(box.MinEdge.Z, box.MaxEdge.Z);

		//
		// Compute texture coords
		f32 tx1 = (box.MinEdge.X/BS)+0.5;
		f32 ty1 = (box.MinEdge.Y/BS)+0.5;
		f32 tz1 = (box.MinEdge.Z/BS)+0.5;
		f32 tx2 = (box.MaxEdge.X/BS)+0.5;
		f32 ty2 = (box.MaxEdge.Y/BS)+0.5;
		f32 tz2 = (box.MaxEdge.Z/BS)+0.5;
		f32 txc[24] = {
			// up
			tx1, 1-tz2, tx2, 1-tz1,
			// down
			tx1, tz1, tx2, tz2,
			// right
			tz1, 1-ty2, tz2, 1-ty1,
			// left
			1-tz2, 1-ty2, 1-tz1, 1-ty1,
			// back
			1-tx2, 1-ty2, 1-tx1, 1-ty1,
			// front
			tx1, 1-ty2, tx2, 1-ty1,
		};
		if (data->m_smooth_lighting) {
			u16 lights[8];
			for (int j = 0; j < 8; ++j) {
				f32 x = (j & 4) ? dx2 : dx1;
				f32 y = (j & 2) ? dy2 : dy1;
				f32 z = (j & 1) ? dz2 : dz1;
				lights[j] = blendLight(frame, core::vector3df(x, y, z));
			}
			makeSmoothLightedCuboid(collector, box, tiles, 6, lights, txc, f->light_source);
		} else {
			makeCuboid(collector, box, tiles, 6, colors, txc, f->light_source);
		}
	}
}

void MapblockMeshGenerator::drawMeshNode()
{
	u16 l = getInteriorLight(n, 1, nodedef);
	u8 facedir = 0;
	if (f->param_type_2 == CPT2_FACEDIR ||
			f->param_type_2 == CPT2_COLORED_FACEDIR) {
		facedir = n.getFaceDir(nodedef);
	} else if (f->param_type_2 == CPT2_WALLMOUNTED ||
			f->param_type_2 == CPT2_COLORED_WALLMOUNTED) {
		//convert wallmounted to 6dfacedir.
		//when cache enabled, it is already converted
		facedir = n.getWallMounted(nodedef);
		if (!enable_mesh_cache) {
			static const u8 wm_to_6d[6] = {20, 0, 16+1, 12+3, 8, 4+2};
			facedir = wm_to_6d[facedir];
		}
	}

	if (!data->m_smooth_lighting && f->mesh_ptr[facedir]) {
		// use cached meshes
		for (u16 j = 0; j < f->mesh_ptr[0]->getMeshBufferCount(); j++) {
			const TileSpec &tile = getNodeTileN(n, p, j, data);
			scene::IMeshBuffer *buf = f->mesh_ptr[facedir]->getMeshBuffer(j);
			collector->append(tile, (video::S3DVertex *)
				buf->getVertices(), buf->getVertexCount(),
				buf->getIndices(), buf->getIndexCount(), origin,
				encode_light_and_color(l, tile.color, f->light_source),
				f->light_source);
		}
	} else if (f->mesh_ptr[0]) {
		// no cache, clone and rotate mesh
		scene::IMesh* mesh = cloneMesh(f->mesh_ptr[0]);
		rotateMeshBy6dFacedir(mesh, facedir);
		recalculateBoundingBox(mesh);
		meshmanip->recalculateNormals(mesh, true, false);
		for (u16 j = 0; j < mesh->getMeshBufferCount(); j++) {
			const TileSpec &tile = getNodeTileN(n, p, j, data);
			scene::IMeshBuffer *buf = mesh->getMeshBuffer(j);
			video::S3DVertex *vertices = (video::S3DVertex *)buf->getVertices();
			u32 vertex_count = buf->getVertexCount();
			if (data->m_smooth_lighting) {
				for (u16 m = 0; m < vertex_count; ++m) {
					video::S3DVertex &vertex = vertices[m];
					vertex.Color = blendLight(frame, vertex.Pos, vertex.Normal, tile.color);
					vertex.Pos += origin;
				}
				collector->append(tile, vertices, vertex_count,
					buf->getIndices(), buf->getIndexCount());
			} else {
				collector->append(tile, vertices, vertex_count,
					buf->getIndices(), buf->getIndexCount(), origin,
					encode_light_and_color(l, tile.color, f->light_source),
					f->light_source);
			}
		}
		mesh->drop();
	}
}

void MapblockMeshGenerator::drawNode()
{
	if (data->m_smooth_lighting) {
		getSmoothLightFrame(&frame, blockpos_nodes + p, data, f->light_source);
	} else {
		frame.light_source = f->light_source;
		light = getInteriorLight(n, 1, nodedef);
	}
}

/*
	TODO: Fix alpha blending for special nodes
	Currently only the last element rendered is blended correct
*/
void MapblockMeshGenerator::generate()
{
    for (p.Z = 0; p.Z < MAP_BLOCKSIZE; p.Z++)
    for (p.Y = 0; p.Y < MAP_BLOCKSIZE; p.Y++)
    for (p.X = 0; p.X < MAP_BLOCKSIZE; p.X++)
	{
		n = data->m_vmanip.getNodeNoEx(blockpos_nodes + p);
		f = &nodedef->get(n);

		// Only solidness=0 stuff is drawn here
		if (f->solidness != 0)
			continue;

		if (f->drawtype == NDT_AIRLIKE)
			continue;

		origin = intToFloat(p, BS);

		drawNode();

		switch(f->drawtype) {
		default: // pre-converted drawtypes go here too, if appear
			infostream << "Got drawtype " << f->drawtype << std::endl;
			FATAL_ERROR("Unknown drawtype");
			break;
		case NDT_LIQUID:
			drawLiquidNode();
			break;
		case NDT_FLOWINGLIQUID:
			drawFlowingLiquidNode();
			break;
		case NDT_GLASSLIKE:
			drawGlasslikeNode();
			break;
		case NDT_GLASSLIKE_FRAMED:
			drawGlasslikeFramedNode();
			break;
		case NDT_ALLFACES:
			drawAllfacesNode();
			break;
		case NDT_TORCHLIKE:
			drawTorchlikeNode();
			break;
		case NDT_SIGNLIKE:
			drawSignlikeNode();
			break;
		case NDT_PLANTLIKE:
			drawPlantlikeNode();
			break;
		case NDT_FIRELIKE:
			drawFirelikeNode();
			break;
		case NDT_FENCELIKE:
			drawFencelikeNode();
			break;
		case NDT_RAILLIKE:
			drawRaillikeNode();
			break;
		case NDT_NODEBOX:
			drawNodeboxNode();
			break;
		case NDT_MESH:
			drawMeshNode();
			break;
		}
	}
}

void mapblock_mesh_generate_special(MeshMakeData *data,
		MeshCollector &collector)
{
	MapblockMeshGenerator generator(data, &collector);
	generator.generate();
}
