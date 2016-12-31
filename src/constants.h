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

#ifndef CONSTANTS_HEADER
#define CONSTANTS_HEADER

/*
	All kinds of constants.

	Cross-platform compatibility crap should go in porting.h.

    Some things here are legacy crap.
*/

/*
    Connection
*/

#define PEER_ID_INEXISTENT 0
#define PEER_ID_SERVER 1

// Define for simulating the quirks of sending through internet.
// Causes the socket class to deliberately drop random packets.
// This disables unit testing of socket and connection.
#define INTERNET_SIMULATOR 0
#define INTERNET_SIMULATOR_PACKET_LOSS 10 // 10 = easy, 4 = hard

// Max packet size that can be received.
#define MAX_RECV_PACKET_SIZE 65536
// Max packet-size to use for transmission
// Theoretical maximum for UDP is 65507, but that may be too large
// for the network stack.
// The smallest value that must always be supported by the network
// (IPv4) is 548 (576 - 28 for the UDP/IP headers)
#define MAX_SEND_PACKET_SIZE_IPV4 512
// Theoretical maximum for UDP/IPv6: 65487, but the presence of
// additional options in the header would lower that limit.
// The smallest value that must always be supported for IPv6 is 1500
// including headers. Such packets may end up being fragmented.
// The minimum packet size that can always be transmitted without
// fragmentation is 1280, including headers of at least 48 bytes.
#define MAX_SEND_PACKET_SIZE_IPV6 1200
// For local packets, use the same maximum for IPv4 and IPv6.
// Not too close to the theoretical maximum.
#define MAX_SEND_PACKET_SIZE_LOCAL 65000
#define MAX_SEND_PACKET_SIZE_INITIAL MAX_SEND_PACKET_SIZE_IPV4

#define CONNECTION_TIMEOUT 30

#define RESEND_TIMEOUT_MIN 0.1
#define RESEND_TIMEOUT_MAX 3.0
// resend_timeout = avg_rtt * this
#define RESEND_TIMEOUT_FACTOR 4

/*
    Server
*/

// This many blocks are sent when player is building
#define LIMITED_MAX_SIMULTANEOUS_BLOCK_SENDS 0
// Override for the previous one when distance of block is very low
#define BLOCK_SEND_DISABLE_LIMITS_MAX_D 1

/*
    Map-related things
*/

// The absolute working limit is (2^15 - viewing_range).
// I really don't want to make every algorithm to check if it's going near
// the limit or not, so this is lower.
// This is the maximum value the setting map_generation_limit can be
#define MAX_MAP_GENERATION_LIMIT (31000)

// Size of node in floating-point units
// The original idea behind this is to disallow plain casts between
// floating-point and integer positions, which potentially give wrong
// results. (negative coordinates, values between nodes, ...)
// Use floatToInt(p, BS) and intToFloat(p, BS).
#define BS (10.0)

// Dimension of a MapBlock
#define MAP_BLOCKSIZE 16
// This makes mesh updates too slow, as many meshes are updated during
// the main loop (related to TempMods and day/night)
//#define MAP_BLOCKSIZE 32

/*
    Old stuff that shouldn't be hardcoded
*/

// Size of player's main inventory
#define PLAYER_INVENTORY_SIZE (8*4)

// Maximum hit points of a player
#define PLAYER_MAX_HP 20

// Maximal breath of a player
#define PLAYER_MAX_BREATH 11

// Number of different files to try to save a player to if the first fails
// (because of a case-insensitive filesystem)
// TODO: Use case-insensitive player names instead of this hack.
#define PLAYER_FILE_ALTERNATE_TRIES 1000

// For screenshots a serial number is appended to the filename + datetimestamp
// if filename + datetimestamp is not unique.
// This is the maximum number of attempts to try and add a serial to the end of
// the file attempting to ensure a unique filename
#define SCREENSHOT_MAX_SERIAL_TRIES 1000

/*
    GUI related things
*/

// TODO: implement dpi-based scaling for windows and remove this hack
#if defined(_WIN32)
	#define TTF_DEFAULT_FONT_SIZE   (18)
#else
	#define TTF_DEFAULT_FONT_SIZE	(16)
#endif
#define DEFAULT_FONT_SIZE       (10)

#endif
