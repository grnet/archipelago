/*
Copyright (C) 2010-2014 GRNET S.A.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef MAPPERVERSION2_H

#define MAPPERVERSION2_H

#include <unistd.h>
#include <hash.h>
#include <peer.h>

struct map;

/* Maximum length of an object name in memory */
#define v2_max_objectlen 128

/* Required size in storage to store object information.
 *
 * byte for flags + map_node->objectlen + max object len in disk
 */
struct v2_object_on_disk {
	unsigned char flags;
	uint32_t objectlen;
	unsigned char object[v2_max_objectlen];
}__attribute__((packed));

#define v2_objectsize_in_map (sizeof(struct v2_object_on_disk))

//#define v2_read_chunk_size (512*1024)
#define v2_nr_objs_per_chunk ((512*1024)/v2_objectsize_in_map)
#define v2_read_chunk_size (v2_nr_objs_per_chunk * v2_objectsize_in_map)

/* Map header contains:
 * 	map signature - uint32_t
 * 	map version   - uint32_t
 * 	volume size   - uint64_t
 * 	block size    - uint32_t
 * 	map flags     - uint32_t
 * 	map epoch     - uint64_t
 */
struct v2_header_struct {
	uint32_t signature;
	uint32_t version;
	uint64_t size;
	uint32_t blocksize;
	uint32_t flags;
	uint64_t epoch;
} __attribute__((packed));

#define v2_mapheader_size (sizeof(struct v2_header_struct))

extern struct map_ops v2_ops;

int read_map_header_v2(struct map *map, struct v2_header_struct *v2_hdr);
void write_map_header_v2(struct map *map, struct v2_header_struct *v2_hdr);

#endif /* end MAPPERVERSION2_H */
