/*
 * Copyright 2013 GRNET S.A. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 *   1. Redistributions of source code must retain the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer.
 *   2. Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials
 *      provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY GRNET S.A. ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL GRNET S.A OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and
 * documentation are those of the authors and should not be
 * interpreted as representing official policies, either expressed
 * or implied, of GRNET S.A.
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
