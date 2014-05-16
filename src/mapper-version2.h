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
#include <mapper.h>

/* v2 functions */


/* Maximum length of an object name in memory */
#define v2_max_objectlen 128

/* Required size in storage to store object information.
 *
 * byte for flags + map_node->objectlen + max object len in disk
 */
#define v2_objectsize_in_map (1 + sizeof(uint32_t) + v2_max_objectlen)

//#define v2_read_chunk_size (512*1024)
#define v2_nr_objs_per_chunk ((512*1024)/v2_objectsize_in_map)
#define v2_read_chunk_size (v2_nr_objs_per_chunk * v2_objectsize_in_map)

/* Map header contains:
 * 	map version   - uint32_t
 * 	map signature - uint32_t
 * 	volume size   - uint64_t
 * 	block size    - uint32_t
 * 	map flags     - uint32_t
 * 	map epoch     - uint64_t
 */
#define v2_mapheader_size (sizeof(uint32_t) + \
			   sizeof(uint32_t) + \
			   sizeof(uint64_t) + \
			   sizeof(uint32_t) + \
			   sizeof(uint32_t) + \
			   sizeof(uint64_t))

int read_object_v2(struct map_node *mn, unsigned char *buf);
void object_to_map_v2(unsigned char* buf, struct map_node *mn);
struct xseg_request * prepare_write_object_v2(struct peer_req *pr,
				struct map *map, struct map_node *mn);
//int read_map_v2(struct map *m, unsigned char * data);
int read_map_metadata_v2(struct map *map, unsigned char *metadata,
		uint64_t metadata_len);
int load_map_data_v2(struct peer_req *pr, struct map *map);
//int write_map_v2(struct peer_req *pr, struct map *map);
int write_map_metadata_v2(struct peer_req *pr, struct map *map);
int write_map_data_v2(struct peer_req *pr, struct map *map);

/*.read_map = read_map_v2,	\*/
#define map_functions_v2 {				\
			.read_object = read_object_v2,	\
			.object_to_map = object_to_map_v2, \
			.prepare_write_object = prepare_write_object_v2,\
			.load_map_data = load_map_data_v2, \
			.write_map_metadata = write_map_metadata_v2, \
			.write_map_data = write_map_data_v2, \
			.read_map_metadata = read_map_metadata_v2 \
			}

#endif /* end MAPPERVERSION2_H */
