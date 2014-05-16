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

#ifndef MAPPERVERSION0_H

#define MAPPERVERSION0_H

#include <unistd.h>
#include <hash.h>
#include <peer.h>
#include <mapper.h>

/* version 0 functions */

/* no header */
#define v0_mapheader_size 0

/* Maximum length of an object name in memory */
#define v0_max_objectlen (HEXLIFIED_SHA256_DIGEST_SIZE)

/* Required size in storage to store object information.
 *
 * max object len in disk. just the unhexlified name.
 */
#define v0_objectsize_in_map (SHA256_DIGEST_SIZE)

int read_object_v0(struct map_node *mn, unsigned char *buf);
void object_to_map_v0(unsigned char* buf, struct map_node *mn);
struct xseg_request * prepare_write_object_v0(struct peer_req *pr,
				struct map *map, struct map_node *mn);
//int read_map_v0(struct map *m, unsigned char * data);
int read_map_metadata_v0(struct map *map, unsigned char *metadata,
		uint64_t metadata_len);
int load_map_data_v0(struct peer_req *pr, struct map *map);
int write_map_metadata_v0(struct peer_req *pr, struct map *map);
int write_map_data_v0(struct peer_req *pr, struct map *map);

/*.read_map = read_map_v0,	\*/
#define map_functions_v0 {				\
			.object_to_map = object_to_map_v0, \
			.read_object = read_object_v0,	\
			.prepare_write_object = prepare_write_object_v0,\
			.load_map_data = load_map_data_v0, \
			.write_map_metadata = write_map_metadata_v0, \
			.write_map_data = write_map_data_v0, \
			.read_map_metadata = read_map_metadata_v0 \
			}


#endif /* end MAPPERVERSION0_H */
