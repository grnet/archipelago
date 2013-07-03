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

#ifndef MAPPERVERSION1_H

#define MAPPERVERSION1_H

#include <xseg/xseg.h>
#include <hash.h>
#include <peer.h>
#include <mapper.h>

/* v1 functions */

/* Maximum length of an object name in memory */
#define v1_max_objectlen (MAPPER_PREFIX_LEN + HEXLIFIED_SHA256_DIGEST_SIZE)

/* Required size in storage to store object information.
 *
 * transparency byte + max object len in disk
 */
#define v1_objectsize_in_map (1 + SHA256_DIGEST_SIZE)

/* Map header contains:
 * 	map version
 * 	volume size
 */
#define v1_mapheader_size (sizeof (uint32_t) + sizeof(uint64_t))

int read_object_v1(struct map_node *mn, unsigned char *buf);
//void v1_object_to_map(unsigned char* buf, struct map_node *mn);
struct xseg_request * prepare_write_object_v1(struct peer_req *pr,
				struct map *map, struct map_node *mn);
//int read_map_v1(struct map *m, unsigned char * data);
int read_map_metadata_v1(struct map *map, unsigned char *metadata,
		uint32_t metadata_len);
int load_map_data_v1(struct peer_req *pr, struct map *map);
int write_map_metadata_v1(struct peer_req *pr, struct map *map);
int write_map_data_v1(struct peer_req *pr, struct map *map);

/*.read_map = read_map_v1,	\*/
#define map_functions_v1 {				\
			.read_object = read_object_v1,	\
			.prepare_write_object = prepare_write_object_v1,\
			.load_map_data = load_map_data_v1, \
			.write_map_metadata = write_map_metadata_v1, \
			.write_map_data = write_map_data_v1, \
			.read_map_metadata = read_map_metadata_v1 \
			}
#endif /* end MAPPERVERSION1_H */
