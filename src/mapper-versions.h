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

#ifndef MAPPERVERSIONS_H

#define MAPPERVERSIONS_H

#include <mapper.h>
#include <xseg/protocol.h>
#include <mapper-version0.h>
#include <mapper-version1.h>
#include <mapper-version2.h>

#define MAP_LATEST_VERSION 2
/* These come straight from the struct map fields that need to be kept in
 * permament storage.
 *
 * version
 * signature
 * size
 * blocksize
 * epoch
 * flags
 */
#define MAX_MAPHEADER_SIZE (sizeof(uint32_t) \
			  + sizeof(uint64_t) \
			  + sizeof(uint64_t) \
			  + sizeof(uint32_t) \
			  + sizeof(uint64_t) \
			  + sizeof(uint32_t) \
			   )

/* should always be the maximum objectlen of all versions */
//#define MAX_OBJECT_LEN v2_max_objectlen

/* since object names are cacluclated from the volume names, the limit of the
 * maximum volume len is calculated from the maximum object len, statically for
 * all map versions.
 *
 * How the object name is calculated is reflected in this formula:
 *
 * volume-index-epoch
 */
//#define MAX_VOLUME_LEN (MAX_OBJECT_LEN - HEXLIFIED_INDEX - HEXLIFIED_EPOCH - 2)

/* Some compile time checks */
#if MAX_OBJECT_LEN < v2_max_objectlen
#error "MAX_OBJECT_LEN is smaller than v2_max_objectlen"
#endif

#if MAX_OBJECT_LEN < v1_max_objectlen
#error "MAX_OBJECT_LEN is smaller than v1_max_objectlen"
#endif

#if MAX_OBJECT_LEN < v0_max_objectlen
#error "MAX_OBJECT_LEN is smaller than v0_max_objectlen"
#endif


/*
 * map read/write functions
 *
 * version 0 -> pithos map
 * version 1 -> archipelago version 1
 * version 2 -> archipelago version 2
 *
 */

struct map_functions {
	void (*object_to_map)(unsigned char *buf, struct map_node *mn);
	int (*read_object)(struct map_node *mn, unsigned char *buf);
	struct xseg_request * (*prepare_write_object)(struct peer_req *pr,
			struct map *map, struct map_node *mn);
//	int (*read_map)(struct map *map, unsigned char * data);
//	int (*write_map)(struct peer_req *pr, struct map *map);
	int (*read_map_metadata)(struct map *map, unsigned char *metadata,
			uint64_t metadata_len);
	int (*load_map_data)(struct peer_req *pr, struct map *map);
	int (*write_map_metadata)(struct peer_req *pr, struct map *map);
	int (*write_map_data)(struct peer_req *pr, struct map *map);
};

extern struct map_functions map_functions[];

#endif /* end MAPPERVERSIONS_H */
