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
#include <peer.h>
#include <hash.h>

struct map;

/* Maximum length of an object name in memory */
// 7 is the deprecated MAPPER_PREFIX_LEN, held here for backwards compatibility
#define v1_max_objectlen (7 + HEXLIFIED_SHA256_DIGEST_SIZE)

/* Required size in storage to store object information.
 *
 * transparency byte + max object len in disk
 */
struct v1_object_on_disk {
	unsigned char flags;
	unsigned char name[SHA256_DIGEST_SIZE];
};
#define v1_objectsize_in_map (sizeof(struct v1_object_on_disk))

struct v1_header_struct {
	uint32_t version;
	uint64_t size;
} __attribute__((packed));

#define v1_mapheader_size (sizeof(struct v1_header_struct))

extern struct map_ops v1_ops;

int read_map_header_v1(struct map *map, struct v1_header_struct *v1_hdr);
void write_map_header_v1(struct map *map, struct v1_header_struct *v1_hdr);

#endif /* end MAPPERVERSION1_H */
