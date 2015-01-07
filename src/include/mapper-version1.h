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
} __attribute__ ((packed));

#define v1_mapheader_size (sizeof(struct v1_header_struct))

extern struct map_ops v1_ops;

int read_map_header_v1(struct map *map, struct v1_header_struct *v1_hdr);
void write_map_header_v1(struct map *map, struct v1_header_struct *v1_hdr);

#endif                          /* end MAPPERVERSION1_H */
