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

#ifndef MAPPERVERSION0_H

#define MAPPERVERSION0_H

#include <unistd.h>
#include <hash.h>
#include <peer.h>

struct map;

/* Maximum length of an object name in memory */
#define v0_max_objectlen (HEXLIFIED_SHA256_DIGEST_SIZE)

/* Required size in storage to store object information.
 *
 * max object len in disk. just the unhexlified name.
 */
struct v0_object_on_disk {
	unsigned char name[SHA256_DIGEST_SIZE];
};

#define v0_objectsize_in_map (sizeof(struct v0_object_on_disk))

struct v0_header_struct {
	/* Empty */
} __attribute__((packed));
#define v0_mapheader_size (sizeof(struct v0_header_struct))

extern struct map_ops v0_ops;

int read_map_header_v0(struct map *map, struct v0_header_struct *v0_hdr);
void write_map_header_v0(struct map *map, struct v0_header_struct *v0_hdr);


#endif /* end MAPPERVERSION0_H */
