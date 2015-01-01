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

#ifndef _FILE_H
#define _FILE_H

#define _GNU_SOURCE
#include <xseg/xcache.h>

#define FIO_STR_ID_LEN		3
#define LOCK_SUFFIX		"_lock"
#define LOCK_SUFFIX_LEN		5
#define HASH_SUFFIX		"_hash"
#define HASH_SUFFIX_LEN		5
#define MAX_PATH_SIZE		1024
#define MAX_FILENAME_SIZE 	(XSEG_MAX_TARGETLEN + LOCK_SUFFIX_LEN + MAX_UNIQUESTR_LEN + FIO_STR_ID_LEN)
#define MAX_PREFIX_LEN		10
#define MAX_UNIQUESTR_LEN	128
#define SNAP_SUFFIX		"_snap"
#define SNAP_SUFFIX_LEN		5

#define WRITE 1
#define READ 2

/* fdcache_node flags */
#define READY (1 << 1)

/* fdcache node info */
struct fdcache_entry {
    volatile int fd;
    volatile unsigned int flags;
};

/* pfiled context */
struct pfiled {
    uint32_t vpath_len;
    uint32_t prefix_len;
    uint32_t lockpath_len;
    uint32_t uniquestr_len;
    long maxfds;
    uint32_t directio;
    char vpath[MAX_PATH_SIZE + 1];
    char lockpath[MAX_PATH_SIZE + 1];
    char prefix[MAX_PREFIX_LEN + 1];
    char uniquestr[MAX_UNIQUESTR_LEN + 1];
    struct xcache cache;
    uint32_t migrate;
};

/*
 * pfiled specific structure
 * containing information on a pending I/O operation
 */
struct fio {
    uint32_t state;
    xcache_handler h;
    char str_id[FIO_STR_ID_LEN];
};


static int open_file_path(struct pfiled *pfiled, char *path, int create);
static int open_file_write_path(struct pfiled *pfiled, char *path);
static int open_file_read_path(struct pfiled *pfiled, char *path);


#endif                          /* end of include guard: _FILE_H */
