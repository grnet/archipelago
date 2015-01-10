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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <limits.h>
#include <pthread.h>
#include <syscall.h>
#include <sys/sendfile.h>
#include <openssl/sha.h>
#include <sys/resource.h>
#include <xseg/xseg.h>
#include <xseg/protocol.h>

#include "hash.h"
#include "peer.h"
#include "filed.h"

#define min(_a, _b) (_a < _b ? _a : _b)

/*
 * Globals, holding command-line arguments
 */

void custom_peer_usage(char *argv0)
{
    fprintf(stderr, "General peer options:\n"
            "  Option        | Default    | \n"
            "  --------------------------------------------\n"
            "    --fdcache   | 2 * nr_ops | Fd cache size\n"
            "    --archip    | None       | Archipelago directory\n"
            "    --prefix    | None       | Common prefix of objects that should be stripped\n"
            "    --uniquestr | None       | Unique string for this instance\n"
            "\n");
}

struct pfiled *__get_pfiled(struct peerd *peer)
{
    return (struct pfiled *) peer->priv;
}

struct fio *__get_fio(struct peer_req *pr)
{
    return (struct fio *) pr->priv;
}


/* cache ops */
static void *cache_node_init(void *p, void *xh)
{
    //struct peerd *peer = (struct peerd *)p;
    //struct pfiled *pfiled = __get_pfiled(peer);
    xcache_handler h = *(xcache_handler *) (xh);
    struct fdcache_entry *fdentry = malloc(sizeof(struct fdcache_entry));
    if (!fdentry) {
        return NULL;
    }

    XSEGLOG2(&lc, D, "Initialing node h: %llu with %p",
             (long long unsigned) h, fdentry);

    fdentry->fd = -1;
    fdentry->flags = 0;

    return fdentry;
}

static int cache_init(void *p, void *e)
{
    struct fdcache_entry *fdentry = (struct fdcache_entry *) e;

    if (fdentry->fd != -1) {
        XSEGLOG2(&lc, E, "Found invalid fd %d", fdentry->fd);
        return -1;
    }

    return 0;
}

static void cache_put(void *p, void *e)
{
    struct fdcache_entry *fdentry = (struct fdcache_entry *) e;

    XSEGLOG2(&lc, D, "Putting entry %p with fd %d", fdentry, fdentry->fd);

    if (fdentry->fd != -1) {
        close(fdentry->fd);
    }

    fdentry->fd = -1;
    fdentry->flags = 0;
    return;
}

static void close_cache_entry(struct peerd *peer, struct peer_req *pr)
{
    struct pfiled *pfiled = __get_pfiled(peer);
    struct fio *fio = __get_fio(pr);
    if (fio->h != NoEntry) {
        xcache_put(&pfiled->cache, fio->h);
    }
}

static void pfiled_complete(struct peerd *peer, struct peer_req *pr)
{
    close_cache_entry(peer, pr);
    complete(peer, pr);
}

static void pfiled_fail(struct peerd *peer, struct peer_req *pr)
{
    close_cache_entry(peer, pr);
    fail(peer, pr);
}

static void handle_unknown(struct peerd *peer, struct peer_req *pr)
{
    XSEGLOG2(&lc, W, "unknown request op");
    pfiled_fail(peer, pr);
}

static int is_hex_char(char c)
{
    if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
        return 1;
    }

    return 0;
}

static int matches_pithos_object(char *target, uint32_t targetlen)
{
    int i;

    if (targetlen != HEXLIFIED_SHA256_DIGEST_SIZE) {
        return 0;
    }

    for (i = 0; i < HEXLIFIED_SHA256_DIGEST_SIZE; i++) {
        if (!is_hex_char(target[i])) {
            return 0;
        }
    }

    return 1;
}

static int create_dir(char *path)
{
    struct stat st;

    if (stat(path, &st) < 0) {
        if (mkdir(path, 0777) == 0) {
            return 0;
        }
        if (errno != EEXIST || stat(path, &st) < 0) {
            return -1;
        }
    }

    if (!S_ISDIR(st.st_mode)) {
        return -1;
    }

    return 0;
}

static int __create_path(char *buf, struct pfiled *pfiled, char dirs[6],
                         char *target, uint32_t targetlen, int mkdirs)
{
    int i, r;
    char *path = pfiled->vpath;
    uint32_t pathlen = pfiled->vpath_len;

    strncpy(buf, path, pathlen);

    for (i = 0; i < 9; i += 3) {
        buf[pathlen + i] = dirs[i - (i / 3)];
        buf[pathlen + i + 1] = dirs[i + 1 - (i / 3)];
        buf[pathlen + i + 2] = '/';
        if (mkdirs == 1) {
            buf[pathlen + i + 3] = '\0';
            r = create_dir(buf);
            if (r < 0) {
                return -1;
            }
        }
    }

    strncpy(&buf[pathlen + 9], target, targetlen);
    buf[pathlen + 9 + targetlen] = '\0';

    return 0;
}

static int get_dirs_filed(char buf[6], struct pfiled *pfiled, char *target,
                          uint32_t targetlen)
{
    unsigned char sha[SHA256_DIGEST_SIZE];
    char hex[HEXLIFIED_SHA256_DIGEST_SIZE];

    SHA256((unsigned char *) target, targetlen, sha);
    hexlify(sha, 3, hex);
    strncpy(buf, hex, 6);

    return 0;
}

//make sure to return -ENOENT iff pithos file does not exist.
//Any other error on any other case.
//Migrations only work with caching, since old pithos files are guaranteed read
//only.
static int get_dirs_pithos(char buf[6], struct pfiled *pfiled, char *target,
                           uint32_t targetlen)
{
    int ret, r, pithos_fd;
    char *pithos_path = NULL, *filed_path = NULL;
    struct stat pithos_st, filed_st;

    pithos_path = malloc(MAX_PATH_SIZE + MAX_FILENAME_SIZE + 1);
    filed_path = malloc(MAX_PATH_SIZE + MAX_FILENAME_SIZE + 1);
    if (!pithos_path || !filed_path) {
        ret = -ENOMEM;
        goto out;
    }

    strncpy(buf, target, 6);
    __create_path(pithos_path, pfiled, buf, target, targetlen, 0);

    pithos_fd = open_file_read_path(pfiled, pithos_path);
    if (pithos_fd < 0) {
        ret = -errno;
        goto out_free;
    }
    XSEGLOG2(&lc, I, "Found pithos file %s to on old path", pithos_path);

    if (!pfiled->migrate) {
        ret = 0;
        goto out_close_pithos;
    }

    r = fstat(pithos_fd, &pithos_st);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Fail in stat for pithos_file %s", pithos_path);
        ret = -EIO;
        goto out_close_pithos;
    }

    get_dirs_filed(buf, pfiled, target, targetlen);
    r = __create_path(filed_path, pfiled, buf, target, targetlen, 1);
    if (r < 0) {
        r = -EIO;
        goto out_close_pithos;
    }

    r = link(pithos_path, filed_path);
    if (r < 0) {
        if (errno != EEXIST) {
            XSEGLOG2(&lc, E, "Could not link %s to %s (errno: %d)",
                     pithos_path, filed_path, errno);
            ret = -EIO;
            goto out_close_pithos;
        }
        XSEGLOG2(&lc, I, "Could not link %s to %s. Link already exists",
                 pithos_path, filed_path);

        r = stat(filed_path, &filed_st);
        if (r < 0) {
            XSEGLOG2(&lc, E, "Could not stat %s (errno: %d)",
                     filed_path, errno);
            ret = -EIO;
            goto out_close_pithos;
        }
        if (filed_st.st_ino != pithos_st.st_ino) {
            //not the same file.
            //should we hash the contents ?
            XSEGLOG2(&lc, E, "Old pithos file %s has different "
                     "inode from filed file %s", pithos_path, filed_path);
            ret = -EIO;
            goto out_close_pithos;
        }
    }

    XSEGLOG2(&lc, I, "Successfully linked pithos_file %s to %s",
             pithos_path, filed_path);

    //unlink pithos_path
    r = unlink(pithos_path);
    if (r < 0) {
        /* This is not fatal. It can also be a race with another filed
         * process. In either case, the move was successfull and the new
         * file exists. Just log a warning, and if no other filed
         * process takes care of it, let the external migration tool
         * that will finilize the migration handle it.
         */
        XSEGLOG2(&lc, W, "Could not remove old pithos file");
    }

    /* buf is already fixed */
    ret = 0;

  out_close_pithos:
    close(pithos_fd);
  out_free:
    free(pithos_path);
    free(filed_path);
  out:
    return ret;
}

static int get_dirs(char buf[6], struct pfiled *pfiled, char *target,
                    uint32_t targetlen)
{
    uint32_t prefixlen = pfiled->prefix_len;
    int r;

    if (matches_pithos_object(target, targetlen)) {
        r = get_dirs_pithos(buf, pfiled, target, targetlen);
        if (r != -ENOENT) {
            return r;
        }
    }

    return get_dirs_filed(buf, pfiled, target, targetlen);
}

static int strnjoin(char *dest, int n, ...)
{
    int pos, i;
    va_list ap;
    char *s;
    int l;

    pos = 0;
    va_start(ap, n);
    for (i = 0; i < n; i++) {
        s = va_arg(ap, char *);
        l = va_arg(ap, int);
        strncpy(dest + pos, s, l);
        pos += l;
    }
    dest[pos] = '\0';
    va_end(ap);

    return pos;
}

static int strjoin(char *dest, char *f, int f_len, char *s, int s_len)
{
    int pos;

    pos = 0;
    strncpy(dest + pos, f, f_len);
    pos += f_len;
    strncpy(dest + pos, s, s_len);
    pos += s_len;
    dest[pos] = '\0';

    return f_len + s_len;
}

static int create_path(char *buf, struct pfiled *pfiled, char *target,
                       uint32_t targetlen, int mkdirs)
{
    char dirs[6];
    int r;
    //propagate mkdirs here, to signal a write and filter them out or signal
    //error when do_not_migrate flag enabled ?
    r = get_dirs(dirs, pfiled, target, targetlen);
    if (r < 0) {
        return r;
    }

    return __create_path(buf, pfiled, dirs, target, targetlen, mkdirs);
}


static ssize_t persisting_read(int fd, void *data, size_t size, off_t offset)
{
    ssize_t r = 0, sum = 0;
    char error_str[1024];
    XSEGLOG2(&lc, D, "fd: %d, size: %d, offset: %d", fd, size, offset);

    while (sum < size) {
        XSEGLOG2(&lc, D, "read: %llu, (aligned)size: %llu", sum, size);
        r = pread(fd, (char *) data + sum, size - sum, offset + sum);
        if (r < 0) {
            XSEGLOG2(&lc, E, "fd: %d, Error: %s", fd,
                     strerror_r(errno, error_str, 1023));
            break;
        } else if (r == 0) {
            break;
        } else {
            sum += r;
        }
    }
    XSEGLOG2(&lc, D, "read: %llu, (aligned)size: %llu", sum, size);

    if (sum == 0 && r < 0) {
        sum = r;
    }
    XSEGLOG2(&lc, D, "Finished. Read %d, r = %d", sum, r);

    return sum;
}

static ssize_t persisting_write(int fd, void *data, size_t size, off_t offset)
{
    ssize_t r = 0, sum = 0;

    XSEGLOG2(&lc, D, "fd: %d, size: %d, offset: %d", fd, size, offset);
    while (sum < size) {
        XSEGLOG2(&lc, D, "written: %llu, (aligned)size: %llu", sum, size);
        r = pwrite(fd, (char *) data + sum, size - sum, offset + sum);
        if (r < 0) {
            break;
        } else {
            sum += r;
        }
    }
    XSEGLOG2(&lc, D, "written: %llu, (aligned)size: %llu", sum, size);

    if (sum == 0 && r < 0) {
        sum = r;
    }
    XSEGLOG2(&lc, D, "Finished. Wrote %d, r = %d", sum, r);

    return sum;
}

static ssize_t aligned_read(int fd, void *data, ssize_t size, off_t offset,
                            int alignment)
{
    char *tmp_data;
    ssize_t r;
    size_t misaligned_data, misaligned_size, misaligned_offset;
    off_t aligned_offset = offset;
    size_t aligned_size = size;

    misaligned_data = (unsigned long) data % alignment;
    misaligned_size = size % alignment;
    misaligned_offset = offset % alignment;
    XSEGLOG2(&lc, D,
             "misaligned_data: %u, misaligned_size: %u, misaligned_offset: %u",
             misaligned_data, misaligned_size, misaligned_offset);
    if (misaligned_data || misaligned_size || misaligned_offset) {
        aligned_offset = offset - misaligned_offset;
        aligned_size = size + misaligned_offset;

        misaligned_size = aligned_size % alignment;
        aligned_size = aligned_size - misaligned_size + alignment;
        r = posix_memalign(&tmp_data, alignment, aligned_size);
        if (r < 0) {
            return -1;
        }
    } else {
        tmp_data = data;
        aligned_offset = offset;
        aligned_size = size;
    }

    XSEGLOG2(&lc, D, "aligned_data: %u, aligned_size: %u, aligned_offset: %u",
             tmp_data, aligned_size, aligned_offset);
    r = persisting_read(fd, tmp_data, aligned_size, aligned_offset);

    //FIXME if r < size ?
    if (tmp_data != data) {
        memcpy(data, tmp_data + misaligned_offset, size);
        free(tmp_data);
    }
    if (r >= size) {
        r = size;
    }
    return r;
}

pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;

int __fcntl_lock(int fd, off_t start, off_t len)
{
    return pthread_mutex_lock(&m);
}

int __fcntl_unlock(int fd, off_t start, off_t len)
{
    return pthread_mutex_unlock(&m);
}

static ssize_t aligned_write(int fd, void *data, size_t size, off_t offset,
                             int alignment)
{
    int locked = 0;
    char *tmp_data;
    ssize_t r;
    size_t misaligned_data, misaligned_size, misaligned_offset;
    size_t aligned_size = size, aligned_offset = offset, read_size;
    misaligned_data = (unsigned long) data % alignment;
    misaligned_size = size % alignment;
    misaligned_offset = offset % alignment;
    if (misaligned_data || misaligned_size || misaligned_offset) {
        //if somthing is misaligned then:
        //
        // First check if the offset was missaligned.
        aligned_offset = offset - misaligned_offset;

        // Then adjust the size with the misaligned offset and check if
        // it remains misaligned.
        aligned_size = size + misaligned_offset;
        misaligned_size = aligned_size % alignment;

        // in case there is no misaligned_size
        if (misaligned_size) {
            aligned_size = aligned_size + alignment - misaligned_size;
        }
        // Allocate aligned memory
        r = posix_memalign(&tmp_data, alignment, aligned_size);
        if (r < 0) {
            return -1;
        }

        XSEGLOG2(&lc, D,
                 "fd: %d, misaligned_data: %u, misaligned_size: %u, misaligned_offset: %u",
                 fd, misaligned_data, misaligned_size, misaligned_offset);
        XSEGLOG2(&lc, D,
                 "fd: %d, aligned_data: %u, aligned_size: %u, aligned_offset: %u",
                 fd, tmp_data, aligned_size, aligned_offset);
        XSEGLOG2(&lc, D, "fd: %d, locking from %u to %u", fd, aligned_offset,
                 aligned_offset + aligned_size);
        __fcntl_lock(fd, aligned_offset,
                     aligned_size + alignment - misaligned_size);
        locked = 1;

        if (misaligned_offset) {
            XSEGLOG2(&lc, D, "fd: %d, size: %d, offset: %d", fd, size, offset);
            /* read misaligned_offset */
            read_size = alignment;
            r = persisting_read(fd, tmp_data, alignment, aligned_offset);
            if (r < 0) {
                free(tmp_data);
                return -1;
            } else if (r != read_size) {
                memset(tmp_data + r, 0, read_size - r);
            }
        }

        if (misaligned_size) {
            read_size = alignment;
            r = persisting_read(fd, tmp_data + aligned_size - alignment,
                                alignment,
                                aligned_offset + aligned_size - alignment);
            if (r < 0) {
                free(tmp_data);
                return -1;
            } else if (r != read_size) {
                memset(tmp_data + aligned_size - alignment + r, 0,
                       read_size - r);
            }
        }
        memcpy(tmp_data + misaligned_offset, data, size);
    } else {
        aligned_size = size;
        aligned_offset = offset;
        tmp_data = data;
    }

    r = persisting_write(fd, tmp_data, aligned_size, aligned_offset);

    if (locked) {
        XSEGLOG2(&lc, D, "fd: %d, unlocking from %u to %u", fd, aligned_offset,
                 aligned_offset + aligned_size);
        __fcntl_unlock(fd, aligned_offset,
                       aligned_size + alignment - misaligned_size);
    }
    if (tmp_data != data) {
        free(tmp_data);
    }

    if (r >= size) {
        r = size;
    }
    return r;
}

static ssize_t filed_write(int fd, void *data, size_t size, off_t offset,
                           int direct)
{
    if (direct) {
        return aligned_write(fd, data, size, offset, 512);
    } else {
        return persisting_write(fd, data, size, offset);
    }
}

static ssize_t filed_read(int fd, void *data, size_t size, off_t offset,
                          int direct)
{
    if (direct) {
        return aligned_read(fd, data, size, offset, 512);
    } else {
        return persisting_read(fd, data, size, offset);
    }
}

static ssize_t pfiled_read(struct pfiled *pfiled, int fd, void *data,
                           size_t size, off_t offset)
{
    return filed_read(fd, data, size, offset, pfiled->directio);
}

static ssize_t pfiled_write(struct pfiled *pfiled, int fd, void *data,
                            size_t size, off_t offset)
{
    return filed_write(fd, data, size, offset, pfiled->directio);
}

static ssize_t generic_io_path(char *path, void *data, size_t size,
                               off_t offset, int write, int flags, mode_t mode)
{
    int fd;
    ssize_t r;

    fd = open(path, flags, mode);
    if (fd < 0) {
        return -1;
    }
    XSEGLOG2(&lc, D, "Opened file %s as fd %d", path, fd);

    if (write) {
        r = filed_write(fd, data, size, offset, flags & O_DIRECT);
    } else {
        r = filed_read(fd, data, size, offset, flags & O_DIRECT);
    }

    close(fd);

    return r;
}

static ssize_t read_path(char *path, void *data, size_t size, off_t offset,
                         int direct)
{
    int flags = O_RDONLY;
    if (direct) {
        flags |= O_DIRECT;
    }

    return generic_io_path(path, data, size, offset, 0, flags, 0);
}

static ssize_t pfiled_read_name(struct pfiled *pfiled, char *name,
                                uint32_t namelen, void *data, size_t size,
                                off_t offset)
{
    char path[XSEG_MAX_TARGETLEN + MAX_PATH_SIZE + 1];
    int r;
    r = create_path(path, pfiled, name, namelen, 0);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Could not create path");
        return -1;
    }
    return read_path(path, data, size, offset, pfiled->directio);
}

static ssize_t write_path(char *path, void *data, size_t size, off_t offset,
                          int direct, int extra_open_flags, mode_t mode)
{
    int flags = O_RDWR | extra_open_flags;
    if (direct) {
        flags |= O_DIRECT;
    }
    return generic_io_path(path, data, size, offset, 1, flags, mode);
}

static ssize_t pfiled_write_name(struct pfiled *pfiled, char *name,
                                 uint32_t namelen, void *data, size_t size,
                                 off_t offset, int extra_open_flags,
                                 mode_t mode)
{
    char path[XSEG_MAX_TARGETLEN + MAX_PATH_SIZE + 1];
    int r;
    r = create_path(path, pfiled, name, namelen, 1);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Could not create path");
        return -1;
    }
    return write_path(path, data, size, offset, pfiled->directio,
                      extra_open_flags, mode);
}

static int is_target_valid_len(struct pfiled *pfiled, char *target,
                               uint32_t targetlen, int mode)
{
    if (targetlen > XSEG_MAX_TARGETLEN) {
        XSEGLOG2(&lc, E, "Invalid targetlen %u, max: %u",
                 targetlen, XSEG_MAX_TARGETLEN);
        return -1;
    }
    if (mode == WRITE || mode == READ) {
        /*
         * if name starts with prefix
         *      assert targetlen >= prefix_len + 6
         * else
         *      assert targetlen >= 6
         */
        /* 6 chars are needed for the directory structrure */
        if (!pfiled->prefix_len
            || strncmp(target, pfiled->prefix, pfiled->prefix_len)) {
            if (targetlen < 6) {
                XSEGLOG2(&lc, E, "Targetlen should be at least 6");
                return -1;
            }
        } else {
            if (targetlen < pfiled->prefix_len + 6) {
                XSEGLOG2(&lc, E, "Targetlen should be at least prefix "
                         "len(%u) + 6", pfiled->prefix_len);
                return -1;
            }
        }
    } else {
        XSEGLOG2(&lc, E, "Invalid mode");
        return -1;
    }

    return 0;
}

/*
static int is_target_valid(struct pfiled *pfiled, char *target, int mode)
{
	return is_target_valid_len(pfiled, target, strlen(target), mode);
}
*/

static int open_file_path(struct pfiled *pfiled, char *path, int create)
{
    int fd, flags;
    char error_str[1024];

    flags = O_RDWR;
    if (create) {
        flags |= O_CREAT;
        XSEGLOG2(&lc, D, "Opening file %s with O_RDWR|O_CREAT", path);
    } else {
        XSEGLOG2(&lc, D, "Opening file %s with O_RDWR", path);
    }

    if (pfiled->directio) {
        flags |= O_DIRECT;
    }

    fd = open(path, flags,
              S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
    if (fd < 0) {
        XSEGLOG2(&lc, E, "Could not open file %s. Error: %s", path,
                 strerror_r(errno, error_str, 1023));
        return -errno;
    }

    return fd;
}

static int open_file_write_path(struct pfiled *pfiled, char *path)
{
    return open_file_path(pfiled, path, 1);
}

static int open_file_read_path(struct pfiled *pfiled, char *path)
{
    return open_file_path(pfiled, path, 0);
}

static int open_file_write(struct pfiled *pfiled, char *target,
                           uint32_t targetlen)
{
    int r;
    char tmp[XSEG_MAX_TARGETLEN + MAX_PATH_SIZE + 1];

    r = create_path(tmp, pfiled, target, targetlen, 1);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Could not create path");
        return -1;
    }

    return open_file_write_path(pfiled, tmp);
}

static int open_file_read(struct pfiled *pfiled, char *target,
                          uint32_t targetlen)
{
    int r;
    char tmp[XSEG_MAX_TARGETLEN + MAX_PATH_SIZE + 1];

    r = create_path(tmp, pfiled, target, targetlen, 0);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Could not create path");
        return -1;
    }

    return open_file_read_path(pfiled, tmp);
}

static int open_file(struct pfiled *pfiled, char *target, uint32_t targetlen,
                     int mode)
{
    if (mode == WRITE) {
        return open_file_write(pfiled, target, targetlen);
    } else if (mode == READ) {
        return open_file_read(pfiled, target, targetlen);
    } else {
        XSEGLOG2(&lc, E, "Invalid mode for target");
    }
    return -1;
}

static int dir_open(struct pfiled *pfiled, struct fio *fio,
                    char *target, uint32_t targetlen, int mode)
{
    int r, fd;
    struct fdcache_entry *e;
    xcache_handler h = NoEntry, nh;
    char name[XSEG_MAX_TARGETLEN + 1];

    if (targetlen > XSEG_MAX_TARGETLEN) {
        XSEGLOG2(&lc, E, "Invalid targetlen %u, max: %u",
                 targetlen, XSEG_MAX_TARGETLEN);
        return -1;
    }
    strncpy(name, target, targetlen);
    name[targetlen] = '\0';
    XSEGLOG2(&lc, I, "Dir open started for %s", name);

    h = xcache_lookup(&pfiled->cache, name);
    if (h == NoEntry) {
        r = is_target_valid_len(pfiled, target, targetlen, mode);
        if (r < 0) {
            XSEGLOG2(&lc, E, "Invalid len for target %s", name);
            goto out_err;
        }

        h = xcache_alloc_init(&pfiled->cache, name);
        if (h == NoEntry) {
            /* FIXME add waitq to wait for free */
            XSEGLOG2(&lc, E, "Could not allocate cache entry for %s", name);
            goto out_err;
        }
        XSEGLOG2(&lc, D, "Allocated new handler %llu for %s",
                 (long long unsigned) h, name);

        e = xcache_get_entry(&pfiled->cache, h);
        if (!e) {
            XSEGLOG2(&lc, E, "Alloced handler but no valid fd cache entry");
            goto out_free;
        }

        /* open/create file */
        fd = open_file(pfiled, target, targetlen, mode);
        if (fd < 0) {
            XSEGLOG2(&lc, E, "Could not open file for target %s", name);
            goto out_free;
        }
        XSEGLOG2(&lc, D, "Opened file %s. fd %d", name, fd);

        e->fd = fd;

        XSEGLOG2(&lc, D, "Inserting handler %llu for %s to fdcache",
                 (long long unsigned) h, name);
        nh = xcache_insert(&pfiled->cache, h);
        if (nh != h) {
            XSEGLOG2(&lc, D, "Partial cache hit for %s. New handler %llu",
                     name, (long long unsigned) nh);
            xcache_put(&pfiled->cache, h);
            h = nh;
        }
    } else {
        XSEGLOG2(&lc, D, "Cache hit for %s, handler: %llu", name,
                 (long long unsigned) h);
    }

    e = xcache_get_entry(&pfiled->cache, h);
    if (!e) {
        XSEGLOG2(&lc, E, "Found handler but no valid fd cache entry");
        xcache_put(&pfiled->cache, h);
        fio->h = NoEntry;
        goto out_err;
    }
    fio->h = h;

    //assert e->fd != -1 ?;
    XSEGLOG2(&lc, I, "Dir open finished for %s", name);
    return e->fd;

  out_free:
    xcache_free_new(&pfiled->cache, h);
  out_err:
    XSEGLOG2(&lc, E, "Dir open failed for %s", name);
    return -1;
}

static void handle_read(struct peerd *peer, struct peer_req *pr)
{
    struct pfiled *pfiled = __get_pfiled(peer);
    struct fio *fio = __get_fio(pr);
    struct xseg_request *req = pr->req;
    int r, fd;
    char *target = xseg_get_target(peer->xseg, req);
    char *data = xseg_get_data(peer->xseg, req);

    XSEGLOG2(&lc, I, "Handle read started for pr: %p, req: %p", pr, pr->req);

    if (!req->size) {
        pfiled_complete(peer, pr);
        return;
    }

    if (req->datalen < req->size) {
        XSEGLOG2(&lc, E, "Request datalen is less than request size");
        pfiled_fail(peer, pr);
        return;
    }


    fd = dir_open(pfiled, fio, target, req->targetlen, READ);
    if (fd < 0) {
        XSEGLOG2(&lc, E, "Open failed");
        pfiled_fail(peer, pr);
        return;
    }


    XSEGLOG2(&lc, D, "req->serviced: %llu, req->size: %llu", req->serviced,
             req->size);
    r = pfiled_read(pfiled, fd, data, req->size, req->offset);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Cannot read");
        req->serviced = 0;
    } else if (r < req->size) {
        /* reached end of file. zero out the rest data buffer */
        memset(data + r, 0, req->size - r);
        req->serviced = req->size;
    } else {
        req->serviced = r;
    }
    XSEGLOG2(&lc, D, "req->serviced: %llu, req->size: %llu", req->serviced,
             req->size);

  out:
    if (req->serviced > 0) {
        XSEGLOG2(&lc, I, "Handle read completed for pr: %p, req: %p",
                 pr, pr->req);
        pfiled_complete(peer, pr);
    } else {
        XSEGLOG2(&lc, E, "Handle read failed for pr: %p, req: %p",
                 pr, pr->req);
        pfiled_fail(peer, pr);
    }
    return;
}

static void handle_write(struct peerd *peer, struct peer_req *pr)
{
    struct pfiled *pfiled = __get_pfiled(peer);
    struct fio *fio = __get_fio(pr);
    struct xseg_request *req = pr->req;
    int fd;
    ssize_t r;
    char *target = xseg_get_target(peer->xseg, req);
    char *data = xseg_get_data(peer->xseg, req);

    XSEGLOG2(&lc, I, "Handle write started for pr: %p, req: %p", pr, pr->req);

    if (req->datalen < req->size) {
        XSEGLOG2(&lc, E, "Request datalen is less than request size");
        pfiled_fail(peer, pr);
        return;
    }

    fd = dir_open(pfiled, fio, target, req->targetlen, WRITE);
    if (fd < 0) {
        XSEGLOG2(&lc, E, "Open failed");
        pfiled_fail(peer, pr);
        return;
    }

    if (!req->size) {
        if (req->flags & (XF_FLUSH | XF_FUA)) {
            /* No FLUSH/FUA support yet (O_SYNC ?).
             * note that with FLUSH/size == 0
             * there will probably be a (uint64_t)-1 offset */
            pfiled_complete(peer, pr);
            return;
        } else {
            pfiled_complete(peer, pr);
            return;
        }
    }

    XSEGLOG2(&lc, D, "req->serviced: %llu, req->size: %llu", req->serviced,
             req->size);
    r = pfiled_write(pfiled, fd, data, req->size, req->offset);
    if (r < 0) {
        req->serviced = 0;
    } else {
        req->serviced = r;
    }
    XSEGLOG2(&lc, D, "req->serviced: %llu, req->size: %llu", req->serviced,
             req->size);
    r = fsync(fd);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Fsync failed.");
        /* if fsync fails, then no bytes serviced correctly */
        req->serviced = 0;
    }

    if (req->serviced > 0) {
        XSEGLOG2(&lc, I, "Handle write completed for pr: %p, req: %p",
                 pr, pr->req);
        pfiled_complete(peer, pr);
    } else {
        XSEGLOG2(&lc, E, "Handle write failed for pr: %p, req: %p",
                 pr, pr->req);
        pfiled_fail(peer, pr);
    }
    return;
}

static void handle_info(struct peerd *peer, struct peer_req *pr)
{
    struct pfiled *pfiled = __get_pfiled(peer);
    struct fio *fio = __get_fio(pr);
    struct xseg_request *req = pr->req;
    struct stat stat;
    int fd, r;
    uint64_t size;
    char *target = xseg_get_target(peer->xseg, req);
    char *data = xseg_get_data(peer->xseg, req);
    char buf[XSEG_MAX_TARGETLEN + 1];
    struct xseg_reply_info *xinfo = (struct xseg_reply_info *) data;

    if (req->datalen < sizeof(struct xseg_reply_info)) {
        strncpy(buf, target, req->targetlen);
        r = xseg_resize_request(peer->xseg, req, req->targetlen,
                                sizeof(struct xseg_reply_info));
        if (r < 0) {
            XSEGLOG2(&lc, E, "Cannot resize request");
            pfiled_fail(peer, pr);
            return;
        }
        target = xseg_get_target(peer->xseg, req);
        strncpy(target, buf, req->targetlen);
    }

    XSEGLOG2(&lc, I, "Handle info started for pr: %p, req: %p", pr, pr->req);
    fd = dir_open(pfiled, fio, target, req->targetlen, READ);
    if (fd < 0) {
        XSEGLOG2(&lc, E, "Dir open failed");
        pfiled_fail(peer, pr);
        return;
    }

    r = fstat(fd, &stat);
    if (r < 0) {
        XSEGLOG2(&lc, E, "fail in stat");
        pfiled_fail(peer, pr);
        return;
    }

    size = (uint64_t) stat.st_size;
    xinfo->size = size;

    XSEGLOG2(&lc, I, "Handle info completed for pr: %p, req: %p", pr, pr->req);
    pfiled_complete(peer, pr);
}

static void handle_copy(struct peerd *peer, struct peer_req *pr)
{
    struct pfiled *pfiled = __get_pfiled(peer);
    struct fio *fio = __get_fio(pr);
    struct xseg_request *req = pr->req;
    char *target = xseg_get_target(peer->xseg, req);
    char *data = xseg_get_data(peer->xseg, req);
    struct xseg_request_copy *xcopy = (struct xseg_request_copy *) data;
    struct stat st;
    char *buf = malloc(MAX_PATH_SIZE + MAX_FILENAME_SIZE);
    int src = -1, dst = -1, r = -1;
    ssize_t c = 0, bytes;
    ssize_t limit = 0;

    XSEGLOG2(&lc, I, "Handle copy started for pr: %p, req: %p", pr, pr->req);
    if (!buf) {
        XSEGLOG2(&lc, E, "Out of memory");
        pfiled_fail(peer, pr);
        return;
    }

    r = is_target_valid_len(pfiled, xcopy->target, xcopy->targetlen, READ);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Source target not valid");
        goto out;
    }

    dst = dir_open(pfiled, fio, target, req->targetlen, WRITE);
    if (dst < 0) {
        XSEGLOG2(&lc, E, "Fail in dst");
        r = dst;
        goto out;
    }

    src = open_file(pfiled, xcopy->target, xcopy->targetlen, READ);
    if (src < 0) {
        XSEGLOG2(&lc, E, "Failed to open src");
        goto out;
    }

    r = fstat(src, &st);
    if (r < 0) {
        XSEGLOG2(&lc, E, "fail in stat for src %s", buf);
        goto out;
    }

    c = 0;

    limit = min(req->size, st.st_size);
    while (c < limit) {
        bytes = sendfile(dst, src, NULL, limit - c);
        if (bytes < 0) {
            XSEGLOG2(&lc, E, "Copy failed for %s", buf);
            r = -1;
            goto out;
        }
        c += bytes;
    }
    r = 0;

  out:
    req->serviced = c;
    if (limit && c == limit) {
        req->serviced = req->size;
    }

    if (src > 0) {
        close(src);
    }
    free(buf);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Handle copy failed for pr: %p, req: %p", pr,
                 pr->req);
        pfiled_fail(peer, pr);
    } else {
        XSEGLOG2(&lc, I, "Handle copy completed for pr: %p, req: %p", pr,
                 pr->req);
        pfiled_complete(peer, pr);
    }
    return;
}

static void handle_delete(struct peerd *peer, struct peer_req *pr)
{
    struct pfiled *pfiled = __get_pfiled(peer);
    //struct fio *fio = __get_fio(pr);
    struct xseg_request *req = pr->req;
    char name[XSEG_MAX_TARGETLEN + 1];
    char *buf = malloc(MAX_PATH_SIZE + MAX_FILENAME_SIZE);
    int r;
    char *target = xseg_get_target(peer->xseg, req);

    XSEGLOG2(&lc, I, "Handle delete started for pr: %p, req: %p", pr, pr->req);

    if (!buf) {
        XSEGLOG2(&lc, E, "Out of memory");
        pfiled_fail(peer, pr);
        return;
    }

    r = is_target_valid_len(pfiled, target, req->targetlen, READ);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Target not valid");
        goto out;
    }

    r = create_path(buf, pfiled, target, req->targetlen, 0);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Create path failed");
        goto out;
    }
    r = unlink(buf);
  out:
    free(buf);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Handle delete failed for pr: %p, req: %p", pr,
                 pr->req);
        pfiled_fail(peer, pr);
    } else {
        strncpy(name, target, XSEG_MAX_TARGETLEN);
        name[XSEG_MAX_TARGETLEN] = 0;
        xcache_invalidate(&pfiled->cache, name);
        XSEGLOG2(&lc, I, "Handle delete completed for pr: %p, req: %p", pr,
                 pr->req);
        pfiled_complete(peer, pr);
    }
    return;
}

static int __get_precalculated_hash(struct peerd *peer, char *target,
                                    uint32_t targetlen, char *hash)
{
    int ret = -1;
    int r;
    uint32_t len, hash_file_len;
    char *hash_file = NULL;
    struct pfiled *pfiled = __get_pfiled(peer);

    XSEGLOG2(&lc, D, "Started.");

    hash_file = malloc(MAX_FILENAME_SIZE + 1);
    hash_file_len =
        strjoin(hash_file, target, targetlen, HASH_SUFFIX, HASH_SUFFIX_LEN);
    hash[0] = '\0';

    r = pfiled_read_name(pfiled, hash_file, hash_file_len, hash,
                         HEXLIFIED_SHA256_DIGEST_SIZE, 0);
    if (r < 0) {
        if (errno != ENOENT) {
            XSEGLOG2(&lc, E, "Error opening %s", hash_file);
        } else {
            XSEGLOG2(&lc, I, "No precalculated hash for %s", hash_file);
            ret = 0;
        }
        goto out;
    }
    len = (uint32_t) r;
    XSEGLOG2(&lc, D, "Read %u bytes", len);

    if (len == HEXLIFIED_SHA256_DIGEST_SIZE) {
        hash[HEXLIFIED_SHA256_DIGEST_SIZE] = 0;
        XSEGLOG2(&lc, D, "Found hash for %s : %s", hash_file, hash);
        ret = 0;
    }
  out:
    free(hash_file);
    XSEGLOG2(&lc, D, "Finished.");
    return ret;
}

static int __set_precalculated_hash(struct peerd *peer, char *target,
                                    uint32_t targetlen, char *hash)
{
    int ret = -1;
    int r;
    uint32_t len, hash_file_len;
    char *hash_file = NULL;
    struct pfiled *pfiled = __get_pfiled(peer);

    XSEGLOG2(&lc, D, "Started.");

    hash_file = malloc(MAX_FILENAME_SIZE + 1);
    hash_file_len =
        strjoin(hash_file, target, targetlen, HASH_SUFFIX, HASH_SUFFIX_LEN);

    r = pfiled_write_name(pfiled, hash_file, hash_file_len, hash,
                          HEXLIFIED_SHA256_DIGEST_SIZE, 0, O_CREAT | O_EXCL,
                          S_IWUSR | S_IRUSR | S_IRGRP | S_IWGRP | S_IROTH |
                          S_IWOTH);
    if (r < 0) {
        if (errno != EEXIST) {
            XSEGLOG2(&lc, E, "Error opening %s", hash_file);
        } else {
            XSEGLOG2(&lc, I, "Hash file already exists %s", hash_file);
            ret = 0;
        }
        goto out;
    }

    len = (uint32_t) r;
    XSEGLOG2(&lc, D, "Wrote %u bytes", len);
    ret = 0;
  out:
    free(hash_file);
    XSEGLOG2(&lc, D, "Finished.");
    return ret;
}

static void handle_hash(struct peerd *peer, struct peer_req *pr)
{
    //open src
    //read all file
    //sha256 hash
    //stat (open without create)
    //write to hash_tmpfile
    //link file

    int len;
    int src = -1, dst = -1, r = -1;
    ssize_t c;
    uint64_t sum, trailing_zeros;
    struct pfiled *pfiled = __get_pfiled(peer);
    struct fio *fio = __get_fio(pr);
    struct xseg_request *req = pr->req;
    char *pathname = NULL, *tmpfile_pathname = NULL, *tmpfile = NULL;
    char *target;
//      char hash_name[HEXLIFIED_SHA256_DIGEST_SIZE + 1];
    char *hash_name;
    char name[XSEG_MAX_TARGETLEN + 1];

    unsigned char *object_data = NULL;
    unsigned char sha[SHA256_DIGEST_SIZE];
    struct xseg_reply_hash *xreply;

    target = xseg_get_target(peer->xseg, req);

    XSEGLOG2(&lc, I, "Handle hash started for pr: %p, req: %p", pr, pr->req);

    if (!req->size) {
        XSEGLOG2(&lc, E, "No request size provided");
        r = -1;
        goto out;
    }

    r = is_target_valid_len(pfiled, target, req->targetlen, READ);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Source target not valid");
        goto out;
    }

    r = posix_memalign(&hash_name, 512, 512 + 1);

    r = __get_precalculated_hash(peer, target, req->targetlen, hash_name);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Error getting precalculated hash");
        goto out;
    }

    if (hash_name[0] != '\0') {
        XSEGLOG2(&lc, I, "Precalucated hash found %s", hash_name);
        goto found;
    }

    XSEGLOG2(&lc, I, "No precalculated hash found");

    strncpy(name, target, req->targetlen);
    name[req->targetlen] = '\0';

    pathname = malloc(MAX_PATH_SIZE + MAX_FILENAME_SIZE + 1);
    //object_data = malloc(sizeof(char) * req->size);
    r = posix_memalign(&object_data, 512, sizeof(char) * req->size);
    if (!pathname || !object_data) {
        XSEGLOG2(&lc, E, "Out of memory");
        goto out;
    }

    src = dir_open(pfiled, fio, target, req->targetlen, READ);
    if (src < 0) {
        XSEGLOG2(&lc, E, "Fail in src");
        r = dst;
        goto out;
    }

    c = pfiled_read(pfiled, src, object_data, req->size, req->offset);
    if (c < 0) {
        XSEGLOG2(&lc, E, "Error reading from source");
        r = -1;
        goto out;
    }
    sum = c;

    //rstrip here in case zeros were written in the end
    trailing_zeros = 0;
    for (; trailing_zeros < sum; trailing_zeros++) {
        if (object_data[sum - trailing_zeros - 1]) {
            break;
        }
    }

    XSEGLOG2(&lc, D, "Read %llu, Trainling zeros %llu", sum, trailing_zeros);

    sum -= trailing_zeros;
    //calculate hash name
    SHA256(object_data, sum, sha);

    hexlify(sha, SHA256_DIGEST_SIZE, hash_name);
    hash_name[HEXLIFIED_SHA256_DIGEST_SIZE] = '\0';


    r = create_path(pathname, pfiled, hash_name, HEXLIFIED_SHA256_DIGEST_SIZE,
                    1);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Create path failed");
        r = -1;
        goto out;
    }


    dst = open_file(pfiled, hash_name, HEXLIFIED_SHA256_DIGEST_SIZE, READ);
    if (dst > 0) {
        XSEGLOG2(&lc, I, "%s already exists, no write needed", pathname);
        req->serviced = req->size;
        r = 0;
        goto out;
    }

    tmpfile_pathname = malloc(MAX_PATH_SIZE + MAX_FILENAME_SIZE + 1);
    if (!tmpfile_pathname) {
        XSEGLOG2(&lc, E, "Out of memory");
        r = -1;
        goto out;
    }

    tmpfile = malloc(MAX_FILENAME_SIZE);
    if (!tmpfile) {
        XSEGLOG2(&lc, E, "Out of memory");
        r = -1;
        goto out;
    }

    len = strnjoin(tmpfile, 4, target, req->targetlen,
                   HASH_SUFFIX, HASH_SUFFIX_LEN,
                   pfiled->uniquestr, pfiled->uniquestr_len,
                   fio->str_id, FIO_STR_ID_LEN);

    r = pfiled_write_name(pfiled, tmpfile, len, object_data, sum, 0,
                          O_CREAT | O_EXCL,
                          S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH |
                          S_IWOTH);
    if (r < 0) {
        if (errno != EEXIST) {
            char error_str[1024];
            XSEGLOG2(&lc, E, "Error opening %s (%s)", tmpfile_pathname,
                     strerror_r(errno, error_str, 1023));
        } else {
            XSEGLOG2(&lc, E, "Error opening %s. Stale data found.",
                     tmpfile_pathname);
        }
        r = -1;
        goto out;
    } else if (r < sum) {
        XSEGLOG2(&lc, E, "Error writting to dst file %s", tmpfile_pathname);
        r = -1;
        goto out_unlink;
    }
    XSEGLOG2(&lc, D, "Opened %s and wrote", tmpfile);

    r = create_path(tmpfile_pathname, pfiled, tmpfile, len, 1);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Create path failed");
        r = -1;
        goto out;
    }

    r = link(tmpfile_pathname, pathname);
    if (r < 0 && errno != EEXIST) {
        XSEGLOG2(&lc, E, "Error linking tmp file %s. Errno %d",
                 pathname, errno);
        r = -1;
        goto out_unlink;
    }

    r = unlink(tmpfile_pathname);
    if (r < 0) {
        XSEGLOG2(&lc, W, "Error unlinking tmp file %s", tmpfile_pathname);
        r = 0;
    }

    r = __set_precalculated_hash(peer, target, req->targetlen, hash_name);
    if (r < 0) {
        XSEGLOG2(&lc, W, "Error setting precalculated hash");
        r = 0;
    }

  found:
    r = xseg_resize_request(peer->xseg, pr->req, pr->req->targetlen,
                            sizeof(struct xseg_reply_hash));
    if (r < 0) {
        XSEGLOG2(&lc, E, "Resize request failed");
        r = -1;
        goto out;
    }

    xreply = (struct xseg_reply_hash *) xseg_get_data(peer->xseg, req);
    strncpy(xreply->target, hash_name, HEXLIFIED_SHA256_DIGEST_SIZE);
    xreply->targetlen = HEXLIFIED_SHA256_DIGEST_SIZE;

    req->serviced = req->size;
    r = 0;

  out:
    if (dst > 0) {
        close(dst);
    }
    if (r < 0) {
        XSEGLOG2(&lc, E, "Handle hash failed for pr: %p, req: %p. ",
                 "Target %s", pr, pr->req, name);
        pfiled_fail(peer, pr);
    } else {
        XSEGLOG2(&lc, I, "Handle hash completed for pr: %p, req: %p\n\t"
                 "hashed %s to %s", pr, pr->req, name, hash_name);
        pfiled_complete(peer, pr);
    }
    free(tmpfile_pathname);
    free(pathname);
    free(object_data);
    return;

  out_unlink:
    unlink(tmpfile_pathname);
    goto out;
}

static int __locked_by(char *lockfile, char *expected, uint32_t expected_len,
                       int direct)
{
    int ret = -1;
    int r;
    uint32_t len;
    char tmpbuf[MAX_UNIQUESTR_LEN];

    XSEGLOG2(&lc, D, "Started. Lockfile: %s, expected: %s, expected_len: %u",
             lockfile, expected, expected_len);
    r = read_path(lockfile, tmpbuf, MAX_UNIQUESTR_LEN, 0, direct);
    if (r < 0) {
        if (errno != ENOENT) {
            XSEGLOG2(&lc, E, "Error opening %s", lockfile);
        } else {
            //-2 == retry
            XSEGLOG2(&lc, I, "lock file removed");
            ret = -2;
        }
        goto out;
    }
    len = (uint32_t) r;
    XSEGLOG2(&lc, D, "Read %u bytes", len);
    if (!strncmp(tmpbuf, expected, expected_len)) {
        XSEGLOG2(&lc, D, "Lock file %s locked by us.", lockfile);
        ret = 0;
    }
  out:
    XSEGLOG2(&lc, D, "Finished. Lockfile: %s", lockfile);
    return ret;
}

static int __try_lock(struct pfiled *pfiled, char *tmpfile, char *lockfile,
                      uint32_t flags, int fd)
{
    int r, direct;
    XSEGLOG2(&lc, D, "Started. Lockfile: %s, Tmpfile:%s", lockfile, tmpfile);

    r = pfiled_write(pfiled, fd, pfiled->uniquestr, pfiled->uniquestr_len, 0);
    if (r < 0 || r < pfiled->uniquestr_len) {
        return -1;
    }
    r = fsync(fd);
    if (r < 0) {
        return -1;
    }

    direct = pfiled->directio;
//      direct = 0;

    while (link(tmpfile, lockfile) < 0) {
        //actual error
        if (errno != EEXIST) {
            XSEGLOG2(&lc, E, "Error linking %s to %s", tmpfile, lockfile);
            return -1;
        }
        r = __locked_by(lockfile, pfiled->uniquestr, pfiled->uniquestr_len,
                        direct);
        if (!r) {
            break;
        }
        if (flags & XF_NOSYNC) {
            XSEGLOG2(&lc, D, "Could not get lock file %s, "
                     "XF_NOSYNC set. Aborting", lockfile);
            return -1;
        }
        sleep(1);
    }
    XSEGLOG2(&lc, D, "Finished. Lockfile: %s", lockfile);
    return 0;
}

static void handle_acquire(struct peerd *peer, struct peer_req *pr)
{
    int r, ret = -1;
    struct pfiled *pfiled = __get_pfiled(peer);
    struct fio *fio = __get_fio(pr);
    struct xseg_request *req = pr->req;
    char *buf = malloc(MAX_FILENAME_SIZE);
    char *tmpfile = malloc(MAX_FILENAME_SIZE);
    char *lockfile_pathname;
    char *tmpfile_pathname;
    int fd = -1, flags;
    char *target = xseg_get_target(peer->xseg, req);
    uint32_t buf_len, tmpfile_len;

    lockfile_pathname = malloc(MAX_PATH_SIZE + MAX_FILENAME_SIZE + 1);
    tmpfile_pathname = malloc(MAX_PATH_SIZE + MAX_FILENAME_SIZE + 1);

    if (!buf || !tmpfile || !tmpfile_pathname || !lockfile_pathname) {
        XSEGLOG2(&lc, E, "Out of memory");
        pfiled_fail(peer, pr);
        return;
    }

    r = is_target_valid_len(pfiled, target, req->targetlen, READ);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Target not valid");
        goto out;
    }


    buf_len =
        strjoin(buf, target, req->targetlen, LOCK_SUFFIX, LOCK_SUFFIX_LEN);

    XSEGLOG2(&lc, I, "Started. Lockfile: %s", buf);


    tmpfile_len = strnjoin(tmpfile, 3, buf, buf_len,
                           pfiled->uniquestr, pfiled->uniquestr_len,
                           fio->str_id, FIO_STR_ID_LEN);

    XSEGLOG2(&lc, I, "Trying to acquire lock %s", buf);

    if (!pfiled->lockpath_len) {
        if (create_path(tmpfile_pathname, pfiled, tmpfile, tmpfile_len, 1) < 0) {
            XSEGLOG2(&lc, E, "Create path failed for %s", buf);
            goto out;
        }

        if (create_path(lockfile_pathname, pfiled, buf, buf_len, 1) < 0) {
            XSEGLOG2(&lc, E, "Create path failed for %s", buf);
            goto out;
        }
    } else {
        strjoin(tmpfile_pathname, pfiled->lockpath,
                pfiled->lockpath_len, tmpfile, tmpfile_len);
        strjoin(lockfile_pathname, pfiled->lockpath,
                pfiled->lockpath_len, buf, buf_len);
    }

    //create exclusive unique lockfile (block_uniqueid+target)
    //if (OK)
    //      write blocker uniqueid to the unique lockfile
    //      try to link it to the lockfile
    //      if (OK)
    //              unlink unique lockfile;
    //              complete
    //      else
    //              spin while not able to link

    //nfs v >= 3
    XSEGLOG2(&lc, D, "Tmpfile: %s", tmpfile_pathname);
    flags = O_RDWR | O_CREAT | O_EXCL;
    if (pfiled->directio) {
        flags |= O_DIRECT;
    }
    fd = open(tmpfile_pathname, flags,
              S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
    if (fd < 0) {
        //actual error
        if (errno != EEXIST) {
            XSEGLOG2(&lc, E, "Error opening %s", tmpfile_pathname);
            goto out;
        } else {
            XSEGLOG2(&lc, E, "Error opening %s. Stale data found.",
                     tmpfile_pathname);
        }
        ret = -1;
    } else {
        XSEGLOG2(&lc, D, "Tmpfile %s created. Trying to get lock",
                 tmpfile_pathname);
        r = __try_lock(pfiled, tmpfile_pathname, lockfile_pathname,
                       req->flags, fd);
        if (r < 0) {
            XSEGLOG2(&lc, E, "Trying to get lock %s failed", buf);
            ret = -1;
        } else {
            XSEGLOG2(&lc, D, "Trying to get lock %s succeed", buf);
            ret = 0;
        }
        r = close(fd);
        if (r < 0) {
            XSEGLOG2(&lc, W, "Error closing %s", tmpfile_pathname);
        }
        r = unlink(tmpfile_pathname);
        if (r < 0) {
            XSEGLOG2(&lc, E, "Error unlinking %s", tmpfile_pathname);
        }
    }
  out:
    if (ret < 0) {
        XSEGLOG2(&lc, I, "Failed to acquire lock %s", buf);
        pfiled_fail(peer, pr);
    } else {
        XSEGLOG2(&lc, I, "Acquired lock %s", buf);
        pfiled_complete(peer, pr);
    }
    free(buf);
    free(lockfile_pathname);
    free(tmpfile_pathname);
    return;
}

static void handle_release(struct peerd *peer, struct peer_req *pr)
{
    struct pfiled *pfiled = __get_pfiled(peer);
//      struct fio *fio = __get_fio(pr);
    struct xseg_request *req = pr->req;
    char *buf = malloc(MAX_FILENAME_SIZE + 1);
    char *pathname = malloc(MAX_PATH_SIZE + MAX_FILENAME_SIZE + 1);
    char *tmpbuf = malloc(MAX_UNIQUESTR_LEN + 1);
    char *target = xseg_get_target(peer->xseg, req);
    int r, buf_len, direct;

    if (!buf || !pathname) {
        XSEGLOG2(&lc, E, "Out of memory");
        fail(peer, pr);
        return;
    }

    r = is_target_valid_len(pfiled, target, req->targetlen, READ);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Target not valid");
        goto out;
    }

    buf_len =
        strnjoin(buf, 2, target, req->targetlen, LOCK_SUFFIX, LOCK_SUFFIX_LEN);

    XSEGLOG2(&lc, I, "Started. Lockfile: %s", buf);

    if (!pfiled->lockpath_len) {
        r = create_path(pathname, pfiled, buf, buf_len, 0);
        if (r < 0) {
            XSEGLOG2(&lc, E, "Create path failed for %s", buf);
            goto out;
        }
    } else {
        strjoin(pathname, pfiled->lockpath, pfiled->lockpath_len,
                buf, buf_len);
    }

    direct = pfiled->directio;

    if ((req->flags & XF_FORCE) || !__locked_by(pathname, pfiled->uniquestr,
                                                pfiled->uniquestr_len,
                                                direct)) {
        r = unlink(pathname);
        if (r < 0) {
            XSEGLOG2(&lc, E, "Could not unlink %s", pathname);
            goto out;
        }
    } else {
        r = -1;
    }

  out:
    if (r < 0) {
        fail(peer, pr);
    } else {
        XSEGLOG2(&lc, I, "Released lockfile: %s", buf);
        complete(peer, pr);
    }
    XSEGLOG2(&lc, I, "Finished. Lockfile: %s", buf);
    free(buf);
    free(tmpbuf);
    free(pathname);
    return;
}

int dispatch(struct peerd *peer, struct peer_req *pr, struct xseg_request *req,
             enum dispatch_reason reason)
{
    struct fio *fio = __get_fio(pr);
    if (reason == dispatch_accept) {
        fio->h = NoEntry;
    }

    switch (req->op) {
    case X_READ:
        handle_read(peer, pr);
        break;
    case X_WRITE:
        handle_write(peer, pr);
        break;
    case X_INFO:
        handle_info(peer, pr);
        break;
    case X_COPY:
        handle_copy(peer, pr);
        break;
    case X_DELETE:
        handle_delete(peer, pr);
        break;
    case X_ACQUIRE:
        handle_acquire(peer, pr);
        break;
    case X_RELEASE:
        handle_release(peer, pr);
        break;
    case X_HASH:
        handle_hash(peer, pr);
        break;
    case X_SYNC:
    default:
        handle_unknown(peer, pr);
    }
    return 0;
}

int custom_peer_init(struct peerd *peer, int argc, char *argv[])
{
    /*
       get blocks,maps paths
       get optional pithos block,maps paths
       get fdcache size
       check if greater than limit (tip: getrlimit)
       assert cachesize greater than nr_ops
       assert nr_ops greater than nr_threads
       get prefix
     */

    int ret = 0;
    int i, r;
    struct fio *fio;
    struct pfiled *pfiled = malloc(sizeof(struct pfiled));
    struct rlimit rlim;
    struct xcache_ops c_ops = {
        .on_node_init = cache_node_init,
        .on_init = cache_init,
        .on_put = cache_put,
    };
    if (!pfiled) {
        XSEGLOG2(&lc, E, "Out of memory");
        ret = -ENOMEM;
        goto out;
    }
    peer->priv = pfiled;

    pfiled->maxfds = 2 * peer->nr_ops;
    pfiled->migrate = 0;        /* false by default */

    for (i = 0; i < peer->nr_ops; i++) {
        peer->peer_reqs[i].priv = malloc(sizeof(struct fio));
        if (!peer->peer_reqs->priv) {
            XSEGLOG2(&lc, E, "Out of memory");
            ret = -ENOMEM;
            goto out;
        }
        fio = __get_fio(&peer->peer_reqs[i]);
        fio->str_id[0] = '_';
        fio->str_id[1] = 'a' + (i / 26);
        fio->str_id[2] = 'a' + (i % 26);
    }

    pfiled->vpath[0] = '\0';
    pfiled->prefix[0] = '\0';
    pfiled->uniquestr[0] = '\0';
    pfiled->lockpath[0] = '\0';

    BEGIN_READ_ARGS(argc, argv);
    READ_ARG_ULONG("--fdcache", pfiled->maxfds);
    READ_ARG_STRING("--archip", pfiled->vpath, MAX_PATH_SIZE - 1);
    READ_ARG_STRING("--lockdir", pfiled->lockpath, MAX_PATH_SIZE - 1);
    READ_ARG_STRING("--prefix", pfiled->prefix, MAX_PREFIX_LEN);
    READ_ARG_STRING("--uniquestr", pfiled->uniquestr, MAX_UNIQUESTR_LEN);
    READ_ARG_BOOL("--directio", pfiled->directio);
    READ_ARG_BOOL("--pithos-migrate", pfiled->migrate);
    END_READ_ARGS();

    pfiled->uniquestr_len = strlen(pfiled->uniquestr);
    pfiled->prefix_len = strlen(pfiled->prefix);

    //TODO test path exist/is_dir/have_access
    pfiled->vpath_len = strlen(pfiled->vpath);
    if (!pfiled->vpath_len) {
        XSEGLOG2(&lc, E, "Archipelago path was not provided");
        usage(argv[0]);
        return -1;
    }
    if (pfiled->vpath[pfiled->vpath_len - 1] != '/') {
        pfiled->vpath[pfiled->vpath_len] = '/';
        pfiled->vpath[++pfiled->vpath_len] = '\0';
    }

    pfiled->lockpath_len = strlen(pfiled->lockpath);

    if (pfiled->lockpath_len &&
        pfiled->lockpath[pfiled->lockpath_len - 1] != '/') {
        pfiled->lockpath[pfiled->lockpath_len] = '/';
        pfiled->lockpath[++pfiled->lockpath_len] = '\0';
    }

    r = getrlimit(RLIMIT_NOFILE, &rlim);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Could not get limit for max fds");
        return -1;
    }
    //TODO check nr_ops == nr_threads.
    //
    r = xcache_init(&pfiled->cache, pfiled->maxfds, &c_ops, XCACHE_LRU_HEAP,
                    peer);
    if (r < 0) {
        return -1;
    }
    //check max fds. (> fdcache + nr_threads)
    //TODO assert fdcache > 2*nr_threads or add waitq
    if (rlim.rlim_cur < pfiled->cache.size + peer->nr_threads - 4) {
        XSEGLOG2(&lc, E, "FD limit %d is less than cachesize + nr_ops -4(%u)",
                 rlim.rlim_cur, pfiled->cache.size + peer->nr_ops - 4);
        return -1;
    }

  out:
    return ret;
}

void custom_peer_finalize(struct peerd *peer)
{
    /*
       we could close all fds, but we can let the system do it for us.
     */
    return;
}

/*
static int safe_atoi(char *s)
{
	long l;
	char *endp;

	l = strtol(s, &endp, 10);
	if (s != endp && *endp == '\0')
		return l;
	else
		return -1;
}
*/
