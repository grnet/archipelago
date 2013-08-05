/*
 * Copyright 2012 GRNET S.A. All rights reserved.
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

/*
 * The Pithos File Blocker Peer (pfiled)
 */

#define _GNU_SOURCE
#include <stdio.h>
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
#include <peer.h>
#include <xtypes/xcache.h>
#include <openssl/sha.h>
#include <sys/resource.h>

#include <xseg/xseg.h>
#include <xseg/protocol.h>

#include <hash.h>

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
                "\n"
               );
}

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
	uint32_t uniquestr_len;
	long maxfds;
	char vpath[MAX_PATH_SIZE + 1];
	char prefix[MAX_PREFIX_LEN + 1];
	char uniquestr[MAX_UNIQUESTR_LEN + 1];
	struct xcache cache;
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

struct pfiled * __get_pfiled(struct peerd *peer)
{
	return (struct pfiled *) peer->priv;
}

struct fio * __get_fio(struct peer_req *pr)
{
	return (struct fio*) pr->priv;
}


/* cache ops */
static void * cache_node_init(void *p, void *xh)
{
	//struct peerd *peer = (struct peerd *)p;
	//struct pfiled *pfiled = __get_pfiled(peer);
	xcache_handler h = *(xcache_handler *)(xh);
	struct fdcache_entry *fdentry = malloc(sizeof(struct fdcache_entry));
	if (!fdentry)
		return NULL;

	XSEGLOG2(&lc, D, "Initialing node h: %llu with %p",
			(long long unsigned)h, fdentry);

	fdentry->fd = -1;
	fdentry->flags = 0;

	return fdentry;
}

static int cache_init(void *p, void *e)
{
	struct fdcache_entry *fdentry = (struct fdcache_entry *)e;

	if (fdentry->fd != -1) {
		XSEGLOG2(&lc, E, "Found invalid fd %d", fdentry->fd);
		return -1;
	}

	return 0;
}

static void cache_put(void *p, void *e)
{
	struct fdcache_entry *fdentry = (struct fdcache_entry *)e;

	XSEGLOG2(&lc, D, "Putting entry %p with fd %d", fdentry, fdentry->fd);

	if (fdentry->fd != -1)
		close(fdentry->fd);

	fdentry->fd = -1;
	fdentry->flags = 0;
	return;
}

static void close_cache_entry(struct peerd *peer, struct peer_req *pr)
{
	struct pfiled *pfiled = __get_pfiled(peer);
	struct fio *fio = __get_fio(pr);
	if (fio->h != NoEntry)
		xcache_put(&pfiled->cache, fio->h);
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

static void get_dirs(char buf[6], struct pfiled *pfiled, char *target, uint32_t targetlen)
{
	unsigned char sha[SHA256_DIGEST_SIZE];
	char hex[HEXLIFIED_SHA256_DIGEST_SIZE];
	char *prefix = pfiled->prefix;
	uint32_t prefixlen = pfiled->prefix_len;

	if (strncmp(target, prefix, prefixlen)) {
		strncpy(buf, target, 6);
		return;
	}

	SHA256((unsigned char *)target, targetlen, sha);
	hexlify(sha, 3, hex);
	strncpy(buf, hex, 6);
	return;
}

static int create_path(char *buf, struct pfiled *pfiled, char *target,
			uint32_t targetlen, int mkdirs)
{
	int i;
	struct stat st;
	char dirs[6];
	char *path = pfiled->vpath;
	uint32_t pathlen = pfiled->vpath_len;

	get_dirs(dirs, pfiled, target, targetlen);

	strncpy(buf, path, pathlen);

	for (i = 0; i < 9; i+= 3) {
		buf[pathlen + i] = dirs[i - (i/3)];
		buf[pathlen + i +1] = dirs[i + 1 - (i/3)];
		buf[pathlen + i + 2] = '/';
		if (mkdirs == 1) {
			buf[pathlen + i + 3] = '\0';
retry:
			if (stat(buf, &st) < 0) 
				if (mkdir(buf, 0750) < 0) {
					if (errno == EEXIST)
						goto retry;
					//perror(buf);
					return -1;
				}
		}
	}

	strncpy(&buf[pathlen + 9], target, targetlen);
	buf[pathlen + 9 + targetlen] = '\0';

	return 0;
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
		 * 	assert targetlen >= prefix_len + 6
		 * else
		 * 	assert targetlen >= 6
		 */
		/* 6 chars are needed for the directory structrure */
		if (!pfiled->prefix_len || strncmp(target, pfiled->prefix, pfiled->prefix_len)) {
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

static int open_file_write(struct pfiled *pfiled, char *target, uint32_t targetlen)
{
	int r, fd;
	char tmp[XSEG_MAX_TARGETLEN + MAX_PATH_SIZE + 1];
	char error_str[1024];

	r = create_path(tmp, pfiled, target, targetlen, 1);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Could not create path");
		return -1;
	}
	XSEGLOG2(&lc, D, "Opening file %s with O_RDWR|O_CREAT", tmp);
	fd = open(tmp, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
	if (fd < 0){
		XSEGLOG2(&lc, E, "Could not open file %s. Error: %s", tmp, strerror_r(errno, error_str, 1023));
		return -1;
	}
	return fd;
}

static int open_file_read(struct pfiled *pfiled, char *target, uint32_t targetlen)
{
	int r, fd;
	char tmp[XSEG_MAX_TARGETLEN + MAX_PATH_SIZE + 1];
	char error_str[1024];

	r = create_path(tmp, pfiled, target, targetlen, 0);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Could not create path");
		return -1;
	}
	XSEGLOG2(&lc, D, "Opening file %s with O_RDWR", tmp);
	fd = open(tmp, O_RDWR, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
	if (fd < 0){
		XSEGLOG2(&lc, E, "Could not open file %s. Error: %s", tmp, strerror_r(errno, error_str, 1023));
		return -1;
	}
	return fd;
}

static int open_file(struct pfiled *pfiled, char *target, uint32_t targetlen, int mode)
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
	name[targetlen] = 0;
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
			XSEGLOG2(&lc, E, "Could not allocate cache entry for %s",
					name);
			goto out_err;
		}
		XSEGLOG2(&lc, D, "Allocated new handler %llu for %s",
				(long long unsigned)h, name);

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
				(long long unsigned)h, name);
		nh = xcache_insert(&pfiled->cache, h);
		if (nh != h) {
			XSEGLOG2(&lc, D, "Partial cache hit for %s. New handler %llu",
					name, (long long unsigned)nh);
			xcache_put(&pfiled->cache, h);
			h = nh;
		}
	} else {
		XSEGLOG2(&lc, D, "Cache hit for %s, handler: %llu", name,
				(long long unsigned)h);
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
	if (fd < 0){
		if (errno != ENOENT) {
			XSEGLOG2(&lc, E, "Open failed");
			pfiled_fail(peer, pr);
			return;
		} else {
			memset(data, 0, req->size);
			req->serviced = req->size;
			goto out;
		}
	}


	XSEGLOG2(&lc, D, "req->serviced: %llu, req->size: %llu", req->serviced,
			req->size);
	while (req->serviced < req->size) {
		XSEGLOG2(&lc, D, "req->serviced: %llu, req->size: %llu",
				req->serviced, req->size);
		r = pread(fd, data + req->serviced,
				req->size- req->serviced,
				req->offset + req->serviced);
		if (r < 0) {
			XSEGLOG2(&lc, E, "Cannot read");
			break;
		}
		else if (r == 0) {
			/* reached end of file. zero out the rest data buffer */
			memset(data + req->serviced, 0, req->size - req->serviced);
			req->serviced = req->size;
		}
		else {
			req->serviced += r;
		}
	}
	XSEGLOG2(&lc, D, "req->serviced: %llu, req->size: %llu", req->serviced,
			req->size);

out:
	if (req->serviced > 0 ) {
		XSEGLOG2(&lc, I, "Handle read completed for pr: %p, req: %p",
				pr, pr->req);
		pfiled_complete(peer, pr);
	}
	else {
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
	int r, fd;
	char *target = xseg_get_target(peer->xseg, req);
	char *data = xseg_get_data(peer->xseg, req);

	XSEGLOG2(&lc, I, "Handle write started for pr: %p, req: %p", pr, pr->req);

	if (req->datalen < req->size) {
		XSEGLOG2(&lc, E, "Request datalen is less than request size");
		pfiled_fail(peer, pr);
		return;
	}

	fd = dir_open(pfiled, fio, target, req->targetlen, WRITE);
	if (fd < 0){
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
	while (req->serviced < req->size) {
		XSEGLOG2(&lc, D, "req->serviced: %llu, req->size: %llu",
				req->serviced, req->size);
		r = pwrite(fd, data + req->serviced,
				req->size- req->serviced,
				req->offset + req->serviced);
		if (r < 0) {
			break;
		}
		else {
			req->serviced += r;
		}
	}
	XSEGLOG2(&lc, D, "req->serviced: %llu, req->size: %llu", req->serviced,
			req->size);
	r = fsync(fd);
	if (r< 0) {
		XSEGLOG2(&lc, E, "Fsync failed.");
		/* if fsync fails, then no bytes serviced correctly */
		req->serviced = 0;
	}

	if (req->serviced > 0 ) {
		XSEGLOG2(&lc, I, "Handle write completed for pr: %p, req: %p",
				pr, pr->req);
		pfiled_complete(peer, pr);
	}
	else {
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
	struct xseg_reply_info *xinfo  = (struct xseg_reply_info *)data;

	if (req->datalen < sizeof(struct xseg_reply_info)) {
		strncpy(buf, target, req->targetlen);
		r = xseg_resize_request(peer->xseg, req, req->targetlen, sizeof(struct xseg_reply_info));
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

	size = (uint64_t)stat.st_size;
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
	struct xseg_request_copy *xcopy = (struct xseg_request_copy *)data;
	struct stat st;
	char *buf = malloc(MAX_PATH_SIZE + MAX_FILENAME_SIZE);
	int src = -1, dst = -1, r = -1;
	ssize_t c = 0, bytes;

	XSEGLOG2(&lc, I, "Handle copy started for pr: %p, req: %p", pr, pr->req);
	if (!buf){
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

	r = create_path(buf, pfiled, xcopy->target, xcopy->targetlen, 0);
	if (r < 0)  {
		XSEGLOG2(&lc, E, "Create path failed");
		r = -1;
		goto out;
	}

	src = open(buf, O_RDONLY);
	if (src < 0) {
		XSEGLOG2(&lc, E, "fail in src %s", buf);
		r = src;
		goto out;
	}

	r = fstat(src, &st);
	if (r < 0){
		XSEGLOG2(&lc, E, "fail in stat for src %s", buf);
		goto out;
	}

	c = 0;
	while (c < st.st_size) {
		bytes = sendfile(dst, src, NULL, st.st_size - c);
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
	if (src > 0)
		close(src);
	free(buf);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Handle copy failed for pr: %p, req: %p", pr, pr->req);
		pfiled_fail(peer, pr);
	} else {
		XSEGLOG2(&lc, I, "Handle copy completed for pr: %p, req: %p", pr, pr->req);
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

	if (!buf){
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
	if (r< 0) {
		XSEGLOG2(&lc, E, "Create path failed");
		goto out;
	}
	r = unlink(buf);
out:
	free(buf);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Handle delete failed for pr: %p, req: %p", pr, pr->req);
		pfiled_fail(peer, pr);
	} else {
		strncpy(name, target, XSEG_MAX_TARGETLEN);
		name[XSEG_MAX_TARGETLEN] = 0;
		xcache_invalidate(&pfiled->cache, name);
		XSEGLOG2(&lc, I, "Handle delete completed for pr: %p, req: %p", pr, pr->req);
		pfiled_complete(peer, pr);
	}
	return;
}

static int __get_precalculated_hash(struct peerd *peer, char *target,
		uint32_t targetlen, char hash[HEXLIFIED_SHA256_DIGEST_SIZE + 1])
{
	int ret = -1;
	int r, fd;
	uint32_t len, pos;
	char *hash_file = NULL, *hash_path = NULL;
	char tmpbuf[HEXLIFIED_SHA256_DIGEST_SIZE];
	struct pfiled *pfiled = __get_pfiled(peer);

	XSEGLOG2(&lc, D, "Started.");

	hash_file = malloc(MAX_FILENAME_SIZE + 1);
	hash_path = malloc(MAX_PATH_SIZE + MAX_FILENAME_SIZE + 1);

	pos = 0;
	strncpy(hash_file+pos, target, targetlen);
	pos += targetlen;
	strncpy(hash_file+pos, HASH_SUFFIX, HASH_SUFFIX_LEN);
	pos += HASH_SUFFIX_LEN;
	hash_file[pos] = 0;
	hash[0] = 0;

	r = create_path(hash_path, pfiled, hash_file, pos, 1);
	if (r < 0)  {
		XSEGLOG2(&lc, E, "Create path failed");
		goto out;
	}

	fd = open(hash_path, O_RDONLY, S_IRWXU | S_IRUSR);
	if (fd < 0) {
		if (errno != ENOENT){
			XSEGLOG2(&lc, E, "Error opening %s", hash_path);
		} else {
			XSEGLOG2(&lc, I, "No precalculated hash for %s", hash_file);
			ret = 0;
		}
		goto out;
	}

	r = pread(fd, tmpbuf, HEXLIFIED_SHA256_DIGEST_SIZE, 0);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Error reading from %s", hash_path);
		close(fd);
		goto out;
	}
	len = (uint32_t)r;

	XSEGLOG2(&lc, D, "Read %u bytes", len);

	r = close(fd);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Could not close hash_file %s", hash_path);
		goto out;
	}

	if (len == HEXLIFIED_SHA256_DIGEST_SIZE){
		strncpy(hash, tmpbuf, HEXLIFIED_SHA256_DIGEST_SIZE);
		hash[HEXLIFIED_SHA256_DIGEST_SIZE] = 0;
		XSEGLOG2(&lc, D, "Found hash for %s : %s", hash_file, hash);
		ret = 0;
	}
out:
	free(hash_path);
	XSEGLOG2(&lc, D, "Finished.");
	return ret;
}

static int __set_precalculated_hash(struct peerd *peer, char *target,
		uint32_t targetlen, char hash[HEXLIFIED_SHA256_DIGEST_SIZE + 1])
{
	int ret = -1;
	int r, fd;
	uint32_t len, pos;
	char *hash_file = NULL, *hash_path = NULL;
	char tmpbuf[HEXLIFIED_SHA256_DIGEST_SIZE];
	struct pfiled *pfiled = __get_pfiled(peer);

	XSEGLOG2(&lc, D, "Started.");

	hash_file = malloc(MAX_FILENAME_SIZE + 1);
	hash_path = malloc(MAX_PATH_SIZE + MAX_FILENAME_SIZE + 1);

	pos = 0;
	strncpy(hash_file+pos, target, targetlen);
	pos += targetlen;
	strncpy(hash_file+pos, HASH_SUFFIX, HASH_SUFFIX_LEN);
	pos += HASH_SUFFIX_LEN;
	hash_file[pos] = 0;

	r = create_path(hash_path, pfiled, hash_file, pos, 1);
	if (r < 0)  {
		XSEGLOG2(&lc, E, "Create path failed");
		goto out;
	}

	fd = open(hash_path, O_WRONLY | O_CREAT | O_EXCL, S_IRWXU | S_IRUSR);
	if (fd < 0) {
		if (errno != ENOENT){
			XSEGLOG2(&lc, E, "Error opening %s", hash_path);
		} else {
			XSEGLOG2(&lc, I, "Hash file already exists %s", hash_file);
			ret = 0;
		}
		goto out;
	}

	r = pwrite(fd, hash, HEXLIFIED_SHA256_DIGEST_SIZE, 0);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Error reading from %s", hash_path);
		close(fd);
		goto out;
	}
	len = (uint32_t)r;

	XSEGLOG2(&lc, D, "Wrote %u bytes", len);

	r = close(fd);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Could not close hash_file %s", hash_path);
		goto out;
	}

out:
	free(hash_path);
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

	int src = -1, dst = -1, r = -1, pos;
	ssize_t c;
	uint64_t sum, written, trailing_zeros;
	struct pfiled *pfiled = __get_pfiled(peer);
	struct fio *fio = __get_fio(pr);
	struct xseg_request *req = pr->req;
	char *pathname = NULL, *tmpfile_pathname = NULL, *tmpfile = NULL;
	char *target;
	char hash_name[HEXLIFIED_SHA256_DIGEST_SIZE + 1];
	char name[XSEG_MAX_TARGETLEN + 1];

	unsigned char *object_data = NULL;
	unsigned char sha[SHA256_DIGEST_SIZE];
	struct xseg_reply_hash *xreply;

	target = xseg_get_target(peer->xseg, req);

	XSEGLOG2(&lc, I, "Handle hash started for pr: %p, req: %p",
			pr, pr->req);

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

	r = __get_precalculated_hash(peer, target, req->targetlen, hash_name);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Error getting precalculated hash");
		goto out;
	}

	if (hash_name[0] != 0) {
		XSEGLOG2(&lc, I, "Precalucated hash found %s", hash_name);
		goto found;
	}

	XSEGLOG2(&lc, I, "No precalculated hash found");

	strncpy(name, target, req->targetlen);
	name[req->targetlen] = 0;

	pathname = malloc(MAX_PATH_SIZE + MAX_FILENAME_SIZE + 1);
	object_data = malloc(sizeof(char) * req->size);
	if (!pathname || !object_data){
		XSEGLOG2(&lc, E, "Out of memory");
		goto out;
	}

	src = dir_open(pfiled, fio, target, req->targetlen, READ);
	if (src < 0) {
		XSEGLOG2(&lc, E, "Fail in src");
		r = dst;
		goto out;
	}

	sum = 0;
	while (sum < req->size) {
		c = pread(src, object_data + sum, req->size - sum, sum);
		if (c < 0) {
			XSEGLOG2(&lc, E, "Error reading from source");
			r = -1;
			goto out;
		}
		if (c == 0) {
			break;
		}
		sum += c;
	}

	//rstrip here in case zeros were written in the end
	trailing_zeros = 0;
	for (;trailing_zeros < sum; trailing_zeros++)
		if (object_data[sum - trailing_zeros - 1])
			break;

	XSEGLOG2(&lc, D, "Read %llu, Trainling zeros %llu",
			sum, trailing_zeros);

	sum -= trailing_zeros;
	//calculate hash name
	SHA256(object_data, sum, sha);

	hexlify(sha, SHA256_DIGEST_SIZE, hash_name);
	hash_name[HEXLIFIED_SHA256_DIGEST_SIZE] = 0;


	r = create_path(pathname, pfiled, hash_name, HEXLIFIED_SHA256_DIGEST_SIZE, 1);
	if (r < 0)  {
		XSEGLOG2(&lc, E, "Create path failed");
		r = -1;
		goto out;
	}



	dst = open(pathname, O_WRONLY);
	if (dst > 0) {
		XSEGLOG2(&lc, I, "%s already exists, no write needed", pathname);
		req->serviced = req->size;
		r = 0;
		goto out;
	}

	tmpfile_pathname = malloc(MAX_PATH_SIZE + MAX_FILENAME_SIZE + 1);
	if (!tmpfile_pathname){
		XSEGLOG2(&lc, E, "Out of memory");
		r = -1;
		goto out;
	}

	tmpfile = malloc(MAX_FILENAME_SIZE);
	if (!tmpfile){
		XSEGLOG2(&lc, E, "Out of memory");
		r = -1;
		goto out;
	}

	pos = 0;
	strncpy(tmpfile + pos, target, req->targetlen);
	pos += req->targetlen;
	strncpy(tmpfile + pos, SNAP_SUFFIX, SNAP_SUFFIX_LEN);
	pos += SNAP_SUFFIX_LEN;
	strncpy(tmpfile + pos, pfiled->uniquestr, pfiled->uniquestr_len);
	pos += pfiled->uniquestr_len;
	strncpy(tmpfile + pos, fio->str_id, FIO_STR_ID_LEN);
	pos += FIO_STR_ID_LEN;
	tmpfile[pos] = 0;

	r = create_path(tmpfile_pathname, pfiled, tmpfile, pos, 1);
	if (r < 0)  {
		XSEGLOG2(&lc, E, "Create path failed");
		r = -1;
		goto out;
	}

	XSEGLOG2(&lc, D, "Opening %s", tmpfile_pathname);
	dst = open(tmpfile_pathname, O_WRONLY | O_CREAT | O_EXCL,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (dst < 0) {
		if (errno != EEXIST){
			char error_str[1024];
			XSEGLOG2(&lc, E, "Error opening %s (%s)", tmpfile_pathname, strerror_r(errno, error_str, 1023));
		} else {
			XSEGLOG2(&lc, E, "Error opening %s. Stale data found.",
					tmpfile_pathname);
		}
		r = -1;
		goto out;
	}
	XSEGLOG2(&lc, D, "Opened %s", tmpfile_pathname);

	written = 0;
	while (written < sum) {
		c = write(dst, object_data + written, sum - written);
		if (c < 0) {
			XSEGLOG2(&lc, E, "Error writting to dst file %s", tmpfile_pathname);
			r = -1;
			goto out_unlink;
		}
		written += c;
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
	if (r < 0)  {
		XSEGLOG2(&lc, E, "Resize request failed");
		r = -1;
		goto out;
	}

	xreply = (struct xseg_reply_hash *)xseg_get_data(peer->xseg, req);
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

static int __locked_by(char *lockfile, char *expected, uint32_t expected_len)
{
	int ret = -1;
	int r, fd;
	uint32_t len;
	char tmpbuf[MAX_UNIQUESTR_LEN];

	XSEGLOG2(&lc, D, "Started. Lockfile: %s, expected: %s, expected_len: %u", lockfile, expected, expected_len);
	fd = open(lockfile, O_RDONLY, S_IRWXU | S_IRUSR);
	if (fd < 0) {
		if (errno != ENOENT){
			XSEGLOG2(&lc, E, "Error opening %s", lockfile);
		} else {
			//-2 == retry
			XSEGLOG2(&lc, I, "lock file removed");
			ret = -2;
		}
		goto out;
	}
	r = pread(fd, tmpbuf, MAX_UNIQUESTR_LEN, 0);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Error reading from %s", lockfile);
		close(fd);
		goto out;
	}
	len = (uint32_t)r;
	XSEGLOG2(&lc, D, "Read %u bytes", len);
	r = close(fd);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Could not close lockfile %s", lockfile);
		goto out;
	}
	if (len == expected_len && !strncmp(tmpbuf, expected, expected_len)){
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
	int r;
	XSEGLOG2(&lc, D, "Started. Lockfile: %s, Tmpfile:%s", lockfile, tmpfile);
	r = pwrite(fd, pfiled->uniquestr, pfiled->uniquestr_len, 0);
	if (r < 0) {
		return -1;
	}
	r = fsync(fd);
	if (r < 0) {
		return -1;
	}

	while (link(tmpfile, lockfile) < 0) {
		//actual error
		if (errno != EEXIST){
			XSEGLOG2(&lc, E, "Error linking %s to %s",
					tmpfile, lockfile);
			return -1;
		}
		r = __locked_by(lockfile, pfiled->uniquestr, pfiled->uniquestr_len);
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
	char *lockfile_pathname = malloc(MAX_PATH_SIZE + MAX_FILENAME_SIZE);
	char *tmpfile_pathname = malloc(MAX_PATH_SIZE + MAX_FILENAME_SIZE);
	int fd = -1, pos;
	char *target = xseg_get_target(peer->xseg, req);
	uint32_t buf_len, tmpfile_len;

	if (!buf || !tmpfile_pathname || !lockfile_pathname) {
		XSEGLOG2(&lc, E, "Out of memory");
		pfiled_fail(peer, pr);
		return;
	}

	r = is_target_valid_len(pfiled, target, req->targetlen, READ);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Target not valid");
		goto out;
	}


	pos = 0;
	strncpy(buf + pos, target, req->targetlen);
	pos = req->targetlen;
	strncpy(buf + pos, LOCK_SUFFIX, LOCK_SUFFIX_LEN);
	pos += LOCK_SUFFIX_LEN;
	buf[pos] = 0;
	buf_len = pos;

	XSEGLOG2(&lc, I, "Started. Lockfile: %s", buf);


	pos = 0;
	strncpy(tmpfile + pos, buf, buf_len);
	pos += buf_len;
	strncpy(tmpfile + pos, pfiled->uniquestr, pfiled->uniquestr_len);
	pos += pfiled->uniquestr_len;
	strncpy(tmpfile + pos, fio->str_id, FIO_STR_ID_LEN);
	pos += FIO_STR_ID_LEN;
	tmpfile[pos] = 0;
	tmpfile_len = pos;

	XSEGLOG2(&lc, I, "Trying to acquire lock %s", buf);

	if (create_path(tmpfile_pathname, pfiled, tmpfile, tmpfile_len, 1) < 0) {
		XSEGLOG2(&lc, E, "Create path failed for %s", buf);
		goto out;
	}

	if (create_path(lockfile_pathname, pfiled, buf, buf_len, 1) < 0) {
		XSEGLOG2(&lc, E, "Create path failed for %s", buf);
		goto out;
	}

	//create exclusive unique lockfile (block_uniqueid+target)
	//if (OK)
	//	write blocker uniqueid to the unique lockfile
	//	try to link it to the lockfile
	//	if (OK)
	//		unlink unique lockfile;
	//		complete
	//	else
	//		spin while not able to link

	//nfs v >= 3
	XSEGLOG2(&lc, D, "Tmpfile: %s", tmpfile_pathname);
	fd = open(tmpfile_pathname, O_WRONLY | O_CREAT | O_EXCL, S_IRWXU | S_IRUSR);
	if (fd < 0) {
		//actual error
		if (errno != EEXIST){
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
		if (r < 0){
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
	if (ret < 0){
		XSEGLOG2(&lc, I, "Failed to acquire lock %s", buf);
		pfiled_fail(peer, pr);
	}
	else{
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
//	struct fio *fio = __get_fio(pr);
	struct xseg_request *req = pr->req;
	char *buf = malloc(MAX_FILENAME_SIZE + 1);
	char *pathname = malloc(MAX_PATH_SIZE + MAX_FILENAME_SIZE + 1);
	char *tmpbuf = malloc(MAX_UNIQUESTR_LEN + 1);
	char *target = xseg_get_target(peer->xseg, req);
	int r, pos;

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

	pos = 0;
	strncpy(buf + pos, target, req->targetlen);
	pos += req->targetlen;
	strncpy(buf + pos, LOCK_SUFFIX, LOCK_SUFFIX_LEN);
	pos += LOCK_SUFFIX_LEN;
	buf[pos] = 0;

	XSEGLOG2(&lc, I, "Started. Lockfile: %s", buf);

	r = create_path(pathname, pfiled, buf,
			req->targetlen + strlen(LOCK_SUFFIX), 0);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Create path failed for %s", buf);
		goto out;
	}

	if ((req->flags & XF_FORCE) || !__locked_by(pathname, pfiled->uniquestr,
						pfiled->uniquestr_len)) {
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
	}
	else {
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
	if (reason == dispatch_accept)
		fio->h = NoEntry;

	switch (req->op) {
		case X_READ:
			handle_read(peer, pr); break;
		case X_WRITE:
			handle_write(peer, pr); break;
		case X_INFO:
			handle_info(peer, pr); break;
		case X_COPY:
			handle_copy(peer, pr); break;
		case X_DELETE:
			handle_delete(peer, pr); break;
		case X_ACQUIRE:
			handle_acquire(peer, pr); break;
		case X_RELEASE:
			handle_release(peer, pr); break;
		case X_HASH:
			handle_hash(peer, pr); break;
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
	if (!pfiled){
		XSEGLOG2(&lc, E, "Out of memory");
		ret = -ENOMEM;
		goto out;
	}
	peer->priv = pfiled;

	pfiled->maxfds = 2 * peer->nr_ops;

	for (i = 0; i < peer->nr_ops; i++) {
		peer->peer_reqs[i].priv = malloc(sizeof(struct fio));
		if (!peer->peer_reqs->priv){
			XSEGLOG2(&lc, E, "Out of memory");
			ret = -ENOMEM;
			goto out;
		}
		fio = __get_fio(&peer->peer_reqs[i]);
		fio->str_id[0] = '_';
		fio->str_id[1] = 'a' + (i / 26);
		fio->str_id[2] = 'a' + (i % 26);
	}

	pfiled->vpath[0] = 0;
	pfiled->prefix[0] = 0;
	pfiled->uniquestr[0] = 0;

	BEGIN_READ_ARGS(argc, argv);
	READ_ARG_ULONG("--fdcache", pfiled->maxfds);
	READ_ARG_STRING("--archip", pfiled->vpath, MAX_PATH_SIZE);
	READ_ARG_STRING("--prefix", pfiled->prefix, MAX_PREFIX_LEN);
	READ_ARG_STRING("--uniquestr", pfiled->uniquestr, MAX_UNIQUESTR_LEN);
	END_READ_ARGS();

	pfiled->uniquestr_len = strlen(pfiled->uniquestr);
	pfiled->prefix_len = strlen(pfiled->prefix);

	//TODO test path exist/is_dir/have_access
	pfiled->vpath_len = strlen(pfiled->vpath);
	if (!pfiled->vpath_len){
		XSEGLOG2(&lc, E, "Archipelago path was not provided");
		usage(argv[0]);
		return -1;
	}
	if (pfiled->vpath[pfiled->vpath_len -1] != '/'){
		pfiled->vpath[pfiled->vpath_len] = '/';
		pfiled->vpath[++pfiled->vpath_len]= 0;
	}

	r = getrlimit(RLIMIT_NOFILE, &rlim);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Could not get limit for max fds");
		return -1;
	}
	//check max fds. (> fdcache + nr_ops)
	//TODO assert fdcache > 2*nr_ops or add waitq
	if (rlim.rlim_cur < pfiled->maxfds + peer->nr_ops - 4) {
		XSEGLOG2(&lc, E, "FD limit %d is less than fdcache + nr_ops -4(%u)",
				rlim.rlim_cur, pfiled->maxfds + peer->nr_ops - 4);
		return -1;
	}
	r = xcache_init(&pfiled->cache, pfiled->maxfds, &c_ops, XCACHE_LRU_HEAP, peer);
	if (r < 0)
		return -1;

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
