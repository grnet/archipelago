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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <xseg/xseg.h>
#include <peer.h>
#include <time.h>
#include <xseg/protocol.h>
#include <hash.h>
#include <mapper.h>
#include <mapper-versions.h>
#include <xseg/xhash.h>
#include <asm/byteorder.h>


#define NO_V0SIZE ((uint64_t)-1)

static uint32_t nr_reqs = 0;
static uint32_t waiters_for_req = 0;
st_cond_t req_cond;
char buf[XSEG_MAX_TARGETLEN + 1];



char * null_terminate(char *target, uint32_t targetlen)
{
	if (targetlen > XSEG_MAX_TARGETLEN)
		return NULL;
	strncpy(buf, target, targetlen);
	buf[targetlen] = 0;
	return buf;
}

int __set_node(struct mapper_io *mio, struct xseg_request *req,
			struct map_node *mn)
{
	int r = 0;
	if (mn){
		XSEGLOG2(&lc, D, "Inserting (req: %lx, mapnode: %lx) on mio %lx",
				req, mn, mio);
		r = xhash_insert(mio->copyups_nodes, (xhashidx) req, (xhashidx) mn);
		if (r == -XHASH_ERESIZE) {
			xhashidx shift = xhash_grow_size_shift(mio->copyups_nodes);
			xhash_t *new_hashmap = xhash_resize(mio->copyups_nodes, shift, 0, NULL);
			if (!new_hashmap)
				return -1;
			mio->copyups_nodes = new_hashmap;
			r = xhash_insert(mio->copyups_nodes, (xhashidx) req, (xhashidx) mn);
		}
		if (r < 0)
			XSEGLOG2(&lc, E, "Insertion of (%lx, %lx) on mio %lx failed",
					req, mn, mio);
	}
	else {
		XSEGLOG2(&lc, D, "Deleting req: %lx from mio %lx",
				req, mio);
		r = xhash_delete(mio->copyups_nodes, (xhashidx) req);
		if (r == -XHASH_ERESIZE) {
			xhashidx shift = xhash_shrink_size_shift(mio->copyups_nodes);
			xhash_t *new_hashmap = xhash_resize(mio->copyups_nodes, shift, 0, NULL);
			if (!new_hashmap)
				return -1;
			mio->copyups_nodes = new_hashmap;
			r = xhash_delete(mio->copyups_nodes, (xhashidx) req);
		}
		else if (r == -XHASH_ENOENT) {
			XSEGLOG2(&lc, W, "%lx not found on mio %lx", req, mio);
			return -1;
		}
		if (r < 0)
			XSEGLOG2(&lc, E, "Deletion of %lx on mio %lx failed",
					req, mio);
	}
	return r;
}

struct map_node * __get_node(struct mapper_io *mio, struct xseg_request *req)
{
	struct map_node *mn;
	int r = xhash_lookup(mio->copyups_nodes, (xhashidx) req, (xhashidx *) &mn);
	if (r < 0){
		XSEGLOG2(&lc, W, "Cannot find req %lx on mio %lx", req, mio);
		return NULL;
	}
	XSEGLOG2(&lc, D, "Found mapnode %lx req %lx on mio %lx", mn, req, mio);
	return mn;
}

int send_request(struct peer_req *pr, struct xseg_request *req)
{
	int r;
	struct peerd *peer = pr->peer;
	void *dummy;

	r = xseg_set_req_data(peer->xseg, req, pr);
	if (r < 0){
		XSEGLOG2(&lc, E, "Cannot set request data for req %p, pr: %p",
				req, pr);
		return -1;
	}
	xport p = xseg_submit(peer->xseg, req, pr->portno, X_ALLOC);
	if (p == NoPort){
		XSEGLOG2(&lc, E, "Cannot submit request %p, pr: %p",
				req, pr);
		xseg_get_req_data(peer->xseg, req, &dummy);
		return -1;
	}
	r = xseg_signal(peer->xseg, p);
	if (r < 0)
		XSEGLOG2(&lc, W, "Cannot signal port %u", p);

	return 0;
}

#define wait_for_req() \
	do{ \
		ta--; \
		waiters_for_req++; \
		XSEGLOG2(&lc, D, "Waiting for request. Waiters: %u", \
				waiters_for_req); \
		st_cond_wait(req_cond); \
	}while(0)

#define signal_one_req() \
	do { \
		if (waiters_for_req) { \
			ta++; \
			waiters_for_req--; \
			XSEGLOG2(&lc, D, "Siganling one request. Waiters: %u", \
					waiters_for_req); \
			st_cond_signal(req_cond); \
		} \
	}while(0)

struct xseg_request * get_request(struct peer_req *pr, xport dst, char *target,
		uint32_t targetlen, uint64_t datalen)
{
	int r;
	struct peerd *peer = pr->peer;
	struct xseg_request *req;
	char *reqtarget;
retry:
	req = xseg_get_request(peer->xseg, pr->portno, dst, X_ALLOC);
	if (!req){
		if (!nr_reqs) {
			XSEGLOG2(&lc, E, "Cannot allocate request for target %s",
					null_terminate(target, targetlen));
			return NULL;
		} else {
			wait_for_req();
			goto retry;
		}
	}
	r = xseg_prep_request(peer->xseg, req, targetlen, datalen);
	if (r < 0){
		xseg_put_request(peer->xseg, req, pr->portno);
		if (!nr_reqs) {
			XSEGLOG2(&lc, E, "Cannot prepare request for target",
					null_terminate(target, targetlen));
			return NULL;
		} else {
			wait_for_req();
			goto retry;
		}
	}

	reqtarget = xseg_get_target(peer->xseg, req);
	if (!reqtarget){
		xseg_put_request(peer->xseg, req, pr->portno);
		return NULL;
	}
	strncpy(reqtarget, target, req->targetlen);

	nr_reqs++;
	return req;
}

void put_request(struct peer_req *pr, struct xseg_request *req)
{
	struct peerd *peer = pr->peer;
	xseg_put_request(peer->xseg, req, pr->portno);
	nr_reqs--;
	signal_one_req();
}

struct xseg_request * __close_map(struct peer_req *pr, struct map *map)
{
	int r;
	struct peerd *peer = pr->peer;
	struct xseg_request *req;
	struct mapperd *mapper = __get_mapperd(peer);

	XSEGLOG2(&lc, I, "Closing map %s", map->volume);

	req = get_request(pr, mapper->mbportno, map->volume, map->volumelen, 0);
	if (!req){
		XSEGLOG2(&lc, E, "Cannot get request for map %s",
				map->volume);
		goto out_err;
	}

	req->op = X_RELEASE;
	req->size = 0;
	req->offset = 0;
	r = send_request(pr, req);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Cannot send request %p, pr: %p, map: %s",
				req, pr, map->volume);
		goto out_put;
	}


	XSEGLOG2(&lc, I, "Map %s closing", map->volume);
	return req;

out_put:
	put_request(pr, req);
out_err:
	return NULL;
}

int close_map(struct peer_req *pr, struct map *map)
{
	int err;
	struct xseg_request *req;

	map->state |= MF_MAP_CLOSING;
	req = __close_map(pr, map);
	if (!req) {
		map->state &= ~MF_MAP_CLOSING;
		return -1;
	}

	wait_on_pr(pr, (!((req->state & XS_FAILED)||(req->state & XS_SERVED))));
	map->state &= ~MF_MAP_CLOSING;
	err = req->state & XS_FAILED;
	put_request(pr, req);
	if (err)
		return -1;
	else
		map->state &= ~MF_MAP_EXCLUSIVE;
	return 0;
}

struct xseg_request * __open_map(struct peer_req *pr, struct map *map,
						uint32_t flags)
{
	int r;
	struct xseg_request *req;
	struct peerd *peer = pr->peer;
	struct mapperd *mapper = __get_mapperd(peer);

	XSEGLOG2(&lc, I, "Opening map %s", map->volume);

	req = get_request(pr, mapper->mbportno, map->volume, map->volumelen, 0);
	if (!req){
		XSEGLOG2(&lc, E, "Cannot get request for map %s",
				map->volume);
		goto out_err;
	}

	req->op = X_ACQUIRE;
	req->size = MAPPER_DEFAULT_BLOCKSIZE;
	req->offset = 0;
	if (!(flags & MF_FORCE))
		req->flags = XF_NOSYNC;

	r = send_request(pr, req);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Cannot send request %p, pr: %p, map: %s",
				req, pr, map->volume);
		goto out_put;
	}

	map->state |= MF_MAP_OPENING;
	XSEGLOG2(&lc, I, "Map %s opening", map->volume);
	return req;

out_put:
	put_request(pr, req);
out_err:
	return NULL;
}

int open_map(struct peer_req *pr, struct map *map, uint32_t flags)
{
	int err;
	struct xseg_request *req;
	struct mapper_io *mio = __get_mapper_io(pr);

	req = __open_map(pr, map, flags);
	if (!req){
		return -1;
	}
	wait_on_pr(pr, (!((req->state & XS_FAILED)||(req->state & XS_SERVED))));
	map->state &= ~MF_MAP_OPENING;
	err = req->state & XS_FAILED;
	put_request(pr, req);
	if (err)
		return -1;
	else {
		map->state |= MF_MAP_EXCLUSIVE;
		map->opened_count = mio->count;
	}
	return 0;
}

struct xseg_request * __write_map_metadata(struct peer_req *pr, struct map *map)
{
	struct peerd *peer = pr->peer;
	struct mapperd *mapper = __get_mapperd(peer);
	struct xseg_request *req;
	char *data;
	uint64_t pos;
	int r;
	struct header_struct hdr;
	uint32_t header_size = 0;


	switch (map->version) {
		case MAP_V0:
			write_map_header_v0(map, (struct v0_header_struct *)&hdr);
			header_size = v0_mapheader_size;
			break;
		case MAP_V1:
			write_map_header_v1(map, (struct v1_header_struct *)&hdr);
			header_size = v1_mapheader_size;
			break;
		case MAP_V2:
			write_map_header_v2(map, (struct v2_header_struct *)&hdr);
			header_size = v2_mapheader_size;
			break;
		default:
			XSEGLOG2(&lc, E, "Invalid version %u found", map->version);
			goto out_err;
	}
	if (!header_size) {
		goto out;
	}

	req = get_request(pr, mapper->mbportno, map->volume, map->volumelen,
			header_size);
	if (!req){
		XSEGLOG2(&lc, E, "Cannot get request for map %s", map->volume);
		goto out_err;
	}


	req->op = X_WRITE;
	req->size = header_size;
	req->offset = 0;
	data = xseg_get_data(peer->xseg, req);
	memcpy(data, &hdr, header_size);

	r = send_request(pr, req);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Cannot send request %p, pr: %p, map: %s",
				req, pr, map->volume);
		goto out_put;
	}
out:
	return req;

out_put:
	put_request(pr, req);
out_err:
	return NULL;
}

int write_map_metadata(struct peer_req *pr, struct map *map)
{
	int err;
	struct xseg_request *req;

	map->state |= MF_MAP_WRITING;
	req = __write_map_metadata(pr, map);
	if (!req) {
		map->state &= ~MF_MAP_WRITING;
		return -1;
	}
	wait_on_pr(pr, (!((req->state & XS_FAILED)||(req->state & XS_SERVED))));
	map->state &= ~MF_MAP_WRITING;
	err = req->state & XS_FAILED;
	put_request(pr, req);
	if (err)
		return -1;
	return 0;
}

/*
int write_map_data(struct peer_req *pr, struct map *map)
{
}
*/

int write_map(struct peer_req* pr, struct map *map)
{
	int r;
	map->state |= MF_MAP_WRITING;
	struct mapper_io *mio = __get_mapper_io(pr);

	mio->cb = NULL;
	mio->err = 0;

	r = map->mops->write_map_data(pr, map);
	if (r < 0) {
		map->state &= ~MF_MAP_WRITING;
		return r;
	}
	map->state &= ~MF_MAP_WRITING;

	return write_map_metadata(pr, map);
}


int delete_map_data(struct peer_req* pr, struct map *map)
{
	int r;
	map->state |= MF_MAP_DELETING;
	struct mapper_io *mio = __get_mapper_io(pr);

	mio->cb = NULL;
	mio->err = 0;

	r = map->mops->delete_map_data(pr, map);

	map->state &= ~MF_MAP_DELETING;
	return r;
}

struct xseg_request * __load_map_metadata(struct peer_req *pr, struct map *map)
{
	int r;
	struct xseg_request *req;
	struct peerd *peer = pr->peer;
	struct mapperd *mapper = __get_mapperd(peer);
	uint64_t datalen;

	XSEGLOG2(&lc, I, "Loading map metadata %s", map->volume);

	datalen = MAX_MAPHEADER_SIZE;
	req = get_request(pr, mapper->mbportno, map->volume, map->volumelen,
			datalen);
	if (!req){
		XSEGLOG2(&lc, E, "Cannot get request for map %s",
				map->volume);
		goto out_err;
	}


	req->op = X_READ;
	req->size = datalen;
	req->offset = 0;

	r = send_request(pr, req);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Cannot send request %p, pr: %p, map: %s",
				req, pr, map->volume);
		goto out_put;
	}

	XSEGLOG2(&lc, I, "Map %s loading metadata", map->volume);
	return req;

out_put:
	put_request(pr, req);
out_err:
	return NULL;
}

int load_map_metadata(struct peer_req *pr, struct map *map)
{
	int type, r = 0;
	struct xseg_request *req;
	struct peerd *peer = pr->peer;
	char *data;
	uint32_t version;
	uint32_t signature;
	uint32_t assume_v0 = pr->req->flags & XF_ASSUMEV0;
	uint32_t signature_on_disk;
	uint32_t version1_on_disk;


	req = __load_map_metadata(pr, map);
	if (!req) {
		goto out_err;
	}
	wait_on_pr(pr, (!(req->state & XS_FAILED || req->state & XS_SERVED)));
	if (req->state & XS_FAILED) {
		goto out_err;
	}
	if (req->serviced < req->size) {
		goto out_err;
	}

	data = xseg_get_data(peer->xseg, req);
	if (!data) {
		goto out_put;
	}

	signature_on_disk = __cpu_to_be32(MAP_SIGNATURE);
	version1_on_disk = __cpu_to_le32(MAP_V1);
	if (memcmp(data, &signature_on_disk, sizeof(MAP_SIGNATURE))) {
		if (assume_v0) {
			/* assume v0 */
			version = MAP_V0;
		} else if (!memcmp(data, &version1_on_disk, sizeof(uint32_t))) {
			version = MAP_V1;
		} else {
			XSEGLOG2(&lc, E, "No signature found");
			goto out_put;
		}
	} else {
		struct header_struct *hdr = (struct header_struct *)data;
		version = __be32_to_cpu(hdr->version);
	}

	switch (version) {
		case MAP_V0:
			r = read_map_header_v0(map, (struct v0_header_struct *)data);
			break;
		case MAP_V1:
			r = read_map_header_v1(map, (struct v1_header_struct *)data);
			break;
		case MAP_V2:
			r = read_map_header_v2(map, (struct v2_header_struct *)data);
			break;
		default:
			XSEGLOG2(&lc, E, "Loaded invalid version %u > "
					"latest version %u",
					version, MAP_LATEST_VERSION);
			goto out_put;
	}
	if (r < 0) {
		goto out_put;
	}

	put_request(pr, req);

	if (!is_valid_blocksize(map->blocksize)) {
		XSEGLOG2(&lc, E, "%s has Invalid blocksize %llu", map->volume,
				map->blocksize);
		goto out_err;
	}

	return 0;

out_put:
	put_request(pr, req);
out_err:
	XSEGLOG2(&lc, E, "Load map version for map %s failed", map->volume);
	return -1;
}

int load_map(struct peer_req *pr, struct map *map)
{
	//struct xseg_request *req;
	int r;
	uint32_t prev_version;
	struct map_ops *prev_mops;
	uint64_t v0_size = NO_V0SIZE;
	uint64_t nr_objs = 0;

	XSEGLOG2(&lc, I, "Loading map %s", map->volume);

	map->state |= MF_MAP_LOADING;

	r = load_map_metadata(pr, map);
	if (r < 0) {
		goto out_err;
	}
	XSEGLOG2(&lc, D, "Loaded map metadata. Found map version %u", map->version);
	r = map->mops->load_map_data(pr, map);
	if (r < 0)
		goto out_err;

	v0_size = pr->req->v0_size;
	if (map->version == MAP_V0 && v0_size != NO_V0SIZE) {
		nr_objs =__calc_map_obj(v0_size, MAPPER_DEFAULT_BLOCKSIZE);
		if (map->nr_objs != nr_objs) {
			XSEGLOG2(&lc, E, "Size of v0 map invalid. "
					"Read %llu objs vs %llu expected",
					map->nr_objs, nr_objs);
			goto out_err;
		} else {
			map->size = v0_size;
		}
	}

	if (map->version != MAP_LATEST_VERSION &&
			(map->state & MF_MAP_EXCLUSIVE)) {
		/* update map to the latest version */
		/* FIXME assert that all old map data are overwritten */
		prev_version = map->version;
		prev_mops = map->mops;
		map->version = MAP_LATEST_VERSION;
		map->mops = MAP_LATEST_MOPS;
		if (write_map(pr, map) < 0) {
			XSEGLOG2(&lc, E, "Could not update map %s to latest version",
					map->volume);
			map->version = prev_version;
			map->mops = prev_mops;
			goto out_err;
		}
	}

	map->state &= ~MF_MAP_LOADING;
	XSEGLOG2(&lc, I, "Loading map %s completed", map->volume);

	return 0;

out_err:
	XSEGLOG2(&lc, E, "Loading of map %s failed", map->volume);
	map->state &= ~MF_MAP_LOADING;
	return -1;
}


/*
struct xseg_request * __snapshot_object(struct peer_req *pr,
						struct map_node *mn)
{
	struct peerd *peer = pr->peer;
	struct mapperd *mapper = __get_mapperd(peer);
	struct mapper_io *mio = __get_mapper_io(pr);
	//struct map *map = mn->map;
	void *dummy;
	int r = -1;
	xport p;

	//assert mn->volume != zero_block
	//assert mn->flags & MF_OBJECT_WRITABLE
	struct xseg_request *req = xseg_get_request(peer->xseg, pr->portno,
						mapper->bportno, X_ALLOC);
	if (!req){
		XSEGLOG2(&lc, E, "Cannot get request for object %s", mn->object);
		goto out_err;
	}
	r = xseg_prep_request(peer->xseg, req, mn->objectlen,
				sizeof(struct xseg_request_snapshot));
	if (r < 0){
		XSEGLOG2(&lc, E, "Cannot prepare request for object %s", mn->object);
		goto out_put;
	}

	char *target = xseg_get_target(peer->xseg, req);
	strncpy(target, mn->object, req->targetlen);

	struct xseg_request_snapshot *xsnapshot = (struct xseg_request_snapshot *) xseg_get_data(peer->xseg, req);
	xsnapshot->target[0] = 0;
	xsnapshot->targetlen = 0;

	req->offset = 0;
	req->size = MAPPER_DEFAULT_BLOCKSIZE;
	req->op = X_SNAPSHOT;
	r = xseg_set_req_data(peer->xseg, req, pr);
	if (r<0){
		XSEGLOG2(&lc, E, "Cannot set request data for object %s", mn->object);
		goto out_put;
	}
	p = xseg_submit(peer->xseg, req, pr->portno, X_ALLOC);
	if (p == NoPort) {
		XSEGLOG2(&lc, E, "Cannot submit for object %s", mn->object);
		goto out_unset;
	}
	xseg_signal(peer->xseg, p);

	mn->flags |= MF_OBJECT_SNAPSHOTTING;
	XSEGLOG2(&lc, I, "Snapshotting up object %s", mn->object);
	return req;

out_unset:
	xseg_get_req_data(peer->xseg, req, &dummy);
out_put:
	xseg_put_request(peer->xseg, req, pr->portno);
out_err:
	XSEGLOG2(&lc, E, "Snapshotting object %s failed", mn->object);
	return NULL;
}
*/

struct xseg_request * __copyup_object(struct peer_req *pr, struct map_node *mn)
{
	struct peerd *peer = pr->peer;
	struct mapperd *mapper = __get_mapperd(peer);
	struct mapper_io *mio = __get_mapper_io(pr);
	struct map *map = mn->map;
	struct xseg_request *req;
	struct xseg_request_copy *xcopy;
	int r = -1;

	//assert !(mn->flags & MF_OBJECT_WRITABLE)

	uint32_t newtargetlen;
	char new_target[MAX_OBJECT_LEN + 1];
	char *tmp = new_target;
	char hexlified_epoch[HEXLIFIED_EPOCH];
	char hexlified_index[HEXLIFIED_INDEX];
	uint64_t be_epoch = __cpu_to_be64(map->epoch);
	uint64_t be_objectidx = __cpu_to_be64(mn->objectidx);

//	strncpy(new_target, MAPPER_PREFIX, MAPPER_PREFIX_LEN);

	hexlify((unsigned char *)&be_epoch, sizeof(be_epoch), hexlified_epoch);
	hexlify((unsigned char *)&be_objectidx, sizeof(be_objectidx), hexlified_index);
	strncpy(tmp, map->volume, map->volumelen);
	tmp += map->volumelen;
	strncpy(tmp, "_", 1);
	tmp += 1;
	strncpy(tmp, hexlified_epoch, HEXLIFIED_EPOCH);
	tmp += HEXLIFIED_EPOCH;
	strncpy(tmp, "_", 1);
	tmp += 1;
	strncpy(tmp, hexlified_index, HEXLIFIED_INDEX);
	tmp += HEXLIFIED_INDEX;
	*tmp = 0;
	newtargetlen = tmp - new_target;
	XSEGLOG2(&lc, D, "New target: %s (len: %d)", new_target, newtargetlen);

	if (!strncmp(mn->object, zero_block, ZERO_BLOCK_LEN))
		goto copyup_zeroblock;

	req = get_request(pr, mapper->bportno, new_target, newtargetlen,
			sizeof(struct xseg_request_copy));

	xcopy = (struct xseg_request_copy *) xseg_get_data(peer->xseg, req);
	strncpy(xcopy->target, mn->object, mn->objectlen);
	xcopy->targetlen = mn->objectlen;

	req->offset = 0;
	req->size = map->blocksize;
	req->op = X_COPY;
	r = __set_node(mio, req, mn);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Cannot set map node for object %s", mn->object);
		goto out_put;
	}

	r = send_request(pr, req);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Cannot send request %p, pr: %p, map: %s",
				req, pr, map->volume);
		goto out_unset_node;
	}
	mn->state |= MF_OBJECT_COPYING;
	XSEGLOG2(&lc, I, "Copying up object %s \n\t to %s", mn->object, new_target);
	return req;

out_unset_node:
	__set_node(mio, req, NULL);
out_put:
	put_request(pr, req);
//out_err:
	XSEGLOG2(&lc, E, "Copying up object %s \n\t to %s failed", mn->object, new_target);
	return NULL;

copyup_zeroblock:
	XSEGLOG2(&lc, I, "Copying up of zero block is not needed."
			"Proceeding in writing the new object in map");
	/* construct a tmp map_node for writing purposes */
	struct map_node newmn = *mn;
	newmn.flags = 0;
	newmn.flags |= MF_OBJECT_WRITABLE;
	newmn.flags |= MF_OBJECT_ARCHIP;
	strncpy(newmn.object, new_target, newtargetlen);
	newmn.object[newtargetlen] = 0;
	newmn.objectlen = newtargetlen;
	newmn.objectidx = mn->objectidx; 
	req = __object_write(peer, pr, map, &newmn);
	if (!req){
		XSEGLOG2(&lc, E, "Object write returned error for object %s"
				"\n\t of map %s [%llu]",
				mn->object, map->volume, (unsigned long long) mn->objectidx);
		__set_node(mio, req, NULL);
		return NULL;
	}
	r = __set_node(mio, req, mn);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Cannot set map node for object %s", mn->object);
	}
	mn->state |= MF_OBJECT_WRITING;
	XSEGLOG2(&lc, I, "Object %s copy up completed. Pending writing.", mn->object);
	return req;
}

static int __copyup_copy_cb(struct peer_req *pr, struct xseg_request *req,
		struct map_node *mn)
{
	struct peerd *peer = pr->peer;
	struct map *map;
	struct xseg_request *xreq;
	struct map_node newmn;
	char *target;
	int r;
	struct mapper_io *mio = __get_mapper_io(pr);

	mn->state &= ~MF_OBJECT_COPYING;

	map = mn->map;
	if (!map){
		XSEGLOG2(&lc, E, "Object %s has no map back pointer", mn->object);
		return -1;
	}

	/* construct a tmp map_node for writing purposes */
	target = xseg_get_target(peer->xseg, req);
	newmn = *mn;
	newmn.flags = 0;
	newmn.flags |= MF_OBJECT_WRITABLE;
	newmn.flags |= MF_OBJECT_ARCHIP;
	strncpy(newmn.object, target, req->targetlen);
	newmn.object[req->targetlen] = 0;
	newmn.objectlen = req->targetlen;
	newmn.objectidx = mn->objectidx; 
	xreq = __object_write(peer, pr, map, &newmn);
	if (!xreq){
		XSEGLOG2(&lc, E, "Object write returned error for object %s"
				"\n\t of map %s [%llu]",
				mn->object, map->volume, (unsigned long long) mn->objectidx);
		return -1;
	}
	r = __set_node(mio, xreq, mn);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Cannot set map node for object %s", mn->object);
	}
	mn->state |= MF_OBJECT_WRITING;
	return 0;
}

static int __copyup_write_cb(struct peer_req *pr, struct xseg_request *req,
		struct map_node *mn)
{
	struct peerd *peer = pr->peer;
	struct map_node tmp;
	char *data;
	struct map *map = mn->map;

	//assert mn->state & MF_OBJECT_WRITING
	mn->state &= ~MF_OBJECT_WRITING;

	data = xseg_get_data(peer->xseg, req);
	map->mops->read_object(&tmp, (unsigned char *)data);
	/* old object should not be writable */
	if (mn->flags & MF_OBJECT_WRITABLE) {
		XSEGLOG2(&lc, E, "map node %s has wrong flags", mn->object);
		return -1;
	}
	/* update object on cache */
	strncpy(mn->object, tmp.object, tmp.objectlen);
	mn->object[tmp.objectlen] = 0;
	mn->objectlen = tmp.objectlen;
	mn->flags = tmp.flags;
	return 0;
}

void copyup_cb(struct peer_req *pr, struct xseg_request *req)
{
	struct peerd *peer = pr->peer;
	struct mapperd *mapper = __get_mapperd(peer);
	(void)mapper;
	struct mapper_io *mio = __get_mapper_io(pr);
	struct map_node *mn = __get_node(mio, req);
	if (!mn){
		XSEGLOG2(&lc, E, "Cannot get map node");
		goto out_err;
	}
	__set_node(mio, req, NULL);

	if (req->state & XS_FAILED){
		XSEGLOG2(&lc, E, "Req failed");
		mn->state &= ~MF_OBJECT_COPYING;
		mn->state &= ~MF_OBJECT_WRITING;
		goto out_err;
	}
	if (req->op == X_WRITE) {
		if (__copyup_write_cb(pr, req, mn) < 0) {
			goto out_err;
		}
		XSEGLOG2(&lc, I, "Object write of %s completed successfully",
				mn->object);
		mio->pending_reqs--;
		signal_mapnode(mn);
		signal_pr(pr);
	} else if (req->op == X_COPY) {
	//	issue write_object;
		if (__copyup_copy_cb(pr, req, mn) < 0) {
			goto out_err;
		}
		XSEGLOG2(&lc, I, "Object %s copy up completed. "
				 "Pending writing.", mn->object);
	} else {
		//wtf??
		;
	}

out:
	put_request(pr, req);
	return;

out_err:
	mio->pending_reqs--;
	XSEGLOG2(&lc, D, "Mio->pending_reqs: %u", mio->pending_reqs);
	mio->err = 1;
	if (mn)
		signal_mapnode(mn);
	signal_pr(pr);
	goto out;

}

struct xseg_request * __object_write(struct peerd *peer, struct peer_req *pr,
				struct map *map, struct map_node *mn)
{
	int r;
	struct mapper_io *mio = __get_mapper_io(pr);
	struct xseg_request *req;

	req = map->mops->prepare_write_object(pr, map, mn);
	if (!req){
		XSEGLOG2(&lc, E, "Cannot prepare write object");
		goto out_err;
	}

	r = __set_node(mio, req, mn);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Cannot set map node for object %s", mn->object);
		goto out_put;
	}
	r = send_request(pr, req);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Cannot send request %p, pr: %p, map: %s",
				req, pr, map->volume);
		goto out_unset_node;
	}
	XSEGLOG2(&lc, I, "Writing object %s \n\t"
			"Map: %s [%llu]",
			mn->object, map->volume, (unsigned long long) mn->objectidx);

	return req;

out_unset_node:
	__set_node(mio, req, NULL);
out_put:
	put_request(pr, req);
out_err:
	XSEGLOG2(&lc, E, "Object write for object %s failed. \n\t"
			"(Map: %s [%llu]",
			mn->object, map->volume, (unsigned long long) mn->objectidx);
	return NULL;
}

static int __object_delete_delete_cb(struct peer_req *pr, struct xseg_request *req,
		struct map_node *mn)
{
	struct peerd *peer = pr->peer;
	struct map *map;
	struct xseg_request *xreq;
	struct map_node newmn;
	int r;
	struct mapper_io *mio = __get_mapper_io(pr);

	mn->state &= ~MF_OBJECT_DELETING;

	map = mn->map;
	if (!map){
		XSEGLOG2(&lc, E, "Object %s has no map back pointer", mn->object);
		return -1;
	}

	/* construct a tmp map_node for writing purposes */
	newmn = *mn;
	newmn.flags |= MF_OBJECT_DELETED;
	xreq = __object_write(peer, pr, map, &newmn);
	if (!xreq){
		XSEGLOG2(&lc, E, "Object write returned error for object %s"
				"\n\t of map %s [%llu]",
				mn->object, map->volume, (unsigned long long) mn->objectidx);
		return -1;
	}
	r = __set_node(mio, xreq, mn);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Cannot set map node for object %s", mn->object);
	}
	mn->state |= MF_OBJECT_WRITING;
	return 0;
}

static int __object_delete_write_cb(struct peer_req *pr, struct xseg_request *req,
		struct map_node *mn)
{
	struct peerd *peer = pr->peer;
	struct map_node tmp;
	char *data;

	//assert mn->state & MF_OBJECT_WRITING
	mn->state &= ~MF_OBJECT_WRITING;

	/* update object on cache */
	mn->flags |= MF_OBJECT_DELETED;
	return 0;
}

void object_delete_cb(struct peer_req *pr, struct xseg_request *req)
{
	struct mapper_io *mio = __get_mapper_io(pr);
	struct peerd *peer = pr->peer;
	struct map_node *mn = __get_node(mio, req);
	struct xseg_reply_hash *xreply;

	__set_node(mio, req, NULL);

	if (!mn) {
		XSEGLOG2(&lc, E, "Cannot get mapnode");
		mio->err = 1;
		goto out_err;
	}

	if (req->state & XS_FAILED){
		XSEGLOG2(&lc, E, "Req failed");
		mn->state &= ~MF_OBJECT_DELETING;
		mn->state &= ~MF_OBJECT_WRITING;
		goto out_err;
	}
	if (req->op == X_WRITE) {
		if (__object_delete_write_cb(pr, req, mn) < 0) {
			goto out_err;
		}
		XSEGLOG2(&lc, I, "Object write of %s completed successfully",
				mn->object);
		mio->pending_reqs--;
		signal_mapnode(mn);
		//put mapnode here to match get on do_destroy()
		put_mapnode(mn);
		signal_pr(pr);
	} else if (req->op == X_DELETE) {
	//	issue write_object;
		if (__object_delete_delete_cb(pr, req, mn) < 0) {
			goto out_err;
		}
		XSEGLOG2(&lc, I, "Object deletion of %s completed. "
				 "Pending writing.", mn->object);
	} else {
		//wtf??
		;
	}

out:
	put_request(pr, req);
	return;

out_err:
	mio->pending_reqs--;
	XSEGLOG2(&lc, D, "Mio->pending_reqs: %u", mio->pending_reqs);
	mio->err = 1;
	signal_pr(pr);
	goto out;
}


struct xseg_request * __object_delete(struct peer_req *pr, struct map_node *mn)
{
	struct peerd *peer = pr->peer;
	struct mapperd *mapper = __get_mapperd(peer);
	struct mapper_io *mio = __get_mapper_io(pr);
	struct xseg_request *req;
	int r;

	XSEGLOG2(&lc, I, "Deleting mapnode %s", mn->object);

	req = get_request(pr, mapper->bportno, mn->object, mn->objectlen, 0);
	if (!req){
		XSEGLOG2(&lc, E, "Cannot get request for object %s", mn->object);
		goto out_err;
	}

	req->op = X_DELETE;
	req->size = req->datalen;
	req->offset = 0;

	r = __set_node(mio, req, mn);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Cannot set map node for object %s", mn->object);
		goto out_put;
	}
	r = send_request(pr, req);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Cannot send request %p, pr: %p, object: %s",
				req, pr, mn->object);
		goto out_unset_node;
	}
	mn->flags |= MF_OBJECT_DELETING;
	XSEGLOG2(&lc, I, "Object %s deletion pending", mn->object);

	mio->pending_reqs++;

	return req;

out_unset_node:
	__set_node(mio, req, NULL);
out_put:
	put_request(pr, req);
out_err:
	XSEGLOG2(&lc, I, "Object %s deletion failed", mn->object);
	return NULL;
}

#if 0
struct xseg_request * __delete_map(struct peer_req *pr, struct map *map)
{
	void *dummy;
	struct peerd *peer = pr->peer;
	struct mapperd *mapper = __get_mapperd(peer);
	struct mapper_io *mio = __get_mapper_io(pr);
	struct xseg_request *req = xseg_get_request(peer->xseg, pr->portno, 
							mapper->mbportno, X_ALLOC);
	XSEGLOG2(&lc, I, "Deleting map %s", map->volume);
	map->flags |= MF_MAP_DELETED
	if (!req){
		XSEGLOG2(&lc, E, "Cannot get request for map %s", map->volume);
		goto out_err;
	}
	int r = xseg_prep_request(peer->xseg, req, map->volumelen, 0);
	if (r < 0){
		XSEGLOG2(&lc, E, "Cannot prep request for map %s", map->volume);
		goto out_put;
	}
	char *target = xseg_get_target(peer->xseg, req);
	strncpy(target, map->volume, req->targetlen);
	req->op = X_DELETE;
	req->size = req->datalen;
	req->offset = 0;
	r = xseg_set_req_data(peer->xseg, req, pr);
	if (r < 0){
		XSEGLOG2(&lc, E, "Cannot set req data for map %s", map->volume);
		goto out_put;
	}
	/* do not check return value. just make sure there is no node set */
	xport p = xseg_submit(peer->xseg, req, pr->portno, X_ALLOC);
	if (p == NoPort){
		XSEGLOG2(&lc, E, "Cannot submit request for map %s", map->volume);
		goto out_unset;
	}
	r = xseg_signal(peer->xseg, p);
	map->state |= MF_MAP_DELETING;
	XSEGLOG2(&lc, I, "Map %s deletion pending", map->volume);
	return req;

out_unset:
	xseg_get_req_data(peer->xseg, req, &dummy);
out_put:
	xseg_put_request(peer->xseg, req, pr->portno);
out_err:
	map->flags &= ~MF_MAP_DELETED;
	XSEGLOG2(&lc, E, "Map %s deletion failed", map->volume);
	return  NULL;
}
#endif

void hash_cb(struct peer_req *pr, struct xseg_request *req)
{
	struct mapper_io *mio = __get_mapper_io(pr);
	struct peerd *peer = pr->peer;
	struct map_node *mn = __get_node(mio, req);
	struct xseg_reply_hash *xreply;

	XSEGLOG2(&lc, I, "Callback of req %p", req);

	if (!mn) {
		XSEGLOG2(&lc, E, "Cannot get mapnode");
		mio->err = 1;
		goto out_nonode;
	}

	if (req->state & XS_FAILED) {
		mio->err = 1;
		XSEGLOG2(&lc, E, "Request failed");
		goto out;
	}

	if (req->serviced != req->size) {
		mio->err = 1;
		XSEGLOG2(&lc, E, "Serviced != size");
		goto out;
	}

	xreply = (struct xseg_reply_hash *) xseg_get_data(peer->xseg, req);
	if (xreply->targetlen != HEXLIFIED_SHA256_DIGEST_SIZE) {
		XSEGLOG2(&lc, E, "Reply targetlen != HEXLIFIED_SHA256_DIGEST_SIZE");
		mio->err =1;
		goto out;
	}

	strncpy(mn->object, xreply->target, HEXLIFIED_SHA256_DIGEST_SIZE);
	mn->object[HEXLIFIED_SHA256_DIGEST_SIZE] = 0;
	mn->objectlen = HEXLIFIED_SHA256_DIGEST_SIZE;
	XSEGLOG2(&lc, D, "Received hash object %llu: %s (%p)",
			mn->objectidx, mn->object, mn);
	mn->flags = 0;

out:
	put_mapnode(mn);
	__set_node(mio, req, NULL);
out_nonode:
	put_request(pr, req);
	mio->pending_reqs--;
	signal_pr(pr);
	return;
}


int __hash_map(struct peer_req *pr, struct map *map, struct map *hashed_map)
{
	struct mapperd *mapper = __get_mapperd(pr->peer);
	struct mapper_io *mio = __get_mapper_io(pr);
	uint64_t i;
	struct map_node *mn, *hashed_mn;
	struct xseg_request *req;
	int r;

	mio->priv = 0;

	for (i = 0; i < map->nr_objs; i++) {
		mn = get_mapnode(map, i);
		if (!mn) {
			XSEGLOG2(&lc, E, "Cannot get mapnode %llu of map %s ",
					"(nr_objs: %llu)", i, map->volume,
					map->nr_objs);
			return -1;
		}
		hashed_mn = get_mapnode(hashed_map, i);
		if (!hashed_mn) {
			XSEGLOG2(&lc, E, "Cannot get mapnode %llu of map %s ",
					"(nr_objs: %llu)", i, hashed_map->volume,
					hashed_map->nr_objs);
			put_mapnode(mn);
			return -1;
		}
		if (!(mn->flags & MF_OBJECT_ARCHIP)) {
			mio->priv++;
			strncpy(hashed_mn->object, mn->object, mn->objectlen);
			hashed_mn->objectlen = mn->objectlen;
			hashed_mn->object[hashed_mn->objectlen] = 0;
			hashed_mn->flags = mn->flags;

			put_mapnode(mn);
			put_mapnode(hashed_mn);
			continue;
		}

		req = get_request(pr, mapper->bportno, mn->object,
				mn->objectlen, 0);
		if (!req){
			XSEGLOG2(&lc, E, "Cannot get request for map %s",
					map->volume);
			put_mapnode(mn);
			put_mapnode(hashed_mn);
			return -1;
		}

		req->op = X_HASH;
		req->offset = 0;
		req->size = map->blocksize;
		r = __set_node(mio, req, hashed_mn);
		if (r < 0) {
			XSEGLOG2(&lc, E, "Cannot set node");
			put_request(pr, req);
			put_mapnode(mn);
			put_mapnode(hashed_mn);
			return -1;
		}

		r = send_request(pr, req);
		if (r < 0) {
			XSEGLOG2(&lc, E, "Cannot send request %p, pr: %p, map: %s",
					req, pr, map->volume);
			put_request(pr, req);
			__set_node(mio, req, NULL);
			put_mapnode(mn);
			put_mapnode(hashed_mn);
			return -1;
		}
		mio->pending_reqs++;
		put_mapnode(mn);
	}

	return 0;
}

int hash_map(struct peer_req *pr, struct map *map, struct map *hashed_map)
{
	int r;
	struct mapper_io *mio = __get_mapper_io(pr);

	XSEGLOG2(&lc, I, "Hashing map %s", map->volume);
	map->state |= MF_MAP_HASHING;
	mio->pending_reqs = 0;
	mio->cb = hash_cb;
	mio->err = 0;


	r = __hash_map(pr, map, hashed_map);
	if (r < 0) {
		mio->err = 1;
	}

	if (mio->pending_reqs) {
		wait_on_pr(pr, mio->pending_reqs >0);
	}

	mio->cb = NULL;
	map->state &= ~MF_MAP_HASHING;
	if (mio->err) {
		XSEGLOG2(&lc, E, "Hashing map %s failed", map->volume);
		return -1;
	} else {
		XSEGLOG2(&lc, I, "Hashing map %s completed", map->volume);
		return 0;
	}
}
