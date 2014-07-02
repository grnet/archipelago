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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>
#include <xseg/xseg.h>
#include <peer.h>
#include <time.h>
#include <xseg/xhash.h>
#include <xseg/protocol.h>
//#include <sys/stat.h>
//#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <sys/syscall.h>
#include <hash.h>
#include <mapper.h>
#include <mapper-versions.h>

uint64_t cur_count = 0;

extern st_cond_t req_cond;
/* pithos considers this a block full of zeros, so should we.
 * it is actually the sha256 hash of nothing.
 */
char *zero_block="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

void custom_peer_usage()
{
	fprintf(stderr, "Custom peer options: \n"
			"-bp  : port for block blocker(!)\n"
			"-mbp : port for map blocker\n"
			"\n");
}


/*
 * Helper functions
 */

static uint32_t calc_nr_obj(struct map *map, struct xseg_request *req)
{
	unsigned int r = 1;
	uint64_t rem_size = req->size;
	uint64_t obj_offset = req->offset & (map->blocksize - 1); //modulo
	uint64_t obj_size =  (rem_size + obj_offset > map->blocksize) ? map->blocksize - obj_offset : rem_size;
	rem_size -= obj_size;
	while (rem_size > 0) {
		obj_size = (rem_size > map->blocksize) ? map->blocksize : rem_size;
		rem_size -= obj_size;
		r++;
	}

	return r;
}

/*
 * Map cache handling functions
 */

static struct map * find_map(struct mapperd *mapper, char *volume)
{
	struct map *m = NULL;
	int r = xhash_lookup(mapper->hashmaps, (xhashidx) volume,
				(xhashidx *) &m);
	if (r < 0)
		return NULL;
	return m;
}

static struct map * find_map_len(struct mapperd *mapper, char *target,
					uint32_t targetlen, uint32_t flags)
{
	char buf[XSEG_MAX_TARGETLEN+1];

	if (targetlen > MAX_VOLUME_LEN){
		XSEGLOG2(&lc, E, "Namelen %u too long. Max: %d",
					targetlen, MAX_VOLUME_LEN);
		return NULL;
	}

//	if (flags & MF_ARCHIP){
//		strncpy(buf, MAPPER_PREFIX, MAPPER_PREFIX_LEN);
//		strncpy(buf + MAPPER_PREFIX_LEN, target, targetlen);
//		buf[MAPPER_PREFIX_LEN + targetlen] = 0;
//		targetlen += MAPPER_PREFIX_LEN;
//	}
//	else {
		strncpy(buf, target, targetlen);
		buf[targetlen] = 0;
//	}

	XSEGLOG2(&lc, D, "looking up map %s, len %u",
			buf, targetlen);
	return find_map(mapper, buf);
}


static int insert_map(struct mapperd *mapper, struct map *map)
{
	int r = -1;

	if (find_map(mapper, map->volume)){
		XSEGLOG2(&lc, W, "Map %s found in hash maps", map->volume);
		goto out;
	}

	XSEGLOG2(&lc, D, "Inserting map %s, len: %d (map: %lx)", 
			map->volume, strlen(map->volume), (unsigned long) map);
	r = xhash_insert(mapper->hashmaps, (xhashidx) map->volume, (xhashidx) map);
	while (r == -XHASH_ERESIZE) {
		xhashidx shift = xhash_grow_size_shift(mapper->hashmaps);
		xhash_t *new_hashmap = xhash_resize(mapper->hashmaps, shift, 0, NULL);
		if (!new_hashmap){
			XSEGLOG2(&lc, E, "Cannot grow mapper->hashmaps to sizeshift %llu",
					(unsigned long long) shift);
			goto out;
		}
		mapper->hashmaps = new_hashmap;
		r = xhash_insert(mapper->hashmaps, (xhashidx) map->volume, (xhashidx) map);
	}
out:
	return r;
}

static int remove_map(struct mapperd *mapper, struct map *map)
{
	int r = -1;

	//assert no pending pr on map

	r = xhash_delete(mapper->hashmaps, (xhashidx) map->volume);
	while (r == -XHASH_ERESIZE) {
		xhashidx shift = xhash_shrink_size_shift(mapper->hashmaps);
		xhash_t *new_hashmap = xhash_resize(mapper->hashmaps, shift, 0, NULL);
		if (!new_hashmap){
			XSEGLOG2(&lc, E, "Cannot shrink mapper->hashmaps to sizeshift %llu",
					(unsigned long long) shift);
			goto out;
		}
		mapper->hashmaps = new_hashmap;
		r = xhash_delete(mapper->hashmaps, (xhashidx) map->volume);
	}
out:
	return r;
}

inline struct map_node * get_mapnode(struct map *map, uint64_t index)
{
	struct map_node *mn;
	if (index >= map->nr_objs) {
	//	XSEGLOG2(&lc, E, "Index out of range: %llu > %llu",
	//			index, map->nr_objs);
		return NULL;
	}
	if (!map->objects) {
	//	XSEGLOG2(&lc, E, "Map %s has no objects", map->volume);
		return NULL;
	}
	mn = &map->objects[index];
	mn->ref++;
	XSEGLOG2(&lc, D,  "mapnode %p: ref: %u", mn, mn->ref);
	return mn;
}

inline void put_mapnode(struct map_node *mn)
{
	mn->ref--;
	XSEGLOG2(&lc, D, "mapnode %p: ref: %u", mn, mn->ref);
	if (!mn->ref){
		//clean up mn
		st_cond_destroy(mn->cond);
	}
}

int initialize_map_objects(struct map *map)
{
	uint64_t i;
	struct map_node *map_node = map->objects;

	if (!map_node)
		return -1;

	for (i = 0; i < map->nr_objs; i++) {
		map_node[i].map = map;
		map_node[i].objectidx = i;
		map_node[i].waiters = 0;
		map_node[i].state = 0;
		map_node[i].ref = 1;
		map_node[i].cond = st_cond_new(); //FIXME err check;
	}
	return 0;
}



static inline void __get_map(struct map *map)
{
	map->ref++;
}

static inline void put_map(struct map *map)
{
	struct map_node *mn;
	XSEGLOG2(&lc, D, "Putting map %lx %s. ref %u", map, map->volume, map->ref);
	map->ref--;
	if (!map->ref){
		XSEGLOG2(&lc, I, "Freeing map %s", map->volume);
		/*
		 * Check that every object is not used by another state thread.
		 * This should always check out, otherwise there is a bug. Since
		 * before a thread can manipulate an object, it must first get
		 * the map, the map ref will never hit zero, while another
		 * thread is using an object.
		 */
		uint64_t i;
		for (i = 0; i < map->nr_objs; i++) {
			mn = get_mapnode(map, i);
			if (mn) {
				//make sure all pending operations on all objects are completed
				if (mn->state & MF_OBJECT_NOT_READY) {
					XSEGLOG2(&lc, E, "BUG: map node in use while freeing map");
					wait_on_mapnode(mn, mn->state & MF_OBJECT_NOT_READY);
				}
//				mn->state |= MF_OBJECT_DESTROYED;
				put_mapnode(mn); //matching mn->ref = 1 on mn init
				put_mapnode(mn); //matching get_mapnode;
				//assert mn->ref == 0;
				if (mn->ref) {
					XSEGLOG2(&lc, E, "BUG: map node ref != 0 after final put");
				}
			}
		}
		//clean up map
		if (map->objects)
			free(map->objects);
		XSEGLOG2(&lc, I, "Freed map %s", map->volume);
		free(map);
	}
}

static struct map * create_map(char *name, uint32_t namelen, uint32_t flags)
{
	if (namelen + MAPPER_PREFIX_LEN > MAX_VOLUME_LEN){
		XSEGLOG2(&lc, E, "Namelen %u too long. Max: %d",
					namelen, MAX_VOLUME_LEN);
		return NULL;
	}
	struct map *m = malloc(sizeof(struct map));
	if (!m){
		XSEGLOG2(&lc, E, "Cannot allocate map ");
		return NULL;
	}
	m->size = -1;
	strncpy(m->volume, name, namelen);
	m->volume[namelen] = 0;
	m->volumelen = namelen;
	/* Use the latest map version here, when creating a new map. If
	 * the map is read from storage, this version will be rewritten
	 * with the right value.
	 */
	m->version = MAP_LATEST_VERSION;
	m->mops = MAP_LATEST_MOPS;
	m->flags = 0;

	m->signature = MAP_SIGNATURE;
	m->epoch = 0;
	m->state = 0;
	m->nr_objs = 0;
	m->objects = NULL;
	m->ref = 1;
	m->waiters = 0;
	m->cond = st_cond_new(); //FIXME err check;

	m->users = 0;
	m->waiters_users = 0;
	m->users_cond = st_cond_new();

	return m;
}

static void wait_all_map_objects_ready(struct map *map)
{
	uint64_t i;
	struct map_node *mn;

	//TODO: maybe add counter on the map on how many objects are used, to
	//speed up the common case, where there are no used objects.
	map->state |= MF_MAP_SERIALIZING;
	if (map->users)
		wait_all_objects_ready(map);

	for (i = 0; i < map->nr_objs; i++) {
		mn = get_mapnode(map, i);
		if (mn) {
			//make sure all pending operations on all objects are completed
			if (mn->state & MF_OBJECT_NOT_READY) {
				XSEGLOG2(&lc, E, "BUG: Map node %x of map %s, "
						"idx: %llu is not ready",
						mn, map->volume, i);
//				wait_on_mapnode(mn, mn->state & MF_OBJECT_NOT_READY);
			}
			put_mapnode(mn);
		}
	}

	map->state &= ~MF_MAP_SERIALIZING;
}


struct r2o {
	struct map_node *mn;
	uint64_t offset;
	uint64_t size;
};

static int do_copyups(struct peer_req *pr, struct r2o *mns, int n)
{
	struct mapper_io *mio = __get_mapper_io(pr);
	struct map_node *mn;
	int i, j, can_wait = 0;
	mio->pending_reqs = 0;
	mio->cb=copyup_cb;
	mio->err = 0;

	/* do a first scan and issue as many copyups as we can.
	 * then retry and wait when an object is not ready.
	 * this could be done better, since now we wait also on the
	 * pending copyups
	 */
	for (j = 0; j < 2 && !mio->err; j++) {
		for (i = 0; i < n && !mio->err; i++) {
			mn = mns[i].mn;
			//do copyups
			if (mn->state & MF_OBJECT_NOT_READY){
				if (!can_wait)
					continue;
				/* here mn->flags should be
				 * MF_OBJECT_COPYING or MF_OBJECT_WRITING or
				 * later MF_OBJECT_HASHING.
				 * Otherwise it's a bug.
				 */
				if (mn->state != MF_OBJECT_COPYING
						&& mn->state != MF_OBJECT_WRITING) {
					XSEGLOG2(&lc, E, "BUG: Map node has wrong state");
				}
				wait_on_mapnode(mn, mn->state & MF_OBJECT_NOT_READY);
				if (mn->state & MF_OBJECT_DELETED){
					mio->err = 1;
					continue;
				}
			}

			if (!(mn->flags & MF_OBJECT_WRITABLE)) {
				//calc new_target, copy up object
				if (__copyup_object(pr, mn) == NULL){
					XSEGLOG2(&lc, E, "Error in copy up object");
					mio->err = 1;
				} else {
					mio->pending_reqs++;
				}
			}

		}
		can_wait = 1;
	}

	if (mio->err){
		XSEGLOG2(&lc, E, "Mio->err, pending_copyups: %d", mio->pending_reqs);
	}

	if (mio->pending_reqs > 0)
		wait_on_pr(pr, mio->pending_reqs > 0);

	return mio->err ? -1 : 0;
}

static int req2objs(struct peer_req *pr, struct map *map, int write)
{
	int r = 0;
	struct peerd *peer = pr->peer;
	struct mapper_io *mio = __get_mapper_io(pr);
	char *target = xseg_get_target(peer->xseg, pr->req);
	uint32_t nr_objs = calc_nr_obj(map, pr->req);
	uint64_t size = sizeof(struct xseg_reply_map) +
			nr_objs * sizeof(struct xseg_reply_map_scatterlist);
	uint32_t idx, i;
	uint64_t rem_size, obj_index, obj_offset, obj_size;
	struct map_node *mn;
	char buf[XSEG_MAX_TARGETLEN];
	struct xseg_reply_map *reply;

	XSEGLOG2(&lc, D, "Calculated %u nr_objs", nr_objs);

	if (pr->req->offset + pr->req->size > map->size) {
		XSEGLOG2(&lc, E, "Invalid offset/size: offset: %llu, "
				"size: %llu, map size: %llu",
				pr->req->offset, pr->req->size, map->size);
		return -1;
	}

	/* get map_nodes of request */
	struct r2o *mns = malloc(sizeof(struct r2o)*nr_objs);
	if (!mns){
		XSEGLOG2(&lc, E, "Cannot allocate mns");
		return -1;
	}

	map->users++;

	idx = 0;
	rem_size = pr->req->size;
	obj_index = pr->req->offset / map->blocksize;
	obj_offset = pr->req->offset & (map->blocksize -1); //modulo
	obj_size =  (obj_offset + rem_size > map->blocksize) ? map->blocksize - obj_offset : rem_size;
	mn = get_mapnode(map, obj_index);
	if (!mn) {
		XSEGLOG2(&lc, E, "Cannot find obj_index %llu\n",
				(unsigned long long) obj_index);
		r = -1;
		goto out;
	}
	mns[idx].mn = mn;
	mns[idx].offset = obj_offset;
	mns[idx].size = obj_size;
	rem_size -= obj_size;
	while (rem_size > 0) {
		idx++;
		obj_index++;
		obj_offset = 0;
		obj_size = (rem_size > map->blocksize) ? map->blocksize : rem_size;
		rem_size -= obj_size;
		mn = get_mapnode(map, obj_index);
		if (!mn) {
			XSEGLOG2(&lc, E, "Cannot find obj_index %llu\n", (unsigned long long) obj_index);
			r = -1;
			goto out;
		}
		if (mn->flags & MF_OBJECT_DELETED) {
			XSEGLOG2(&lc, E, "Trying to perform I/O on deleted object %s",
					mn->object);
			r = -1;
			goto out;
		};
		mns[idx].mn = mn;
		mns[idx].offset = obj_offset;
		mns[idx].size = obj_size;
	}
	if (write) {
		if (do_copyups(pr, mns, idx+1) < 0) {
			r = -1;
			XSEGLOG2(&lc, E, "do_copyups failed");
			goto out;
		}
	}

	/* resize request to fit reply */
	strncpy(buf, target, pr->req->targetlen);
	r = xseg_resize_request(peer->xseg, pr->req, pr->req->targetlen, size);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Cannot resize request");
		goto out;
	}
	target = xseg_get_target(peer->xseg, pr->req);
	strncpy(target, buf, pr->req->targetlen);

	/* structure reply */
	reply = (struct xseg_reply_map *) xseg_get_data(peer->xseg, pr->req);
	reply->cnt = nr_objs;
	for (i = 0; i < (idx+1); i++) {
		strncpy(reply->segs[i].target, mns[i].mn->object, mns[i].mn->objectlen);
		reply->segs[i].targetlen = mns[i].mn->objectlen;
		reply->segs[i].offset = mns[i].offset;
		reply->segs[i].size = mns[i].size;
		reply->segs[i].flags = 0;
		if (mns[i].mn->flags & MF_OBJECT_ZERO) {
			reply->segs[i].flags |= XF_MAPFLAG_ZERO;
		}
	}
out:
	for (i = 0; i < (idx+1); i++) {
		put_mapnode(mns[i].mn);
	}
	free(mns);
	mio->cb = NULL;
	if (--map->users){
		signal_all_objects_ready(map);
	}
	return r;
}

static int do_info(struct peer_req *pr, struct map *map)
{
	struct peerd *peer = pr->peer;
	struct xseg_reply_info *xinfo;
	struct xseg_request *req = pr->req;
	char buf[XSEG_MAX_TARGETLEN + 1];
	char *target;
	int r;

	if (req->datalen < sizeof(struct xseg_reply_info)) {
		target = xseg_get_target(peer->xseg, req);
		strncpy(buf, target, req->targetlen);
		r = xseg_resize_request(peer->xseg, req, req->targetlen, sizeof(struct xseg_reply_info));
		if (r < 0) {
			XSEGLOG2(&lc, E, "Cannot resize request");
			return -1;
		}
		target = xseg_get_target(peer->xseg, req);
		strncpy(target, buf, req->targetlen);
	}

	xinfo = (struct xseg_reply_info *) xseg_get_data(peer->xseg, req);
	xinfo->size = map->size;
	return 0;
}


static int do_open(struct peer_req *pr, struct map *map)
{
	if (map->state & MF_MAP_EXCLUSIVE) {
		return 0;
	}
	else {
		return -1;
	}
}


static int dropcache(struct peer_req *pr, struct map *map)
{
	int r;
	struct peerd *peer = pr->peer;
	struct mapperd *mapper = __get_mapperd(peer);
	XSEGLOG2(&lc, I, "Dropping cache for map %s", map->volume);
	/*
	 * We can lazily drop the cache from here, by just removing from the maps
	 * hashmap making it inaccessible from future requests. This is because:
	 *
	 * a) Dropping cache for a map is serialized on a map level. So there
	 * should not be any other threds modifying the struct map.
	 *
	 * b) Any other thread manipulating the map nodes should not have
	 * any pending requests on the map node, if the map is not opened
	 * exclusively. If that's the case, then we should not close the map,
	 * a.k.a. releasing the map lock without checking for any pending
	 * requests. Furthermore, since each operation on a map gets a map
	 * reference, the memory will not be freed, unless every request has
	 * finished processing the map.
	 */

	/* Set map as destroyed to notify any waiters that hold a reference to
	 * the struct map.
	 */
	//FIXME err check
	r = remove_map(mapper, map);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Remove map %s from hashmap failed", map->volume);
		XSEGLOG2(&lc, E, "Dropping cache for map %s failed", map->volume);
		return -1;
	}
	map->state |= MF_MAP_DESTROYED;
	XSEGLOG2(&lc, I, "Dropping cache for map %s completed", map->volume);
	put_map(map);	// put map here to destroy it (matches m->ref = 1 on map create)
	return 0;
}

static int do_close(struct peer_req *pr, struct map *map)
{
	if (!(map->state & MF_MAP_CANCACHE)) {
		XSEGLOG2(&lc, E, "Attempted to close a not opened/cached map");
		return -1;
	}
	/* Do not close the map while there are pending requests on the
	 * map nodes.
	 */
	wait_all_map_objects_ready(map);
	if (map->state & MF_MAP_EXCLUSIVE) {
		if (close_map(pr, map) < 0) {
			return -1;
		}
	}
	/* order mapper to drop the cache, after close */
	map->state &= ~MF_MAP_CANCACHE;

	return 0;
}

static int do_hash(struct peer_req *pr, struct map *map)
{
#if 0
	int r;
	struct peerd *peer = pr->peer;
	uint64_t i, bufsize;
	struct map *hashed_map;
	unsigned char sha[SHA256_DIGEST_SIZE];
	unsigned char *buf = NULL;
	char newvolumename[MAX_VOLUME_LEN];
	uint32_t newvolumenamelen = HEXLIFIED_SHA256_DIGEST_SIZE;
	uint64_t pos = 0;
	char targetbuf[XSEG_MAX_TARGETLEN];
	char *target;
	struct xseg_reply_hash *xreply;
	struct map_node *mn;

	if (!(map->flags & MF_MAP_READONLY)) {
		XSEGLOG2(&lc, E, "Cannot hash live volumes");
		return -1;
	}

	XSEGLOG2(&lc, I, "Hashing map %s", map->volume);
	/* prepare hashed_map holder */
	hashed_map = create_map("", 0, 0);
	if (!hashed_map) {
		XSEGLOG2(&lc, E, "Cannot create hashed map");
		return -1;
	}

	/* set map metadata */
	hashed_map->size = map->size;
	hashed_map->nr_objs = map->nr_objs;
	hashed_map->flags = MF_MAP_READONLY;
	hashed_map->blocksize = MAPPER_DEFAULT_BLOCKSIZE; /* FIXME, this should be PITHOS_BLOCK_SIZE right? */

	hashed_map->objects = calloc(map->nr_objs, sizeof(struct map_node));
	if (!hashed_map->objects) {
		XSEGLOG2(&lc, E, "Cannot allocate memory for %llu nr_objs",
				hashed_map->nr_objs);
		r = -1;
		goto out;
	}

	r = initialize_map_objects(hashed_map);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Cannot initialize hashed_map objects");
		goto out;
	}

	r = hash_map(pr, map, hashed_map);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Cannot hash map %s", map->volume);
		goto out;
	}

	bufsize = hashed_map->nr_objs * v0_objectsize_in_map;

	buf = malloc(bufsize);
	if (!buf) {
		XSEGLOG2(&lc, E, "Cannot allocate merkle_hash buffer of %llu bytes",
				bufsize);
		goto out;
	}
	for (i = 0; i < hashed_map->nr_objs; i++) {
		mn = get_mapnode(hashed_map, i);
		if (!mn){
			XSEGLOG2(&lc, E, "Cannot get object %llu for map %s",
					i, hashed_map->volume);
			goto out;
		}
		map_functions[0].object_to_map(buf+pos, mn);
		pos += v0_objectsize_in_map;
		put_mapnode(mn);
	}

	merkle_hash(buf, pos, sha);
	hexlify(sha, SHA256_DIGEST_SIZE, newvolumename);
	strncpy(hashed_map->volume, newvolumename, newvolumenamelen);
	hashed_map->volume[newvolumenamelen] = 0;
	hashed_map->volumelen = newvolumenamelen;

	/* write the hashed_map */
	r = write_map(pr, hashed_map);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Cannot write hashed_map %s", hashed_map->volume);
		goto out;
	}

	/* Resize request to fit xhash reply */
	target = xseg_get_target(peer->xseg, pr->req);
	strncpy(targetbuf, target, pr->req->targetlen);

	r = xseg_resize_request(peer->xseg, pr->req, pr->req->targetlen,
			sizeof(struct xseg_reply_hash));
	if (r < 0){
		XSEGLOG2(&lc, E, "Cannot resize request");
		goto out;
	}

	target = xseg_get_target(peer->xseg, pr->req);
	strncpy(target, targetbuf, pr->req->targetlen);

	/* Put the target of the hashed_map on the reply */
	xreply = (struct xseg_reply_hash *) xseg_get_data(peer->xseg, pr->req);
	strncpy(xreply->target, newvolumename, newvolumenamelen);
	xreply->targetlen = newvolumenamelen;

out:
	if (buf)
		free(buf);
	put_map(hashed_map);
	if (r < 0) {
		return -1;
	} else {
		return 0;
	}
#endif
	return 0;
}

static int do_snapshot(struct peer_req *pr, struct map *map)
{
	uint64_t i;
	struct peerd *peer = pr->peer;
	//struct mapper_io *mio = __get_mapper_io(pr);
	struct map_node *mn;
	uint64_t nr_objs;
	struct map *snap_map;
	struct xseg_request_snapshot *xsnapshot;
	char *snapname;
	uint32_t snapnamelen;
	int r;

	xsnapshot = (struct xseg_request_snapshot *)xseg_get_data(peer->xseg, pr->req);
	if (!xsnapshot) {
		return -1;
	}
	snapname = xsnapshot->target;
	snapnamelen = xsnapshot->targetlen;

	if (!snapnamelen) {
		XSEGLOG2(&lc, E, "Snapshot name must be provided");
		return -1;
	}

	if (!(map->state & MF_MAP_EXCLUSIVE)) {
		XSEGLOG2(&lc, E, "Map was not opened exclusively");
		return -1;
	}
	if (map->epoch == UINT64_MAX) {
		XSEGLOG2(&lc, E, "Max epoch reached for %s", map->volume);
		return -1;
	}
	XSEGLOG2(&lc, I, "Starting snapshot for map %s", map->volume);
	map->state |= MF_MAP_SNAPSHOTTING;

	//create new map struct with name snapshot name and flag readonly.
	snap_map = create_map(snapname, snapnamelen, MF_ARCHIP);
	if (!snap_map) {
		goto out_err;
	}

	//open/load map to check if snap exists
	r = open_map(pr, snap_map, 0);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Could not open snap map");
		XSEGLOG2(&lc, E, "Snapshot exists");
		goto out_put;
	}
	r = load_map_metadata(pr, snap_map);
	if (r >= 0 && !(map->flags & MF_MAP_DELETED)) {
		XSEGLOG2(&lc, E, "Snapshot exists");
		goto out_close;
	}
	snap_map->epoch = 0;
	//snap_map->flags &= ~MF_MAP_DELETED;
	snap_map->flags = MF_MAP_READONLY;
	snap_map->objects = map->objects;
	snap_map->size = map->size;
	snap_map->blocksize = map->blocksize;
	snap_map->nr_objs = map->nr_objs;


	nr_objs = map->nr_objs;

	//set all map_nodes read only;
	//TODO, maybe skip that check and add an epoch number on each object.
	//Then we can check if object is writable iff object epoch == map epoch
	wait_all_map_objects_ready(map);
	for (i = 0; i < nr_objs; i++) {
		mn = get_mapnode(map, i);
		if (!mn) {
			XSEGLOG2(&lc, E, "Could not get map node %llu for map %s",
					i, map->volume);
			goto out_err;
		}

		// make sure all pending operations on all objects are completed
		// Basically make sure, that no previously copy up operation,
		// will mess with our state.
		// This works, since only a map_w, that was processed before
		// this request, can have issued an object write request which
		// may be pending. Since the objects are processed in the same
		// order by the copyup operation and the snapshot operation, we
		// can be sure, that no previously ready objects, have changed
		// their state into not read.
		// No other operation that manipulated map objects can occur
		// simutaneously with snapshot operation.
		if (mn->state & MF_OBJECT_NOT_READY)
			XSEGLOG2(&lc, E, "BUG: object not ready");
	//		wait_on_mapnode(mn, mn->state & MF_OBJECT_NOT_READY);

		mn->flags &= ~MF_OBJECT_WRITABLE;
		put_mapnode(mn);
	}
	//increase epoch
	map->epoch++;
	//write map
	r = write_map(pr, map);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Cannot write map %s", map->volume);
		/* Not restoring epoch or writable status here, is not
		 * devastating, since this is not the common case, and it can
		 * only cause unneeded copy-on-write operations.
		 */
		goto out_err;
	}
	//write snapshot map
	r = write_map(pr, snap_map);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Write of snapshot map failed");
		goto out_unset;
	}

	close_map(pr, snap_map);
	snap_map->objects = NULL;
	put_map(snap_map);

	map->state &= ~MF_MAP_SNAPSHOTTING;

	if (map->opened_count == cur_count)
		close_map(pr, map);

	XSEGLOG2(&lc, I, "Snapshot for map %s completed", map->volume);
	return 0;

out_unset:
	snap_map->objects = NULL;
out_close:
	close_map(pr, snap_map);
out_put:
	put_map(snap_map);
out_err:
	map->state &= ~MF_MAP_SNAPSHOTTING;
	XSEGLOG2(&lc, E, "Snapshot for map %s failed", map->volume);
	return -1;
}

/* This should probably me a map function */
static int do_destroy(struct peer_req *pr, struct map *map)
{
	uint64_t i, nr_objs;
	struct peerd *peer = pr->peer;
	struct mapper_io *mio = __get_mapper_io(pr);
	struct map_node *mn;
	struct xseg_request *req;
	int r;

	if (!(map->state & MF_MAP_EXCLUSIVE))
		return -1;

	if (map->flags & MF_MAP_DELETED) {
		XSEGLOG2(&lc, E, "Map %s already deleted", map->volume);
		do_close(pr, map);
		return -1;
	}

	XSEGLOG2(&lc, I, "Destroying map %s", map->volume);
	map->state |= MF_MAP_DELETING;

	wait_all_map_objects_ready(map);

	mio->cb = object_delete_cb;
	nr_objs = map->nr_objs;
	mio->pending_reqs = 0;
	for (i = 0; i < nr_objs; i++) {
		//throttle generated requests
		if (mio->pending_reqs >= peer->nr_ops)
			wait_on_pr(pr, mio->pending_reqs >= peer->nr_ops);

		mn = get_mapnode(map, i);
		if (!mn) {
			XSEGLOG2(&lc, E, "Could not get map node %llu for map %s",
					i, map->volume);
			mio->err = 1;
			break;
		}

		if (mn->state & MF_OBJECT_NOT_READY) {
			XSEGLOG2(&lc, E, "BUG: object not ready");
			wait_on_mapnode(mn, mn->state & MF_OBJECT_NOT_READY);
		}

		if (mn->flags & MF_OBJECT_ZERO
			|| mn->flags & MF_OBJECT_DELETED
			|| !(mn->flags & MF_OBJECT_ARCHIP && mn->flags & MF_OBJECT_WRITABLE)) {
			//only remove writable archipelago objects.
			//skip already deleted
			XSEGLOG2(&lc, D, "Skipping object %s", mn->object);
			put_mapnode(mn);
			continue;
		}
		XSEGLOG2(&lc, D, "%s flags:\n  Writable: %s\n  Zero: %s\n"
				"  Deleted: %s\n  Archip: %s", mn->object,
				(mn->flags & MF_OBJECT_WRITABLE ? "yes" : "no"),
				(mn->flags & MF_OBJECT_ZERO? "yes" : "no"),
				(mn->flags & MF_OBJECT_DELETED? "yes" : "no"),
				(mn->flags & MF_OBJECT_ARCHIP? "yes" : "no"));

		req = __object_delete(pr, mn);
		if (!req) {
			put_mapnode(mn);
			XSEGLOG2(&lc, E, "Error removing object %s", mn->object);
			mio->err = 1;
		}
		//mapnode will be put by delete_object on completion
	}

	if (mio->pending_reqs > 0)
		wait_on_pr(pr, mio->pending_reqs > 0);

	if (mio->err) {
		XSEGLOG2(&lc, E, "Error while removing objects of %s", map->volume);
		map->state &= ~MF_MAP_DELETING;
		return -1;
	}

	map->flags |= MF_MAP_DELETED;

	mio->cb = NULL;
	mio->pending_reqs = 0;
	/* Also, we could delete/truncate the unnecessary map blocks */
	r = write_map_metadata(pr, map);
	if (r < 0){
		map->state &= ~MF_MAP_DELETING;
		XSEGLOG2(&lc, E, "Failed to destroy map %s", map->volume);
		return -1;
	}
/*
	r = delete_map_data(pr, map);
	if (r < 0) {
		//not fatal. Just log warning
		XSEGLOG2(&lc, E, "Delete map data failed for %s", map->volume);
	}
*/
	map->state &= ~MF_MAP_DELETING;
	XSEGLOG2(&lc, I, "Deleted map %s", map->volume);
	/* do close will drop the map from cache  */

	do_close(pr, map);
	/* if do_close fails, an error message will be logged, but the deletion
	 * was successfull, and there isn't much to do about the error.
	 */
	return 0;
}

static int do_rename(struct peer_req *pr, struct map *map)
{
	uint64_t i;
	struct peerd *peer = pr->peer;
	struct mapper_io *mio = __get_mapper_io(pr);
	struct map_node *mn;
	uint64_t nr_objs;
	struct map *new_map;
	struct xseg_request_rename *xrename;
	char *newname;
	uint32_t newnamelen;
	int r;

	xrename = (struct xseg_request_rename *)xseg_get_data(peer->xseg, pr->req);
	if (!xrename) {
		return -1;
	}
	newname = xrename->target;
	newnamelen = xrename->targetlen;

	if (!newnamelen) {
		XSEGLOG2(&lc, E, "A new name must be provided");
		return -1;
	}

	if (!(map->state & MF_MAP_EXCLUSIVE)) {
		XSEGLOG2(&lc, E, "Map was not opened exclusively");
		return -1;
	}
	XSEGLOG2(&lc, I, "Starting rename for map %s", map->volume);
	map->state |= MF_MAP_RENAMING;

	//create new map struct with name newname.
	new_map = create_map(newname, newnamelen, MF_ARCHIP);
	if (!new_map) {
		goto out_err;
	}

	//open/load map to check if snap exists
	r = open_map(pr, new_map, 0);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Could not open new map");
		XSEGLOG2(&lc, E, "Rename destination exists");
		goto out_put;
	}
	r = load_map_metadata(pr, new_map);
	if (r >= 0 && !(map->flags & MF_MAP_DELETED)) {
		XSEGLOG2(&lc, E, "Rename destination exists");
		goto out_close;
	}
	if (new_map->epoch == UINT64_MAX) {
		XSEGLOG2(&lc, E, "Max epoch reached for %s", new_map->volume);
		goto out_close;
	}

	/* Populate new map fields */
	new_map->epoch++;
	new_map->objects = map->objects;
	new_map->size = map->size;
	new_map->blocksize = map->blocksize;
	new_map->nr_objs = map->nr_objs;
	new_map->flags = map->flags;

	nr_objs = map->nr_objs;

	//TODO, maybe skip that check and add an epoch number on each object.
	//Then we can check if object is writable iff object epoch == map epoch
	wait_all_map_objects_ready(map);

	//write new map
	r = write_map(pr, new_map);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Cannot write map %s", new_map->volume);
		goto out_unset;
	}
	XSEGLOG2(&lc, I, "New map %s created", new_map->volume);
	new_map->objects = NULL;
	close_map(pr, new_map);
	put_map(new_map);
	XSEGLOG2(&lc, I, "Will now proceed to remove old map %s", map->volume);

	mio->cb = NULL;
	mio->pending_reqs = 0;

	map->flags |= MF_MAP_DELETED;
	r = write_map_metadata(pr, map);
	if (r < 0){
		map->state &= ~MF_MAP_RENAMING;
		XSEGLOG2(&lc, E, "Failed to destroy map %s", map->volume);
		return -1;
	}

	r = delete_map_data(pr, map);
	if (r < 0) {
		//not fatal. Just log warning
		XSEGLOG2(&lc, E, "Delete map data failed for %s", map->volume);
	}

	map->state &= ~MF_MAP_RENAMING;
	XSEGLOG2(&lc, I, "Deleted map %s", map->volume);
	/* do close will drop the map from cache  */

	/* if do_close fails, an error message will be logged, but the deletion
	 * was successfull, and there isn't much to do about the error.
	 */
	do_close(pr, map);
	XSEGLOG2(&lc, I, "Renamed %s completed ", map->volume);
	return 0;

out_unset:
	new_map->objects = NULL;
out_close:
	close_map(pr, new_map);
out_put:
	put_map(new_map);
out_err:
	map->state &= ~MF_MAP_RENAMING;
	XSEGLOG2(&lc, E, "Rename for map %s failed", map->volume);
	return -1;
}


static int do_mapr(struct peer_req *pr, struct map *map)
{
	struct peerd *peer = pr->peer;
	int r = req2objs(pr, map, 0);
	if  (r < 0){
		XSEGLOG2(&lc, I, "Map r of map %s, range: %llu-%llu failed",
				map->volume, 
				(unsigned long long) pr->req->offset, 
				(unsigned long long) (pr->req->offset + pr->req->size));
		return -1;
	}
	XSEGLOG2(&lc, I, "Map r of map %s, range: %llu-%llu completed",
			map->volume, 
			(unsigned long long) pr->req->offset, 
			(unsigned long long) (pr->req->offset + pr->req->size));
	XSEGLOG2(&lc, D, "Req->offset: %llu, req->size: %llu",
			(unsigned long long) pr->req->offset,
			(unsigned long long) pr->req->size);
	char buf[XSEG_MAX_TARGETLEN+1];
	struct xseg_reply_map *reply = (struct xseg_reply_map *) xseg_get_data(peer->xseg, pr->req);
	int i;
	for (i = 0; i < reply->cnt; i++) {
		XSEGLOG2(&lc, D, "i: %d, reply->cnt: %u",i, reply->cnt);
		strncpy(buf, reply->segs[i].target, reply->segs[i].targetlen);
		buf[reply->segs[i].targetlen] = 0;
		XSEGLOG2(&lc, D, "%d: Object: %s, offset: %llu, size: %llu", i, buf,
				(unsigned long long) reply->segs[i].offset,
				(unsigned long long) reply->segs[i].size);
	}
	return 0;
}

static int do_mapw(struct peer_req *pr, struct map *map)
{
	struct peerd *peer = pr->peer;
	int r;
	if (map->flags & MF_MAP_READONLY) {
		XSEGLOG2(&lc, E, "Cannot write to a read only map");
		return -1;
	}
	r = req2objs(pr, map, 1);
	if  (r < 0){
		XSEGLOG2(&lc, I, "Map w of map %s, range: %llu-%llu failed",
				map->volume, 
				(unsigned long long) pr->req->offset, 
				(unsigned long long) (pr->req->offset + pr->req->size));
		return -1;
	}
	XSEGLOG2(&lc, I, "Map w of map %s, range: %llu-%llu completed",
			map->volume, 
			(unsigned long long) pr->req->offset, 
			(unsigned long long) (pr->req->offset + pr->req->size));
	XSEGLOG2(&lc, D, "Req->offset: %llu, req->size: %llu",
			(unsigned long long) pr->req->offset,
			(unsigned long long) pr->req->size);
	char buf[XSEG_MAX_TARGETLEN+1];
	struct xseg_reply_map *reply = (struct xseg_reply_map *) xseg_get_data(peer->xseg, pr->req);
	int i;
	for (i = 0; i < reply->cnt; i++) {
		XSEGLOG2(&lc, D, "i: %d, reply->cnt: %u",i, reply->cnt);
		strncpy(buf, reply->segs[i].target, reply->segs[i].targetlen);
		buf[reply->segs[i].targetlen] = 0;
		XSEGLOG2(&lc, D, "%d: Object: %s, offset: %llu, size: %llu", i, buf,
				(unsigned long long) reply->segs[i].offset,
				(unsigned long long) reply->segs[i].size);
	}
	return 0;
}

//here map is the parent map
static int do_clone(struct peer_req *pr, struct map *map)
{
	long i, c;
	int r;
	struct peerd *peer = pr->peer;
	//struct mapperd *mapper = __get_mapperd(peer);
	char *target = xseg_get_target(peer->xseg, pr->req);
	struct map *clonemap;
	struct map_node *map_nodes, *mn;
	struct xseg_request_clone *xclone =
		(struct xseg_request_clone *) xseg_get_data(peer->xseg, pr->req);

	if (!(map->flags & MF_MAP_READONLY)) {
		XSEGLOG2(&lc, E, "Cloning is supported only from a snapshot");
		return -1;
	}

	XSEGLOG2(&lc, I, "Cloning map %s", map->volume);
	clonemap = create_map(target, pr->req->targetlen, MF_ARCHIP);
	if (!clonemap) {
		XSEGLOG2(&lc, E, "Create map %s failed");
		return -1;
	}

	/* open map to get exclusive access to map */
	r = open_map(pr, clonemap, 0);
	if (r < 0){
		XSEGLOG2(&lc, E, "Cannot open map %s", clonemap->volume);
		XSEGLOG2(&lc, E, "Target volume %s exists", clonemap->volume);
		goto out_put;
	}
	r = load_map_metadata(pr, clonemap);
	if (r >= 0 && !(clonemap->flags & MF_MAP_DELETED)) {
		XSEGLOG2(&lc, E, "Target volume %s exists", clonemap->volume);
		goto out_close;
	}

	/* Make sure, we can take at least one snapshot of the new volume */
	if (map->epoch >= UINT64_MAX - 2) {
		XSEGLOG2(&lc, E, "Max epoch reached for %s", clonemap->volume);
		goto out_close;
	}
	clonemap->flags = 0;
	clonemap->epoch++;

	if (!(xclone->size))
		clonemap->size = map->size;
	else
		clonemap->size = xclone->size;
	if (clonemap->size < map->size){
		XSEGLOG2(&lc, W, "Requested clone size (%llu) < map size (%llu)"
				"\n\t for requested clone %s",
				(unsigned long long) clonemap->size,
				(unsigned long long) map->size, clonemap->volume);
		goto out_close;
	}

	clonemap->blocksize = MAPPER_DEFAULT_BLOCKSIZE;
	//alloc and init map_nodes
	c = calc_map_obj(clonemap);
	map_nodes = calloc(c, sizeof(struct map_node));
	if (!map_nodes){
		goto out_close;
	}
	clonemap->objects = map_nodes;
	clonemap->nr_objs = c;
	for (i = 0; i < c; i++) {
		mn = get_mapnode(map, i);
		if (mn) {
			strncpy(map_nodes[i].object, mn->object, mn->objectlen);
			map_nodes[i].objectlen = mn->objectlen;
			map_nodes[i].flags = 0;
			if (mn->flags & MF_OBJECT_ARCHIP)
				map_nodes[i].flags |= MF_OBJECT_ARCHIP;
			if (mn->flags & MF_OBJECT_ZERO)
				map_nodes[i].flags |= MF_OBJECT_ZERO;
			put_mapnode(mn);
		} else {
			strncpy(map_nodes[i].object, zero_block, ZERO_BLOCK_LEN);
			map_nodes[i].objectlen = ZERO_BLOCK_LEN;
			map_nodes[i].flags = MF_OBJECT_ZERO;
		}
		map_nodes[i].object[map_nodes[i].objectlen] = 0; //NULL terminate
		map_nodes[i].state = 0;
		map_nodes[i].objectidx = i;
		map_nodes[i].map = clonemap;
		map_nodes[i].ref = 1;
		map_nodes[i].waiters = 0;
		map_nodes[i].cond = st_cond_new(); //FIXME errcheck;
	}

	r = write_map(pr, clonemap);
	if (r < 0){
		XSEGLOG2(&lc, E, "Cannot write map %s", clonemap->volume);
		goto out_close;
	}

	XSEGLOG2(&lc, I, "Cloning map %s to %s completed",
			map->volume, clonemap->volume);
	close_map(pr, clonemap);
	put_map(clonemap);
	return 0;

out_close:
	close_map(pr, clonemap);
out_put:
	put_map(clonemap);
	return -1;
}

static int open_load_map(struct peer_req *pr, struct map *map, uint32_t flags)
{
	int r, opened = 0;
	if (flags & MF_EXCLUSIVE){
		r = open_map(pr, map, flags);
		if (r < 0) {
			if (flags & MF_FORCE){
				return -1;
			}
		} else {
			opened = 1;
		}
	}
	r = load_map(pr, map);
	if (r < 0 && opened){
		close_map(pr, map);
	}
	return r;
}

struct map * get_map(struct peer_req *pr, char *name, uint32_t namelen,
			uint32_t flags)
{
	int r;
	struct peerd *peer = pr->peer;
	struct mapperd *mapper = __get_mapperd(peer);
	struct map *map = find_map_len(mapper, name, namelen, flags);
	if (!map) {
		if (flags & MF_LOAD){
			map = create_map(name, namelen, flags);
			if (!map)
				return NULL;
			r = insert_map(mapper, map);
			if (r < 0){
				XSEGLOG2(&lc, E, "Cannot insert map %s", map->volume);
				put_map(map);
			}
			__get_map(map);
			r = open_load_map(pr, map, flags);
			if (r < 0){
				dropcache(pr, map);
				/* signal map here, so any other threads that
				 * tried to get the map, but couldn't because
				 * of the opening or loading operation that
				 * failed, can continue.
				 */
				signal_map(map);
				put_map(map);
				return NULL;
			}
			/* If the map is deleted, drop everything and return
			 * NULL.
			 */
			if (map->flags & MF_MAP_DELETED){
				XSEGLOG2(&lc, E, "Loaded deleted map %s. Failing...",
						map->volume);
				do_close(pr, map);
				dropcache(pr, map);
				signal_map(map);
				put_map(map);
				return NULL;
			}

			if (map->state & MF_MAP_EXCLUSIVE) {
				/* cache map files opened exlusively,
				 * but drop the lock if map is readonly.
				 */
				if (map->flags & MF_MAP_READONLY) {
					close_map(pr, map);
				}
				map->state |= MF_MAP_CANCACHE;
			} else if (map->flags & MF_MAP_READONLY &&
					map->version == MAP_LATEST_VERSION) {
				/* always cache read only maps */
				map->state |= MF_MAP_CANCACHE;
			}
			return map;
		} else {
			return NULL;
		}
	} else {
		__get_map(map);
	}
	return map;

}

static int map_action(int (action)(struct peer_req *pr, struct map *map),
		struct peer_req *pr, char *name, uint32_t namelen, uint32_t flags)
{
	//struct peerd *peer = pr->peer;
	struct map *map;
start:
	map = get_map(pr, name, namelen, flags);
	if (!map)
		return -1;
	if (map->state & MF_MAP_NOT_READY){
		wait_on_map(map, (map->state & MF_MAP_NOT_READY));
		put_map(map);
		goto start;
	}
	int r = action(pr, map);
	//always drop cache if map not read exclusively
	if (!(map->state & MF_MAP_CANCACHE))
		dropcache(pr, map);
	signal_map(map);
	put_map(map);
	return r;
}

void * handle_info(struct peer_req *pr)
{
	struct peerd *peer = pr->peer;
	char *target = xseg_get_target(peer->xseg, pr->req);
	int r = map_action(do_info, pr, target, pr->req->targetlen,
				MF_ARCHIP|MF_LOAD);
	if (r < 0)
		fail(peer, pr);
	else
		complete(peer, pr);
	ta--;
	return NULL;
}

void * handle_clone(struct peer_req *pr)
{
	int r;
	struct peerd *peer = pr->peer;
	//struct mapperd *mapper = __get_mapperd(peer);
	struct xseg_request_clone *xclone;
	xclone = (struct xseg_request_clone *) xseg_get_data(peer->xseg, pr->req);
	if (!xclone) {
		r = -1;
		goto out;
	}

	if (xclone->targetlen) {
		r = map_action(do_clone, pr, xclone->target,
				xclone->targetlen, MF_LOAD|MF_ARCHIP);
	} else {
		/* else try to create a new volume */
		XSEGLOG2(&lc, I, "Creating volume");
		if (!xclone->size){
			XSEGLOG2(&lc, E, "Cannot create volume. Size not specified");
			r = -1;
			goto out;
		}
		struct map *map;
		char *target = xseg_get_target(peer->xseg, pr->req);

		//create a new empty map of size
		map = create_map(target, pr->req->targetlen, MF_ARCHIP);
		if (!map) {
			r = -1;
			goto out;
		}
		/* open map to get exclusive access to map */
		r = open_map(pr, map, 0);
		if (r < 0) {
			XSEGLOG2(&lc, E, "Cannot open map %s", map->volume);
			XSEGLOG2(&lc, E, "Target volume %s exists", map->volume);
			put_map(map);
			r = -1;
			goto out;
		}
		r = load_map_metadata(pr, map);
		if (r >= 0 && !(map->flags & MF_MAP_DELETED)) {
			XSEGLOG2(&lc, E, "Map exists %s", map->volume);
			close_map(pr, map);
			put_map(map);
			r = -1;
			goto out;
		}
		if (map->epoch >= UINT64_MAX - 2) {
			XSEGLOG2(&lc, E, "Max epoch reached for %s", map->volume);
			close_map(pr, map);
			put_map(map);
			r = -1;
			goto out;
		}
		map->epoch++;
		map->flags = 0;
		map->size = xclone->size;
		map->blocksize = MAPPER_DEFAULT_BLOCKSIZE;
		map->nr_objs = calc_map_obj(map);
		uint64_t nr_objs = map->nr_objs;
		//populate_map with zero objects;

		struct map_node *map_nodes = calloc(nr_objs, sizeof(struct map_node));
		if (!map_nodes){
			XSEGLOG2(&lc, E, "Cannot allocate %llu nr_objs", nr_objs);
			close_map(pr, map);
			put_map(map);
			r = -1;
			goto out;
		}
		map->objects = map_nodes;

		uint64_t i;
		for (i = 0; i < nr_objs; i++) {
			strncpy(map_nodes[i].object, zero_block, ZERO_BLOCK_LEN);
			map_nodes[i].objectlen = ZERO_BLOCK_LEN;
			map_nodes[i].object[map_nodes[i].objectlen] = 0; //NULL terminate
			map_nodes[i].flags = MF_OBJECT_ZERO ; //MF_OBJECT_ARCHIP;
			map_nodes[i].state = 0;
			map_nodes[i].objectidx = i;
			map_nodes[i].map = map;
			map_nodes[i].ref = 1;
			map_nodes[i].waiters = 0;
			map_nodes[i].cond = st_cond_new(); //FIXME errcheck;
		}
		r = write_map(pr, map);
		if (r < 0){
			XSEGLOG2(&lc, E, "Cannot write map %s", map->volume);
			close_map(pr, map);
			put_map(map);
			goto out;
		}
		XSEGLOG2(&lc, I, "Volume %s created", map->volume);
		r = 0;
		close_map(pr, map);
		put_map(map);
	}
out:
	if (r < 0)
		fail(peer, pr);
	else
		complete(peer, pr);
	ta--;
	return NULL;
}

void * handle_create(struct peer_req *pr)
{
	int r;
	struct peerd *peer = pr->peer;
	struct xseg_request *req = pr->req;
	//struct mapperd *mapper = __get_mapperd(peer);
	XSEGLOG2(&lc, I, "Creating volume");
	if (!req->size){
		XSEGLOG2(&lc, E, "Cannot create volume. Size not specified");
		r = -1;
		goto out;
	}
	struct map *map;
	char *target = xseg_get_target(peer->xseg, pr->req);

	//create a new empty map of size
	//ARCHIP or PITHOS
	map = create_map(target, pr->req->targetlen, MF_ARCHIP);
	if (!map) {
		r = -1;
		goto out;
	}
	/* open map to get exclusive access to map */
	r = open_map(pr, map, 0);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Cannot open map %s", map->volume);
		XSEGLOG2(&lc, E, "Target volume %s exists", map->volume);
		put_map(map);
		r = -1;
		goto out;
	}
	r = load_map_metadata(pr, map);
	if (r >= 0 && !(map->flags & MF_MAP_DELETED)) {
		XSEGLOG2(&lc, E, "Map exists %s", map->volume);
		close_map(pr, map);
		put_map(map);
		r = -1;
		goto out;
	}
	if (map->epoch >= UINT64_MAX - 2) {
		XSEGLOG2(&lc, E, "Max epoch reached for %s", map->volume);
		close_map(pr, map);
		put_map(map);
		r = -1;
		goto out;
	}


	uint64_t nr_objs;
	struct xseg_request_create *mapdata;
	mapdata = (struct xseg_request_create *) xseg_get_data(peer->xseg, pr->req);

	map->epoch++;
	map->flags = 0;
	if (mapdata->create_flags & XF_MAPFLAG_READONLY) {
		map->flags |= MF_MAP_READONLY;
	} else {
		map->flags &= ~MF_MAP_READONLY;
	}
	map->size = req->size;
	if (!mapdata->blocksize) {
		map->blocksize = MAPPER_DEFAULT_BLOCKSIZE;
	} else if (!is_valid_blocksize(mapdata->blocksize)) {
		close_map(pr, map);
		put_map(map);
		r = -1;
		goto out;
	} else {
		map->blocksize = mapdata->blocksize;
	}
	map->nr_objs = calc_map_obj(map);
	map->objects = NULL;


	nr_objs = map->nr_objs;
	if (nr_objs != mapdata->cnt) {
		XSEGLOG2(&lc, E, "Map size does not match supplied objects");
		close_map(pr, map);
		put_map(map);
		r = -1;
		goto out;
	}

	struct map_node *map_nodes = calloc(nr_objs, sizeof(struct map_node));
	if (!map_nodes){
		XSEGLOG2(&lc, E, "Cannot allocate %llu nr_objs", nr_objs);
		close_map(pr, map);
		put_map(map);
		r = -1;
		goto out;
	}
	map->objects = map_nodes;

	uint64_t i;
	for (i = 0; i < nr_objs; i++) {
		map_nodes[i].objectlen = mapdata->segs[i].targetlen;
		strncpy(map_nodes[i].object, mapdata->segs[i].target,
				mapdata->segs[i].targetlen);
		map_nodes[i].object[mapdata->segs[i].targetlen] = 0;
		XSEGLOG2(&lc, D, "%d: %s (%u)", i, map_nodes[i].object,
				mapdata->segs[i].targetlen);
		map_nodes[i].state = 0;
		map_nodes[i].flags = 0;
		if (!(mapdata->segs[i].flags & XF_MAPFLAG_READONLY)) {
			map_nodes[i].flags |= MF_OBJECT_WRITABLE;
		}
		if (!strncmp(map_nodes[i].object, zero_block, ZERO_BLOCK_LEN)) {
			map_nodes[i].flags |= MF_OBJECT_ZERO;
			//assert READONLY
			if (map_nodes[i].flags & MF_OBJECT_WRITABLE) {
				XSEGLOG2(&lc, W, "Zero objects must always be READONLY");
				map_nodes[i].flags &= ~MF_OBJECT_WRITABLE;
			}
		}
		map_nodes[i].objectidx = i;
		map_nodes[i].map = map;
		map_nodes[i].ref = 1;
		map_nodes[i].waiters = 0;
		map_nodes[i].cond = st_cond_new(); //FIXME errcheck;
	}


	r = write_map(pr, map);
	if (r < 0){
		XSEGLOG2(&lc, E, "Cannot write map %s", map->volume);
		close_map(pr, map);
		put_map(map);
		goto out;
	}
	XSEGLOG2(&lc, I, "Volume %s created", map->volume);
	r = 0;
	close_map(pr, map);
	put_map(map);
out:
	if (r < 0)
		fail(peer, pr);
	else
		complete(peer, pr);
	ta--;
	return NULL;
}

void * handle_mapr(struct peer_req *pr)
{
	struct peerd *peer = pr->peer;
	char *target = xseg_get_target(peer->xseg, pr->req);
	int r = map_action(do_mapr, pr, target, pr->req->targetlen,
				MF_ARCHIP|MF_LOAD|MF_EXCLUSIVE);
	if (r < 0)
		fail(peer, pr);
	else
		complete(peer, pr);
	ta--;
	return NULL;
}

void * handle_mapw(struct peer_req *pr)
{
	struct peerd *peer = pr->peer;
	char *target = xseg_get_target(peer->xseg, pr->req);
	int r = map_action(do_mapw, pr, target, pr->req->targetlen,
				MF_ARCHIP|MF_LOAD|MF_EXCLUSIVE|MF_FORCE);
	if (r < 0)
		fail(peer, pr);
	else
		complete(peer, pr);
	XSEGLOG2(&lc, D, "Ta: %d", ta);
	ta--;
	return NULL;
}

void * handle_destroy(struct peer_req *pr)
{
	struct peerd *peer = pr->peer;
	char *target = xseg_get_target(peer->xseg, pr->req);
	/* request EXCLUSIVE access, but do not force it.
	 * check if succeeded on do_destroy
	 */
	int r = map_action(do_destroy, pr, target, pr->req->targetlen,
				MF_ARCHIP|MF_LOAD|MF_EXCLUSIVE);
	if (r < 0)
		fail(peer, pr);
	else
		complete(peer, pr);
	ta--;
	return NULL;
}

void * handle_open(struct peer_req *pr)
{
	struct peerd *peer = pr->peer;
	char *target = xseg_get_target(peer->xseg, pr->req);
	int r = map_action(do_open, pr, target, pr->req->targetlen,
				MF_ARCHIP|MF_LOAD|MF_EXCLUSIVE);
	if (r < 0)
		fail(peer, pr);
	else
		complete(peer, pr);
	ta--;
	return NULL;
}

void * handle_close(struct peer_req *pr)
{
	struct peerd *peer = pr->peer;
	char *target = xseg_get_target(peer->xseg, pr->req);
	//here we do not want to load
	int r = map_action(do_close, pr, target, pr->req->targetlen,
				MF_ARCHIP|MF_EXCLUSIVE|MF_FORCE);
	if (r < 0)
		fail(peer, pr);
	else
		complete(peer, pr);
	ta--;
	return NULL;
}

void * handle_snapshot(struct peer_req *pr)
{
	struct peerd *peer = pr->peer;
	char *target = xseg_get_target(peer->xseg, pr->req);
	/* request EXCLUSIVE access, but do not force it.
	 * check if succeeded on do_snapshot
	 */
	int r = map_action(do_snapshot, pr, target, pr->req->targetlen,
				MF_ARCHIP|MF_LOAD|MF_EXCLUSIVE);
	if (r < 0)
		fail(peer, pr);
	else
		complete(peer, pr);
	ta--;
	return NULL;
}

void * handle_rename(struct peer_req *pr)
{
	struct peerd *peer = pr->peer;
	char *target = xseg_get_target(peer->xseg, pr->req);
	/* request EXCLUSIVE access, but do not force it.
	 * check if succeeded on do_snapshot
	 */
	int r = map_action(do_rename, pr, target, pr->req->targetlen,
				MF_ARCHIP|MF_LOAD|MF_EXCLUSIVE);
	if (r < 0)
		fail(peer, pr);
	else
		complete(peer, pr);
	ta--;
	return NULL;
}

void * handle_hash(struct peer_req *pr)
{
	struct peerd *peer = pr->peer;
	char *target = xseg_get_target(peer->xseg, pr->req);
	/* Do not request exclusive access. Since we are hashing only shapshots
	 * which are read only, there is no need for locking
	 */
	int r = map_action(do_hash, pr, target, pr->req->targetlen,
				MF_ARCHIP|MF_LOAD);
	if (r < 0)
		fail(peer, pr);
	else
		complete(peer, pr);
	ta--;
	return NULL;
}

int dispatch_accepted(struct peerd *peer, struct peer_req *pr,
			struct xseg_request *req)
{
	//struct mapperd *mapper = __get_mapperd(peer);
	struct mapper_io *mio = __get_mapper_io(pr);
	void *(*action)(struct peer_req *) = NULL;

	//mio->state = ACCEPTED;
	mio->err = 0;
	mio->cb = NULL;
	cur_count++;
	mio->count = cur_count;
	switch (pr->req->op) {
		/* primary xseg operations of mapper */
		case X_CLONE: action = handle_clone; break;
		case X_MAPR: action = handle_mapr; break;
		case X_MAPW: action = handle_mapw; break;
		case X_SNAPSHOT: action = handle_snapshot; break;
		case X_INFO: action = handle_info; break;
		case X_DELETE: action = handle_destroy; break;
		case X_OPEN: action = handle_open; break;
		case X_CLOSE: action = handle_close; break;
		case X_HASH: action = handle_hash; break;
		case X_CREATE: action = handle_create; break;
		case X_RENAME: action = handle_rename; break;
		default: fprintf(stderr, "mydispatch: unknown op\n"); break;
	}
	if (action){
		ta++;
		mio->active = 1;
		st_thread_create(action, pr, 0, 0);
	}
	return 0;

}

struct cb_arg {
	struct peer_req *pr;
	struct xseg_request *req;
};

void * callback_caller(struct cb_arg *arg)
{
	struct peer_req *pr = arg->pr;
	struct xseg_request *req = arg->req;
	struct mapper_io *mio = __get_mapper_io(pr);

	mio->cb(pr, req);
	free(arg);
	ta--;
	return NULL;
}

int dispatch(struct peerd *peer, struct peer_req *pr, struct xseg_request *req,
		enum dispatch_reason reason)
{
	struct mapper_io *mio = __get_mapper_io(pr);
	struct cb_arg *arg;

	if (reason == dispatch_accept)
		dispatch_accepted(peer, pr, req);
	else {
		if (mio->cb){
//			mio->cb(pr, req);
			arg = malloc(sizeof(struct cb_arg));
			if (!arg) {
				XSEGLOG2(&lc, E, "Cannot allocate cb_arg");
				return -1;
			}
			arg->pr = pr;
			arg->req = req;
			ta++;
		//	mio->active = 1;
			st_thread_create(callback_caller, arg, 0, 0);
		} else {
			signal_pr(pr);
		}
	}
	return 0;
}

int custom_peer_init(struct peerd *peer, int argc, char *argv[])
{
	int i;

	//FIXME error checks
	struct mapperd *mapper = malloc(sizeof(struct mapperd));
	peer->priv = mapper;
	//mapper = mapperd;
	mapper->hashmaps = xhash_new(3, 0, XHASH_STRING);

	for (i = 0; i < peer->nr_ops; i++) {
		struct mapper_io *mio = malloc(sizeof(struct mapper_io));
		mio->copyups_nodes = xhash_new(3, 0, XHASH_INTEGER);
		mio->pending_reqs = 0;
		mio->err = 0;
		mio->active = 0;
		peer->peer_reqs[i].priv = mio;
	}

	mapper->bportno = -1;
	mapper->mbportno = -1;
	BEGIN_READ_ARGS(argc, argv);
	READ_ARG_ULONG("-bp", mapper->bportno);
	READ_ARG_ULONG("-mbp", mapper->mbportno);
	END_READ_ARGS();
	if (mapper->bportno == -1){
		XSEGLOG2(&lc, E, "Portno for blocker must be provided");
		usage(argv[0]);
		return -1;
	}
	if (mapper->mbportno == -1){
		XSEGLOG2(&lc, E, "Portno for mblocker must be provided");
		usage(argv[0]);
		return -1;
	}

	const struct sched_param param = { .sched_priority = 99 };
	sched_setscheduler(syscall(SYS_gettid), SCHED_FIFO, &param);
	/* FIXME maybe place it in peer
	 * should be done for each port (sportno to eportno)
	 */
	xseg_set_max_requests(peer->xseg, peer->portno_start, 5000);
	xseg_set_freequeue_size(peer->xseg, peer->portno_start, 3000, 0);

	req_cond = st_cond_new();

//	test_map(peer);

	return 0;
}

/* FIXME this should not be here */
int wait_reply(struct peerd *peer, struct xseg_request *expected_req)
{
	struct xseg *xseg = peer->xseg;
	xport portno_start = peer->portno_start;
	xport portno_end = peer->portno_end;
	struct peer_req *pr;
	xport i;
	int  r, c = 0;
	struct xseg_request *received;
	xseg_prepare_wait(xseg, portno_start);
	while(1) {
		XSEGLOG2(&lc, D, "Attempting to check for reply");
		c = 1;
		while (c){
			c = 0;
			for (i = portno_start; i <= portno_end; i++) {
				received = xseg_receive(xseg, i, 0);
				if (received) {
					c = 1;
					r =  xseg_get_req_data(xseg, received, (void **) &pr);
					if (r < 0 || !pr || received != expected_req){
						XSEGLOG2(&lc, W, "Received request with no pr data\n");
						xport p = xseg_respond(peer->xseg, received, peer->portno_start, X_ALLOC);
						if (p == NoPort){
							XSEGLOG2(&lc, W, "Could not respond stale request");
							xseg_put_request(xseg, received, portno_start);
							continue;
						} else {
							xseg_signal(xseg, p);
						}
					} else {
						xseg_cancel_wait(xseg, portno_start);
						return 0;
					}
				}
			}
		}
		xseg_wait_signal(xseg, peer->sd, 1000000UL);
	}
}


void custom_peer_finalize(struct peerd *peer)
{
	struct mapperd *mapper = __get_mapperd(peer);
	struct peer_req *pr = alloc_peer_req(peer);
	if (!pr){
		XSEGLOG2(&lc, E, "Cannot get peer request");
		return;
	}
	struct map *map;
	struct xseg_request *req;
	xhash_iter_t it;
	xhashidx key, val;
	xhash_iter_init(mapper->hashmaps, &it);
	while (xhash_iterate(mapper->hashmaps, &it, &key, &val)){
		map = (struct map *)val;
		if (!(map->state & MF_MAP_EXCLUSIVE))
			continue;
		req = __close_map(pr, map);
		if (!req)
			continue;
		wait_reply(peer, req);
		if (!(req->state & XS_SERVED))
			XSEGLOG2(&lc, E, "Couldn't close map %s", map->volume);
		map->state &= ~MF_MAP_CLOSING;
		put_request(pr, req);
	}
	return;


}
/*
void print_obj(struct map_node *mn)
{
	fprintf(stderr, "[%llu]object name: %s[%u] exists: %c\n", 
			(unsigned long long) mn->objectidx, mn->object, 
			(unsigned int) mn->objectlen, 
			(mn->flags & MF_OBJECT_WRITABLE) ? 'y' : 'n');
}

void print_map(struct map *m)
{
	uint64_t nr_objs = m->size/MAPPER_DEFAULT_BLOCKSIZE;
	if (m->size % MAPPER_DEFAULT_BLOCKSIZE)
		nr_objs++;
	fprintf(stderr, "Volume name: %s[%u], size: %llu, nr_objs: %llu, version: %u\n", 
			m->volume, m->volumelen, 
			(unsigned long long) m->size, 
			(unsigned long long) nr_objs,
			m->version);
	uint64_t i;
	struct map_node *mn;
	if (nr_objs > 1000000) //FIXME to protect against invalid volume size
		return;
	for (i = 0; i < nr_objs; i++) {
		mn = find_object(m, i);
		if (!mn){
			printf("object idx [%llu] not found!\n", (unsigned long long) i);
			continue;
		}
		print_obj(mn);
	}
}
*/
