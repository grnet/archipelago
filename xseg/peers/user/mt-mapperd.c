#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>
#include <xseg/xseg.h>
#include <mpeer.h>
#include <time.h>
#include <sys/sha256.h>
#include <xtypes/xlock.h>
#include <xtypes/xhash.h>
#include <xseg/protocol.h>

#define PENDING 1;


#define XSEG_MAX_TARGET_LEN (SHA256_DIGEST_SIZE << 1) // hex representation of sha256 value takes up double the sha256 size

#define block_size (1<<20)
#define objectsize_in_map (1 + XSEG_MAX_TARGET_LEN) //(transparency byte + max object len)
#define mapheader_size (SHA256_DIGEST_SIZE + (sizeof(uint64_t)) + XSEG_MAX_TARGET_LEN) //volume size + max volume len

#define MF_OBJECT_EXIST		(1 << 0)
#define MF_OBJECT_COPYING	(1 << 1)

char *magic_string = "This a magic string. Please hash me";
char magic_sha256[SHA256_DIGEST_SIZE];
char zero_block[SHA256_DIGEST_SIZE * 2]; 

struct map_node {
	struct xlock lock;
	uint32_t flags;
	uint32_t objectlen;
	uint32_t objectidx;
	char object[XSEG_MAX_TARGET_LEN + 1]; /* NULL terminated string */
	struct xq pending; /* pending peer_reqs on this object */
};

#define MF_MAP_LOADING (1 << 0)
#define MF_MAP_ABORT (1 << 1)

struct map {
	uint32_t flags;
	uint64_t size;
	uint32_t volumelen;
	char volume[XSEG_MAX_TARGET_LEN + 1]; /* NULL terminated string */
	struct xlock lock; 
	xhash_t *objects; // obj_index --> map_node
	struct xq pending; /* pending peer_reqs on this map */
};

struct mapperd {
	xport bportno;
	struct xlock maps_lock;
	xhash_t *hashmaps; // hash_function(target) --> struct map
};

struct mapper_io {
	struct xlock lock;
	volatile uint32_t copyups;
	xhash_t *copyups_nodes;
	int err;
};

static inline struct mapperd * __get_mapperd(struct peerd *peer)
{
	return (struct mapperd *) peer->priv;
}

static inline struct mapper_io * __get_mapper_io(struct peer_req *pr)
{
	return (struct mapper_io *) pr->priv;
}

static struct map * __find_map(struct mapperd *mapper, char *target, uint32_t targetlen)
{
	int r;
	struct map *m;
	char buf[XSEG_MAX_TARGET_LEN+1];
	//assert targetlen <= XSEG_MAX_TARGET_LEN
	strncpy(buf, target, targetlen);
	buf[targetlen] = 0;
	r = xhash_lookup(mapper->hashmaps, (xhashidx) buf, (xhashidx *) &m);
	if (!r)
		return NULL;
	return m;
}

static struct map * find_map(struct mapperd *mapper, char *target, uint32_t targetlen)
{
	struct map *m = NULL;

	xlock_acquire(&mapper->maps_lock, 1);
	m = __find_map(mapper, target, targetlen);
	xlock_release(&mapper->maps_lock);

	return m;
}

static int insert_map(struct mapperd *mapper, struct map *map)
{
	int r = -1;
	
	xlock_acquire(&mapper->maps_lock, 1);
	if (__find_map(mapper, map->volume, map->volumelen))
		goto out;
	
	r = xhash_insert(mapper->hashmaps, (xhashidx) map->volume, (xhashidx) map);
	if (r == -XHASH_ERESIZE) {
		xhashidx shift = xhash_grow_size_shift(map->objects);
		xhash_t *new_hashmap = xhash_resize(mapper->hashmaps, shift, NULL);
		if (!new_hashmap)
			goto out;
		mapper->hashmaps = new_hashmap;
		r = xhash_insert(mapper->hashmaps, (xhashidx) map->volume, (xhashidx) map);
	}
out:
	xlock_release(&mapper->maps_lock);
	return r;
}

static int remove_map(struct mapperd *mapper, struct map *map)
{
	int r = -1;
	
	xlock_acquire(&mapper->maps_lock, 1);
	//assert no pending pr on map
	
	r = xhash_delete(mapper->hashmaps, (xhashidx) map->volume);
	if (r == -XHASH_ERESIZE) {
		xhashidx shift = xhash_shrink_size_shift(map->objects);
		xhash_t *new_hashmap = xhash_resize(mapper->hashmaps, shift, NULL);
		if (!new_hashmap)
			goto out;
		mapper->hashmaps = new_hashmap;
		r = xhash_delete(mapper->hashmaps, (xhashidx) map->volume);
	}
out:
	xlock_release(&mapper->maps_lock);
	return r;
}

/* async map load */
static int load_map(struct mapperd *mapper, struct peer_req *pr, char *target, uint32_t targetlen)
{
	int r;
	xport p;
	struct xseg_request *req;
	struct peerd *peer = __get_peerd(mapper); 
	void *dummy;

	struct map *m = find_map(mapper, target, targetlen);
	if (!m) {
		m = malloc(sizeof(struct map));
		if (!m)
			goto out_err;
		m->size = -1;
		m->volumelen = -1;
		memset(m->volume, 0, XSEG_MAX_TARGET_LEN + 1);
		m->flags = MF_MAP_LOADING;
		xqindex *qidx = xq_alloc_empty(&m->pending, peer->nr_ops);
		if (!qidx) {
			goto out_map;
		}
		m->objects = xhash_new(3, STRING); //FIXME err_check;
		__xq_append_tail(&m->pending, (xqindex) pr);
		xlock_release(&m->lock);
	} else {
		goto map_exists;
	}

	r = insert_map(mapper, m);
	if (r < 0) { //	someone beat us (or resize error) 
		xq_free(&m->pending);
		free(m);
		m = find_map(mapper, target, targetlen);
		if (!m)
			goto out_err;
		goto map_exists;
	}

	req = xseg_get_request(peer->xseg, peer->portno, mapper->bportno, X_ALLOC);
	if (!req)
		goto out_fail;

	r = xseg_prep_request(peer->xseg, req, targetlen, block_size);
	if (r < 0)
		goto out_put;

	char *reqtarget = xseg_get_target(peer->xseg, req);
	if (!reqtarget)
		goto out_put;
	strncpy(reqtarget, target, targetlen);
	req->op = X_READ;
	req->size = block_size;
	req->offset = 0;
	r = xseg_set_req_data(peer->xseg, req, pr);
	if (r < 0)
		goto out_put;
	p = xseg_submit(peer->xseg, req, peer->portno, X_ALLOC);
	if (p == NoPort) 
		goto out_unset;
	r = xseg_signal(peer->xseg, p);
	
	return 0;

out_unset:
	xseg_get_req_data(peer->xseg, req, &dummy);
out_put:
	xseg_put_request(peer->xseg, req, peer->portno);

out_fail:
	//remove m from maps
	//fail pending reqs;	//FIXME possible race if someone got map but not appended pr to pending yet
				// probably refcount with get/put will help 
	remove_map(mapper, m);
	xqindex idx;
	while((idx = xq_pop_head(&m->pending, 1)) != Noneidx) {
		fail(peer, (struct peer_req *) idx);
	}
//out_q:
	xq_free(&m->pending);
out_map:
	free(m);
out_err:
	return -1;

map_exists:
	xlock_acquire(&m->lock, 1);
	if (m->flags & MF_MAP_LOADING) {
		__xq_append_tail(&m->pending, (xqindex) pr);
		xlock_release(&m->lock);
	}
	else {
		xlock_release(&m->lock);
	 	dispatch(peer, pr, pr->req);
	}
	return 0;
}


#define MAP_LOADING 1
static int find_or_load_map(struct mapperd *mapper, struct peer_req *pr, 
				char *target, uint32_t targetlen, struct map **m)
{
	int r;
	*m = find_map(mapper, target, targetlen);
	if (*m) {
		xlock_acquire(&((*m)->lock), 1);
		if ((*m)->flags & MF_MAP_LOADING) {
			__xq_append_tail(&(*m)->pending, (xqindex) pr);
			xlock_release(&((*m)->lock));
			return MAP_LOADING;
		} else {
			xlock_release(&((*m)->lock));
			return 0;
		}
	}
	r = load_map(mapper, pr, target, targetlen);
	if (r < 0)
		return -1; //error
	return MAP_LOADING;	
}



struct map_node *find_object(struct map *map, uint64_t obj_index)
{
	struct map_node *mn;
	int r = xhash_lookup(map->objects, obj_index, (xhashidx *) &mn);
	if (!r)
		return NULL;
	return mn;
}

static int insert_object(struct map *map, struct map_node *mn)
{
	//FIXME no find object first
	int r = xhash_insert(map->objects, mn->objectidx, (xhashidx) mn);
	if (r == -XHASH_ERESIZE) {
		unsigned long shift = xhash_grow_size_shift(map->objects);
		map->objects = xhash_resize(map->objects, shift, NULL);
		if (!map->objects)
			return -1;
		r = xhash_insert(map->objects, mn->objectidx, (xhashidx) mn);
	}
	return r;
}

static inline void object_to_map(char* buf, struct map_node *mn)
{
	buf[0] = (mn->flags & MF_OBJECT_EXIST)? 1 : 0;
	memcpy(buf+1, mn->object, mn->objectlen);
	memset(buf+1+mn->objectlen, 0, XSEG_MAX_TARGET_LEN - mn->objectlen); //zero out the rest of the buffer
}

static int object_write(struct peerd *peer, struct peer_req *pr, 
				struct map *map, uint64_t objidx)
{
	void *dummy;
	struct mapperd *mapper = __get_mapperd(peer);
	struct map_node *mn = find_object(map, objidx);
	if (!mn)
		goto out_err;
	struct xseg_request *req = xseg_get_request(peer->xseg, peer->portno,
							mapper->bportno, X_ALLOC);
	if (!req)
		goto out_err;
	int r = xseg_prep_request(peer->xseg, req, mn->objectlen, objectsize_in_map);
	if (r < 0)
		goto out_put;
	char *target = xseg_get_target(peer->xseg, req);
	strncpy(target, mn->object, mn->objectlen);
	req->size = objectsize_in_map;
	req->offset = mapheader_size + objidx * objectsize_in_map;
	req->op = X_WRITE;
	char *data = xseg_get_data(peer->xseg, req);
	object_to_map(data, mn);

	r = xseg_set_req_data(peer->xseg, req, pr);
	if (r < 0)
		goto out_put;
	xport p = xseg_submit(peer->xseg, req, peer->portno, X_ALLOC);
	if (p == NoPort)
		goto out_unset;
	r = xseg_signal(peer->xseg, p);

	return PENDING;

out_unset:
	xseg_get_req_data(peer->xseg, req, &dummy);
out_put:
	xseg_put_request(peer->xseg, req, peer->portno);
out_err:
	return -1;
}

static inline void mapheader_to_map(struct map *m, char *buf)
{
	uint64_t pos = 0;
	memcpy(buf + pos, SHA256_DIGEST_SIZE, magic_sha256);
	pos += SHA256_DIGEST_SIZE;
	memcpy(buf + pos, &m->size, sizeof(m->size));
	pos += sizeof(m->size);
	memcpy(buf + pos, m->volume, m->volumelen);
	pos += m->volumelen;
	memset(buf + pos, 0, XSEG_MAX_TARGET_LEN - m->volumelen);
}

static int map_write(struct peerd *peer, struct peer_req* pr, struct map *map)
{
	void *dummy;
	struct mapperd *mapper = __get_mapperd(peer);
	struct map_node *mn;
	uint64_t i, pos, max_objidx = map->size / block_size;
	struct xseg_request *req = xseg_get_request(peer->xseg, peer->portno, 
							mapper->bportno, X_ALLOC);
	if (!req)
		goto out_err;
	int r = xseg_prep_request(peer->xseg, req, map->volumelen, 
					mapheader_size + max_objidx * objectsize_in_map);
	if (r < 0)
		goto out_put;
	char *data = xseg_get_data(peer->xseg, req);
	mapheader_to_map(map, data);
	pos = mapheader_size;

	if (map->size % block_size)
		max_objidx++;
	for (i = 0; i < max_objidx; i++) {
		mn = find_object(map, i);
		if (!mn)
			goto out_put;
		object_to_map(data+pos, mn);
		pos += objectsize_in_map;
	}
	r = xseg_set_req_data(peer->xseg, req, pr);
	if (r < 0)
		goto out_put;
	xport p = xseg_submit(peer->xseg, req, peer->portno, X_ALLOC);
	if (p == NoPort)
		goto out_unset;
	r = xseg_signal(peer->xseg, p);
	return PENDING;

out_unset:
	xseg_get_req_data(peer->xseg, req, &dummy);
out_put:
	xseg_put_request(peer->xseg, req, peer->portno);
out_err:
	return -1;
}

static int __set_copyup_node(struct mapper_io *mio, struct xseg_request *req, struct map_node *mn)
{
	int r = 0;
	if (mn){
		r = xhash_insert(mio->copyups_nodes, (xhashidx) req, (xhashidx) mn);
		if (r == -XHASH_ERESIZE) {
			xhashidx shift = xhash_grow_size_shift(mio->copyups_nodes);
			xhash_t *new_hashmap = xhash_resize(mio->copyups_nodes, shift, NULL);
			if (!new_hashmap)
				goto out;
			mio->copyups_nodes = new_hashmap;
			r = xhash_insert(mio->copyups_nodes, (xhashidx) req, (xhashidx) mn);
		}
	}
	else {
		r = xhash_delete(mio->copyups_nodes, (xhashidx) req);
		if (r == -XHASH_ERESIZE) {
			xhashidx shift = xhash_shrink_size_shift(mio->copyups_nodes);
			xhash_t *new_hashmap = xhash_resize(mio->copyups_nodes, shift, NULL);
			if (!new_hashmap)
				goto out;
			mio->copyups_nodes = new_hashmap;
			r = xhash_delete(mio->copyups_nodes, (xhashidx) req);
		}
	}
out:
	return r;
}

static struct map_node * __get_copyup_node(struct mapper_io *mio, struct xseg_request *req)
{
	struct map_node *mn;
	int r = xhash_lookup(mio->copyups_nodes, (xhashidx) req, (xhashidx *) &mn);
	if (r < 0)
		return NULL;
	return mn;
}

// mn->lock held,
static int copyup_object(struct peerd *peer, struct map_node *mn, struct peer_req *pr)
{
	struct mapperd *mapper = __get_mapperd(peer);
	struct mapper_io *mio = __get_mapper_io(pr);
	void *dummy;
	int r = -1, i;
	xport p;
	struct sha256_ctx sha256ctx;
	uint32_t newtargetlen;
	char new_target[XSEG_MAX_TARGET_LEN], buf[SHA256_DIGEST_SIZE];	//assert sha256_digest_size(32) <= MAXTARGETLEN
	char new_object[XSEG_MAX_TARGET_LEN + 1];
	strncpy(new_object, mn->object, mn->objectlen);
	sprintf(new_object + mn->objectlen, "%u", mn->objectidx);


	/* calculate new object name */
	sha256_init_ctx(&sha256ctx);
	sha256_process_bytes(new_object, mn->objectlen + 1, &sha256ctx);
	sha256_finish_ctx(&sha256ctx, buf);
	for (i = 0; i < SHA256_DIGEST_SIZE; ++i)
		sprintf (new_target + i, "%02x", buf[i]);
	newtargetlen = SHA256_DIGEST_SIZE;


	struct xseg_request *req = xseg_get_request(peer->xseg, peer->portno, 
							mapper->bportno, X_ALLOC);
	if (!req)
		goto out;
	r = xseg_prep_request(peer->xseg, req, newtargetlen, 
				sizeof(struct xseg_request_copy));
	if (r < 0)
		goto out_put;

	char *target = xseg_get_target(peer->xseg, req);
	strncpy(target, mn->object, mn->objectlen);
	target[mn->objectlen] = 0;

	struct xseg_request_copy *xcopy = (struct xseg_request_copy *) xseg_get_data(peer->xseg, req);
	strncpy(xcopy->target, new_target, newtargetlen);
	xcopy->target[newtargetlen] = 0;

	req->offset = 0;
	req->size = block_size;
	req->op = X_COPY;
	r = xseg_set_req_data(peer->xseg, req, pr);
	if (r<0)
		goto out_put;
	r = __set_copyup_node(mio, req, mn);
	p = xseg_submit(peer->xseg, req, peer->portno, X_ALLOC);
	if (p == NoPort) {
		r = -1;
		goto out_unset;
	}
	xseg_signal(peer->xseg, p);

	r = 0;
out:
	return r;

out_unset:
	xseg_get_req_data(peer->xseg, req, &dummy);
out_put:
	xseg_put_request(peer->xseg, req, peer->portno);
	goto out;

}

static inline void pithosmap_to_object(struct map_node *mn, char *buf)
{
	int i;
	//hexlify sha256 value
	for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
		sprintf(mn->object, "%02x", buf[i]);
	}

	mn->object[XSEG_MAX_TARGET_LEN] = 0;
	mn->objectlen = strlen(mn->object);
	mn->flags = 0;
}

static inline void map_to_object(struct map_node *mn, char *buf)
{
	char c = buf[0];
	mn->flags = 0;
	if (c)
		mn->flags |= MF_OBJECT_EXIST;
	memcpy(mn->object, buf+1, XSEG_MAX_TARGET_LEN);
	mn->object[XSEG_MAX_TARGET_LEN] = 0;
	mn->objectlen = strlen(mn->object);
}


static int read_map (struct peerd *peer, struct map *map, char *buf)
{
	//type 1, our type, type 0 pithos map
	int r, type = !memcmp(buf, magic_sha256, SHA256_DIGEST_SIZE);
	uint64_t pos;
	uint64_t i, nr_objs;
	struct map_node *map_node;
	if (type) {
		pos = SHA256_DIGEST_SIZE;
		map->size = *(uint64_t *) buf;
		pos += sizeof(uint64_t);
		nr_objs = map->size / block_size;
		if (map->size % block_size)
			nr_objs++;
		map_node = calloc(nr_objs, sizeof(struct map_node));
		if (!map_node)
			return -1;

		for (i = 0; i < nr_objs; i++) {
			map_node[i].objectidx = i;
			xlock_release(&map_node[i].lock);
			xqindex *qidx = xq_alloc_empty(&map_node[i].pending, peer->nr_ops); //FIXME error check
			map_to_object(&map_node[i], buf + pos);
			pos += objectsize_in_map;
			r = insert_object(map, &map_node[i]); //FIXME error check
		}
	} else {
		pos = 0;
		uint64_t max_nr_objs = block_size/SHA256_DIGEST_SIZE;
		map_node = calloc(max_nr_objs, sizeof(struct map_node));
		if (!map_node)
			return -1;
		for (i = 0; i < max_nr_objs; i++) {
			if (!memcmp(buf+pos, "0000000000000000", SHA256_DIGEST_SIZE))
				break;
			map_node[i].objectidx = i;
			xlock_release(&map_node[i].lock);
			xqindex *qidx = xq_alloc_empty(&map_node[i].pending, peer->nr_ops); //FIXME error check
			pithosmap_to_object(&map_node[i], buf + pos);
			pos += SHA256_DIGEST_SIZE; 
			r = insert_object(map, &map_node[i]); //FIXME error check
		}
		map->size = i * block_size; 
	}
	return 0;
}

static int handle_mapread(struct peerd *peer, struct peer_req *pr, 
				struct xseg_request *req)
{
	int r;
	xqindex idx;
	struct mapperd *mapper = __get_mapperd(peer);
	//assert req->op = X_READ;
	char *target = xseg_get_target(peer->xseg, req);
	struct map *map = find_map(mapper, target, req->targetlen);
	if (!map)
		goto out_err;
	//assert map->flags & MF_MAP_LOADING

	if (req->state & XS_FAILED)
		goto out_fail;

	char *data = data;
	r = read_map(peer, map, data);
	if (r < 0)
		goto out_err;
	
	xseg_put_request(peer->xseg, req, peer->portno);
	xlock_acquire(&map->lock, 1);
	map->flags &= ~MF_MAP_LOADING;
	while((idx = __xq_pop_head(&map->pending)) != Noneidx){
		struct peer_req *preq = (struct peer_req *) idx;
		xlock_release(&map->lock);
		dispatch(peer, preq, preq->req);
		xlock_acquire(&map->lock, 1);
	}
	xlock_release(&map->lock);
	return 0;

out_fail:
	xlock_acquire(&map->lock, 1);
	map->flags &= ~MF_MAP_LOADING;
	map->flags |= MF_MAP_ABORT;
	while((idx = __xq_pop_head(&map->pending)) != Noneidx){
		struct peer_req *preq = (struct peer_req *) idx;
		xlock_release(&map->lock);
		fail(peer, preq);
		xlock_acquire(&map->lock, 1);
	}
	xlock_release(&map->lock);
	remove_map(mapper, map);
	free(map);
	return 0;

out_err:
	xseg_put_request(peer->xseg, req, peer->portno);
	goto out_fail;
}

static int handle_clone(struct peerd *peer, struct peer_req *pr, 
				struct xseg_request *req)
{
	struct mapperd *mapper = __get_mapperd(peer);
	struct mapper_io *mio = __get_mapper_io(pr);
	(void) mio;
	struct xseg_request_clone *xclone = (struct xseg_request_clone *) xseg_get_data(peer->xseg, pr->req);
	if (!xclone) {
		goto out_err;
	}
	struct map *map;
	int r = find_or_load_map(mapper, pr, xclone->target, strlen(xclone->target), &map);
	if (r < 0)
		goto out_err;
	else if (r == MAP_LOADING)
		return 0;

	//alloc and init struct map
	struct map *clonemap = malloc(sizeof(struct map));
	if (!clonemap) {
		goto out_err;
	}
	clonemap->objects = xhash_new(3, INTEGER);
	if (!clonemap->objects){
		goto out_err_clonemap;
	}
	xqindex *qidx = xq_alloc_empty(&clonemap->pending, peer->nr_ops);
	if (!qidx)
		goto out_err_objhash;
	xlock_release(&clonemap->lock);
	clonemap->size = xclone->size;
	clonemap->flags = 0;
	strncpy(clonemap->volume, xclone->target, strlen(xclone->target));
	clonemap->volumelen = strlen(xclone->target);
	clonemap->volume[clonemap->volumelen] = 0; //NULL TERMINATE

	//alloc and init map_nodes
	unsigned long c = xclone->size/block_size + 1;
	struct map_node *map_nodes = calloc(c, sizeof(struct map_node));
	if (!map_nodes){
		goto out_err_q;
	}
	int i;
	for (i = 0; i < xclone->size/block_size + 1; i++) {
		strncpy(map_nodes[i].object, zero_block, strlen(zero_block)); //FIXME copy object name from father
		map_nodes[i].objectlen = strlen(zero_block);
		map_nodes[i].object[map_nodes[i].objectlen] = 0; //NULL terminate
		map_nodes[i].flags = 0;
		map_nodes[i].objectidx = i;
		xlock_release(&map_nodes[i].lock);
		r = insert_object(map, &map_nodes[i]);
		if (r < 0)
			goto out_free_all;
	}
	//insert map
	r = insert_map(mapper, clonemap);
	if ( r < 0) {
		goto out_free_all;
	}

	complete(peer, pr);
	return 0;

out_free_all:
	//FIXME not freeing allocated queues of map_nodes
	free(map_nodes);
out_err_q:
	xq_free(&clonemap->pending);
out_err_objhash:
	xhash_free(clonemap->objects);
out_err_clonemap:
	free(clonemap);
out_err:
	fail(peer, pr);
	return -1;
}

static uint32_t calc_nr_obj(struct xseg_request *req)
{
	unsigned int r = 1;
	uint64_t rem_size = req->size;
	uint64_t obj_offset = req->offset & (block_size -1); //modulo
	uint64_t obj_size =  block_size - obj_offset;
	while (rem_size > 0) {
		obj_size = (rem_size - block_size > 0) ? block_size : rem_size;
		rem_size -= obj_size;
		r++;
	}

	return r;
}

static int req2objs(struct peerd *peer, struct peer_req *pr, 
					struct map *map, int write)
{
	char *target = xseg_get_target(peer->xseg, pr->req);
	uint32_t nr_objs = calc_nr_obj(pr->req);
	uint64_t size = sizeof(struct xseg_reply_map) + 
			nr_objs * sizeof(struct xseg_reply_map_scatterlist);

	/* resize request to fit reply */
	char buf[XSEG_MAX_TARGET_LEN];
	strncpy(buf, target, pr->req->targetlen);
	int r = xseg_resize_request(peer->xseg, pr->req, pr->req->targetlen, size);
	if (r < 0) {
		return -1;
	}
	target = xseg_get_target(peer->xseg, pr->req);
	strncpy(target, buf, pr->req->targetlen);

	/* structure reply */
	struct xseg_reply_map *reply = (struct xseg_reply_map *) xseg_get_data(peer->xseg, pr->req);
	reply->cnt = nr_objs;

	uint32_t idx = 0;
	uint64_t rem_size = pr->req->size;
	uint64_t obj_index = pr->req->offset / block_size;
	uint64_t obj_offset = pr->req->offset & (block_size -1); //modulo
	uint64_t obj_size =  block_size - obj_offset;
	struct map_node * mn = find_object(map, obj_index);
	if (!mn) {
		goto out_err;
	}
	xlock_acquire(&mn->lock, 1);
	if (mn->flags & MF_OBJECT_COPYING) 
		goto out_object_copying;
	if (write && !(mn->flags & MF_OBJECT_EXIST)) {
		//calc new_target, copy up object
		r = copyup_object(peer, mn, pr);
		if (r < 0) 
			goto out_err_copy;
		mn->flags |= MF_OBJECT_COPYING;
		goto out_object_copying;
	}

	strncpy(reply->segs[idx].target, mn->object, XSEG_MAX_TARGET_LEN); // or strlen(mn->target ?);
	reply->segs[idx].target[mn->objectlen] = 0;
	xlock_release(&mn->lock);
	reply->segs[idx].offset = obj_offset;
	reply->segs[idx].size = obj_size;
	rem_size -= obj_size;
	while (rem_size > 0) {
		idx++;
		obj_index++;
		obj_offset = 0;
		obj_size = (rem_size - block_size > 0) ? block_size : rem_size;
		rem_size -= obj_size;
		mn = find_object(map, obj_index);
		if (!mn) {
			goto out_err;
		}
		xlock_acquire(&mn->lock, 1);
		if (mn->flags & MF_OBJECT_COPYING) 
			goto out_object_copying;
		if (write && !(mn->flags & MF_OBJECT_EXIST)) {
			//calc new_target, copy up object
			r = copyup_object(peer, mn, pr);
			if (r < 0) 
				goto out_err_copy;
			mn->flags |= MF_OBJECT_COPYING;
			goto out_object_copying;
		}
		strncpy(reply->segs[idx].target, mn->object, XSEG_MAX_TARGET_LEN); // or strlen(mn->target ?);
		reply->segs[idx].target[mn->objectlen] = 0;
		xlock_release(&mn->lock);
		reply->segs[idx].offset = obj_offset;
		reply->segs[idx].size = obj_size;
	}

	return 0;

out_object_copying:
	__xq_append_tail(&mn->pending, (xqindex) pr);
	xlock_release(&mn->lock);
	return PENDING;

out_err_copy:
	xlock_release(&mn->lock);
out_err:
	return -1;
}

static int handle_mapr(struct peerd *peer, struct peer_req *pr, 
				struct xseg_request *req)
{
	struct mapperd *mapper = __get_mapperd(peer);
	struct mapper_io *mio = __get_mapper_io(pr);
	(void)mio;
	//get_map
	char *target = xseg_get_target(peer->xseg, pr->req);
	struct map *map;
	int r = find_or_load_map(mapper, pr, target, pr->req->targetlen, &map);
	if (r < 0) {
		fail(peer, pr);
		return -1;
	}
	else if (r == MAP_LOADING)
		return 0;
	
	//get_object
	r = req2objs(peer, pr, map, 0);
	if  (r < 0)
		fail(peer, pr);
	else if (r == 0)
		complete(peer, pr);

	return 0;


}

static int handle_copyup(struct peerd *peer, struct peer_req *pr,
				struct xseg_request *req)
{
	struct mapperd *mapper = __get_mapperd(peer);
	(void) mapper;
	struct mapper_io *mio = __get_mapper_io(pr);
	int r = 0;
	xlock_acquire(&mio->lock, 1);
	if (req->state & XS_FAILED && !(req->state & XS_SERVED)) {
		mio->err = 1;
		r = 1;
	}
	struct map_node *mn = __get_copyup_node(mio, req);
	if (!mn)
		mio->err =1; //BUG
	else {
		xlock_acquire(&mn->lock, 1);
		mn->flags &= ~MF_OBJECT_COPYING;
		mn->flags |= MF_OBJECT_EXIST;
		if (!r) {
			struct xseg_request_copy *xcopy = (struct xseg_request_copy *) xseg_get_data(peer->xseg, req);
			strncpy(mn->object, xcopy->target, strlen(xcopy->target));
		}
		xlock_release(&mn->lock);
	}
	__set_copyup_node(mio, req, NULL);
	xseg_put_request(peer->xseg, req, peer->portno);

	mio->copyups--;
	if (!mio->copyups) {
		if (mio->err)
			fail(peer, pr);
		else
			complete(peer, pr);
	}
	xlock_release(&mio->lock);

	if (mn) {
		//handle peer_requests waiting on copy up
		xqindex idx;
		xlock_acquire(&mn->lock, 1);
		while ((idx = __xq_pop_head(&mn->pending) != Noneidx)){
			xlock_release(&mn->lock);
			struct peer_req * preq = (struct peer_req *) idx;
			dispatch(peer, preq, preq->req);
			xlock_acquire(&mn->lock, 1);
		}
		xlock_release(&mn->lock);
	}

	return 0;
}

static int handle_mapw(struct peerd *peer, struct peer_req *pr, 
				struct xseg_request *req)
{
	struct mapperd *mapper = __get_mapperd(peer);
	struct mapper_io *mio = __get_mapper_io(pr);
	(void) mio;
	/* handle copy up replies separately */
	if (req->op == X_COPY)
		return handle_copyup(peer, pr, req);

	char *target = xseg_get_target(peer->xseg, pr->req);
	struct map *map;
	int r = find_or_load_map(mapper, pr, target, pr->req->targetlen, &map);
	if (r < 0) {
		fail(peer, pr);
		return -1;
	}
	else if (r == MAP_LOADING)
		return 0;


	r = req2objs(peer, pr, map, 1);
	if (r < 0)
		fail(peer, pr);
	if (r == 0)
		complete(peer, pr);
	//else copyup pending, wait for pr restart

	return 0;
}

static int handle_snap(struct peerd *peer, struct peer_req *pr, 
				struct xseg_request *req)
{
	fail(peer, pr);
	return 0;
}

static int handle_info(struct peerd *peer, struct peer_req *pr, 
				struct xseg_request *req)
{
	struct mapperd *mapper = __get_mapperd(peer);
	struct mapper_io *mio = __get_mapper_io(pr);
	(void) mio;
	char *target = xseg_get_target(peer->xseg, pr->req);
	if (!target)
		return -1;
	struct map *map;
	int r = find_or_load_map(mapper, pr, target, pr->req->targetlen, &map);
	if (r < 0) {
		fail(peer, pr);
		return -1;
	}
	else if (r == MAP_LOADING)
		return 0;
	else {
		struct xseg_reply_info *xinfo = (struct xseg_reply_info *) xseg_get_data(peer->xseg, pr->req);
		xinfo->size = map->size;
		complete(peer, pr);
	}
	return 0;
}

static int handle_destroy(struct peerd *peer, struct peer_req *pr, 
				struct xseg_request *req)
{
	fail(peer, pr);
	return 0;
}

int dispatch(struct peerd *peer, struct peer_req *pr, struct xseg_request *req)
{
	struct mapperd *mapper = __get_mapperd(peer);
	(void) mapper;
	struct mapper_io *mio = __get_mapper_io(pr);
	(void) mio;

	if (req->op == X_READ) {
		handle_mapread(peer, pr, req);
		return 0;
	}

	switch (pr->req->op) {
		/* primary xseg operations of mapper */
		case X_CLONE: handle_clone(peer, pr, req); break;
		case X_MAPR: handle_mapr(peer, pr, req); break;
		case X_MAPW: handle_mapw(peer, pr, req); break;
//		case X_SNAPSHOT: handle_snap(peer, pr, req); break;
		case X_INFO: handle_info(peer, pr, req); break;
		case X_DELETE: handle_destroy(peer, pr, req); break;
		default: break;
	}
	return 0;
}

int custom_peer_init(struct peerd *peer, int argc, const char *argv[])
{
	int i;
	char *buf;
	struct sha256_ctx sha256ctx;
	sha256_init_ctx(&sha256ctx);
	sha256_process_bytes(magic_string, strlen(magic_string), &sha256ctx);
	sha256_finish_ctx(&sha256ctx, magic_sha256);

	buf = calloc(1, block_size);
	sha256_init_ctx(&sha256ctx);
	sha256_process_bytes(buf, block_size, &sha256ctx);
	sha256_finish_ctx(&sha256ctx, buf);
	for (i = 0; i < SHA256_DIGEST_SIZE; ++i)
		sprintf (zero_block + i, "%02x", buf[i]);

	struct mapperd *mapper = malloc(sizeof(struct mapperd));
	xlock_release(&mapper->maps_lock);
	mapper->hashmaps = xhash_new(3, STRING);
	peer->priv = mapper;
	
	for (i = 0; i < peer->nr_ops; i++) {
		struct mapper_io *mio = malloc(sizeof(struct mapper_io));
		xlock_release(&mio->lock);
		mio->copyups_nodes = xhash_new(3, INTEGER);
		mio->copyups = 0;
		mio->err = 0;
		peer->peer_reqs[i].priv = mio;
	}

	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "-bp") && (i+1) < argc){
			mapper->bportno = atoi(argv[i+1]);
			i += 1;
			continue;
		}
	}


	return 0;
}
