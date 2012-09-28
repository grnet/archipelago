#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>
#include <xseg/xseg.h>
#include <mpeer.h>
#include <time.h>
#include <xtypes/xlock.h>
#include <xtypes/xhash.h>
#include <xseg/protocol.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <gcrypt.h>
#include <errno.h>

GCRY_THREAD_OPTION_PTHREAD_IMPL;

#define MF_PENDING 1

#define SHA256_DIGEST_SIZE 32
/* hex representation of sha256 value takes up double the sha256 size */
#define HEXLIFIED_SHA256_DIGEST_SIZE (SHA256_DIGEST_SIZE << 1)

#define block_size (1<<22) //FIXME this should be defined here?
#define objectsize_in_map (1 + XSEG_MAX_TARGETLEN) /* transparency byte + max object len */
#define mapheader_size (SHA256_DIGEST_SIZE + (sizeof(uint64_t)) ) /* magic hash value  + volume size */

#define MF_OBJECT_EXIST		(1 << 0)
#define MF_OBJECT_COPYING	(1 << 1)
#define MF_OBJECT_WRITING	(1 << 2)
#define MF_OBJECT_DELETING	(1 << 3)

#define MF_OBJECT_NOT_READY	(MF_OBJECT_COPYING|MF_OBJECT_WRITING|MF_OBJECT_DELETING)
extern struct log_ctx lc;

char *magic_string = "This a magic string. Please hash me";
unsigned char magic_sha256[SHA256_DIGEST_SIZE];	/* sha256 hash value of magic string */
char zero_block[HEXLIFIED_SHA256_DIGEST_SIZE + 1]; /* hexlified sha256 hash value of a block full of zeros */

//internal mapper states
enum mapper_state {
	ACCEPTED = 0,
	WRITING = 1,
	COPYING = 2,
	DELETING = 3
};

struct map_node {
	uint32_t flags;
	uint32_t objectidx;
	uint32_t objectlen;
	char object[XSEG_MAX_TARGETLEN + 1]; 	/* NULL terminated string */
	struct xq pending; 			/* pending peer_reqs on this object */
	struct map *map;
};

#define MF_MAP_LOADING		(1 << 0)
#define MF_MAP_DESTROYED	(1 << 1)
#define MF_MAP_WRITING		(1 << 2)
#define MF_MAP_DELETING		(1 << 3)

#define MF_MAP_NOT_READY	(MF_MAP_LOADING|MF_MAP_WRITING|MF_MAP_DELETING)

struct map {
	uint32_t flags;
	uint64_t size;
	uint32_t volumelen;
	char volume[XSEG_MAX_TARGETLEN + 1]; /* NULL terminated string */
	xhash_t *objects; 	/* obj_index --> map_node */
	struct xq pending; 	/* pending peer_reqs on this map */
};

struct mapperd {
	xport bportno;		/* blocker that accesses data */
	xport mbportno;		/* blocker that accesses maps */
	xhash_t *hashmaps; // hash_function(target) --> struct map
};

struct mapper_io {
	volatile uint32_t copyups;	/* nr of copyups pending, issued by this mapper io */
	xhash_t *copyups_nodes;		/* hash map (xseg_request) --> (corresponding map_node of copied up object)*/
	struct map_node *copyup_node;
	int err;			/* error flag */
	uint64_t delobj;
	enum mapper_state state;
};

static int my_dispatch(struct peerd *peer, struct peer_req *pr, struct xseg_request *req);
void print_map(struct map *m);

/*
 * Helper functions
 */

static inline struct mapperd * __get_mapperd(struct peerd *peer)
{
	return (struct mapperd *) peer->priv;
}

static inline struct mapper_io * __get_mapper_io(struct peer_req *pr)
{
	return (struct mapper_io *) pr->priv;
}

static inline uint64_t calc_map_obj(struct map *map)
{
	uint64_t nr_objs = map->size / block_size;
	if (map->size % block_size)
		nr_objs++;
	return nr_objs;
}

static uint32_t calc_nr_obj(struct xseg_request *req)
{
	unsigned int r = 1;
	uint64_t rem_size = req->size;
	uint64_t obj_offset = req->offset & (block_size -1); //modulo
	uint64_t obj_size =  (rem_size + obj_offset > block_size) ? block_size - obj_offset : rem_size;
	rem_size -= obj_size;
	while (rem_size > 0) {
		obj_size = (rem_size > block_size) ? block_size : rem_size;
		rem_size -= obj_size;
		r++;
	}

	return r;
}

/*
 * Maps handling functions
 */

static struct map * find_map(struct mapperd *mapper, char *target, uint32_t targetlen)
{
	int r;
	struct map *m = NULL;
	char buf[XSEG_MAX_TARGETLEN+1];
	//assert targetlen <= XSEG_MAX_TARGETLEN
	strncpy(buf, target, targetlen);
	buf[targetlen] = 0;
	XSEGLOG2(&lc, E, "looking up map %s, len %u", buf, targetlen);
	r = xhash_lookup(mapper->hashmaps, (xhashidx) buf, (xhashidx *) &m);
	if (r < 0)
		return NULL;
	return m;
}


static int insert_map(struct mapperd *mapper, struct map *map)
{
	int r = -1;
	
	if (find_map(mapper, map->volume, map->volumelen)){
		XSEGLOG2(&lc, W, "Map %s found in hash maps", map->volume);
		goto out;
	}

	XSEGLOG2(&lc, E, "Inserting map %s, len: %d", map->volume, strlen(map->volume));
	r = xhash_insert(mapper->hashmaps, (xhashidx) map->volume, (xhashidx) map);
	if (r == -XHASH_ERESIZE) {
		xhashidx shift = xhash_grow_size_shift(map->objects);
		xhash_t *new_hashmap = xhash_resize(mapper->hashmaps, shift, NULL);
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
	if (r == -XHASH_ERESIZE) {
		xhashidx shift = xhash_shrink_size_shift(map->objects);
		xhash_t *new_hashmap = xhash_resize(mapper->hashmaps, shift, NULL);
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

/* async map load */
static int load_map(struct peerd *peer, struct peer_req *pr, char *target, uint32_t targetlen)
{
	int r;
	xport p;
	struct xseg_request *req;
	struct mapperd *mapper = __get_mapperd(peer);
	void *dummy;
	//printf("Loading map\n");

	struct map *m = find_map(mapper, target, targetlen);
	if (!m) {
		m = malloc(sizeof(struct map));
		if (!m){
			XSEGLOG2(&lc, E, "Cannot allocate map ");
			goto out_err;
		}
		m->size = -1;
		strncpy(m->volume, target, targetlen);
		m->volume[targetlen] = 0;
		m->volumelen = targetlen;
		m->flags = MF_MAP_LOADING;
		xqindex *qidx = xq_alloc_empty(&m->pending, peer->nr_ops);
		if (!qidx) {
			XSEGLOG2(&lc, E, "Cannot allocate pending queue for map %s",
					m->volume);
			goto out_map;
		}
		m->objects = xhash_new(3, INTEGER); 
		if (!m->objects){
			XSEGLOG2(&lc, E, "Cannot allocate object hashmap for map %s",
					m->volume);
			goto out_q;
		}
		__xq_append_tail(&m->pending, (xqindex) pr); //FIXME err check
	} else {
		goto map_exists;
	}

	r = insert_map(mapper, m);
	if (r < 0)  
		goto out_hash;
	
	//printf("Loading map: preparing req\n");

	req = xseg_get_request(peer->xseg, peer->portno, mapper->mbportno, X_ALLOC);
	if (!req){
		XSEGLOG2(&lc, E, "Cannot allocate request for map %s",
				m->volume);
		goto out_fail;
	}

	r = xseg_prep_request(peer->xseg, req, targetlen, block_size);
	if (r < 0){
		XSEGLOG2(&lc, E, "Cannot prepare request for map %s",
				m->volume);
		goto out_put;
	}

	char *reqtarget = xseg_get_target(peer->xseg, req);
	if (!reqtarget)
		goto out_put;
	strncpy(reqtarget, target, targetlen);
	req->op = X_READ;
	req->size = block_size;
	req->offset = 0;
	r = xseg_set_req_data(peer->xseg, req, pr);
	if (r < 0){
		XSEGLOG2(&lc, E, "Cannot set request data for map %s",
				m->volume);
		goto out_put;
	}
	p = xseg_submit(peer->xseg, req, peer->portno, X_ALLOC);
	if (p == NoPort){ 
		XSEGLOG2(&lc, E, "Cannot submit request for map %s",
				m->volume);
		goto out_unset;
	}
	r = xseg_signal(peer->xseg, p);
	
	XSEGLOG2(&lc, I, "Map %s loading", m->volume);
	return 0;

out_unset:
	xseg_get_req_data(peer->xseg, req, &dummy);
out_put:
	xseg_put_request(peer->xseg, req, peer->portno);

out_fail:
	remove_map(mapper, m);
	xqindex idx;
	while((idx = __xq_pop_head(&m->pending)) != Noneidx) {
		fail(peer, (struct peer_req *) idx);
	}

out_hash:
	xhash_free(m->objects);
out_q:
	xq_free(&m->pending);
out_map:
	XSEGLOG2(&lc, E, "failed to load map %s", m->volume);
	free(m);
out_err:
	return -1;

map_exists:
	//assert map loading when this is reached
	if (m->flags & MF_MAP_LOADING) {
		XSEGLOG2(&lc, I, "Map %s already exists and loading. "
				"Adding to pending queue", m->volume);
		__xq_append_tail(&m->pending, (xqindex) pr); //FIXME errcheck
	}
	else {
		XSEGLOG2(&lc, I, "Map %s already exists and loaded. Dispatching.", m->volume);
	 	my_dispatch(peer, pr, pr->req);
	}
	return 0;
}


static int find_or_load_map(struct peerd *peer, struct peer_req *pr, 
				char *target, uint32_t targetlen, struct map **m)
{
	struct mapperd *mapper = __get_mapperd(peer);
	int r;
	*m = find_map(mapper, target, targetlen);
	if (*m) {
		if ((*m)->flags & MF_MAP_NOT_READY) {
			__xq_append_tail(&(*m)->pending, (xqindex) pr);
			XSEGLOG2(&lc, I, "Map %s found and not ready", (*m)->volume);
			return MF_PENDING;
		//} else if ((*m)->flags & MF_MAP_DESTROYED){
		//	return -1;
		// 
		}else {
			XSEGLOG2(&lc, I, "Map %s found", (*m)->volume);
			return 0;
		}
	}
	r = load_map(peer, pr, target, targetlen);
	if (r < 0)
		return -1; //error
	return MF_PENDING;	
}

/*
 * Object handling functions
 */

struct map_node *find_object(struct map *map, uint64_t obj_index)
{
	struct map_node *mn;
	int r = xhash_lookup(map->objects, obj_index, (xhashidx *) &mn);
	if (r < 0)
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


/*
 * map read/write functions 
 */
static inline void pithosmap_to_object(struct map_node *mn, unsigned char *buf)
{
	int i;
	//hexlify sha256 value
	for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
		sprintf(mn->object+2*i, "%02x", buf[i]);
	}

	mn->object[SHA256_DIGEST_SIZE * 2] = 0;
	mn->objectlen = SHA256_DIGEST_SIZE * 2;
	mn->flags = MF_OBJECT_EXIST;
}

static inline void map_to_object(struct map_node *mn, char *buf)
{
	char c = buf[0];
	mn->flags = 0;
	if (c)
		mn->flags |= MF_OBJECT_EXIST;
	memcpy(mn->object, buf+1, XSEG_MAX_TARGETLEN);
	mn->object[XSEG_MAX_TARGETLEN] = 0;
	mn->objectlen = strlen(mn->object);
}

static inline void object_to_map(char* buf, struct map_node *mn)
{
	buf[0] = (mn->flags & MF_OBJECT_EXIST)? 1 : 0;
	memcpy(buf+1, mn->object, mn->objectlen);
	memset(buf+1+mn->objectlen, 0, XSEG_MAX_TARGETLEN - mn->objectlen); //zero out the rest of the buffer
}

static inline void mapheader_to_map(struct map *m, char *buf)
{
	uint64_t pos = 0;
	memcpy(buf + pos, magic_sha256, SHA256_DIGEST_SIZE);
	pos += SHA256_DIGEST_SIZE;
	memcpy(buf + pos, &m->size, sizeof(m->size));
	pos += sizeof(m->size);
}


static int object_write(struct peerd *peer, struct peer_req *pr, 
				struct map *map, struct map_node *mn)
{
	void *dummy;
	struct mapperd *mapper = __get_mapperd(peer);
	struct xseg_request *req = xseg_get_request(peer->xseg, peer->portno,
							mapper->mbportno, X_ALLOC);
	if (!req){
		XSEGLOG2(&lc, E, "Cannot allocate request for object %s. \n\t"
				"(Map: %s [%llu]",
				mn->object, map->volume, (unsigned long long) mn->objectidx);
		goto out_err;
	}
	int r = xseg_prep_request(peer->xseg, req, map->volumelen, objectsize_in_map);
	if (r < 0){
		XSEGLOG2(&lc, E, "Cannot allocate request for object %s. \n\t"
				"(Map: %s [%llu]",
				mn->object, map->volume, (unsigned long long) mn->objectidx);
		goto out_put;
	}
	char *target = xseg_get_target(peer->xseg, req);
	strncpy(target, map->volume, map->volumelen);
	req->size = objectsize_in_map;
	req->offset = mapheader_size + mn->objectidx * objectsize_in_map;
	req->op = X_WRITE;
	char *data = xseg_get_data(peer->xseg, req);
	object_to_map(data, mn);

	r = xseg_set_req_data(peer->xseg, req, pr);
	if (r < 0){
		XSEGLOG2(&lc, E, "Cannot set request data for object %s. \n\t"
				"(Map: %s [%llu]",
				mn->object, map->volume, (unsigned long long) mn->objectidx);
		goto out_put;
	}
	xport p = xseg_submit(peer->xseg, req, peer->portno, X_ALLOC);
	if (p == NoPort){
		XSEGLOG2(&lc, E, "Cannot submit request for object %s. \n\t"
				"(Map: %s [%llu]",
				mn->object, map->volume, (unsigned long long) mn->objectidx);
		goto out_unset;
	}
	r = xseg_signal(peer->xseg, p);
	if (r < 0)
		XSEGLOG2(&lc, W, "Cannot signal port %u", p);

	XSEGLOG2(&lc, I, "Writing object %s \n\t"
			"Map: %s [%llu]",
			mn->object, map->volume, (unsigned long long) mn->objectidx);

	return MF_PENDING;

out_unset:
	xseg_get_req_data(peer->xseg, req, &dummy);
out_put:
	xseg_put_request(peer->xseg, req, peer->portno);
out_err:
	XSEGLOG2(&lc, E, "Object write for object %s failed. \n\t"
			"(Map: %s [%llu]",
			mn->object, map->volume, (unsigned long long) mn->objectidx);
	return -1;
}

static int map_write(struct peerd *peer, struct peer_req* pr, struct map *map)
{
	void *dummy;
	struct mapperd *mapper = __get_mapperd(peer);
	struct map_node *mn;
	uint64_t i, pos, max_objidx = calc_map_obj(map);
	struct xseg_request *req = xseg_get_request(peer->xseg, peer->portno, 
							mapper->mbportno, X_ALLOC);
	if (!req){
		XSEGLOG2(&lc, E, "Cannot allocate request for map %s", map->volume);
		goto out_err;
	}
	int r = xseg_prep_request(peer->xseg, req, map->volumelen, 
					mapheader_size + max_objidx * objectsize_in_map);
	if (r < 0){
		XSEGLOG2(&lc, E, "Cannot prepare request for map %s", map->volume);
		goto out_put;
	}
	char *target = xseg_get_target(peer->xseg, req);
	strncpy(target, map->volume, req->targetlen);
	char *data = xseg_get_data(peer->xseg, req);
	mapheader_to_map(map, data);
	pos = mapheader_size;
	req->op = X_WRITE;
	req->size = req->datalen;
	req->offset = 0;

	if (map->size % block_size)
		max_objidx++;
	for (i = 0; i < max_objidx; i++) {
		mn = find_object(map, i);
		if (!mn){
			XSEGLOG2(&lc, E, "Cannot find object %lli for map %s",
					(unsigned long long) i, map->volume);
			goto out_put;
		}
		object_to_map(data+pos, mn);
		pos += objectsize_in_map;
	}
	r = xseg_set_req_data(peer->xseg, req, pr);
	if (r < 0){
		XSEGLOG2(&lc, E, "Cannot set request data for map %s",
				map->volume);
		goto out_put;
	}
	xport p = xseg_submit(peer->xseg, req, peer->portno, X_ALLOC);
	if (p == NoPort){
		XSEGLOG2(&lc, E, "Cannot submit request for map %s",
				map->volume);
		goto out_unset;
	}
	r = xseg_signal(peer->xseg, p);
	if (r < 0)
		XSEGLOG2(&lc, W, "Cannot signal port %u", p);

	map->flags |= MF_MAP_WRITING;
	XSEGLOG2(&lc, I, "Writing map %s", map->volume);
	return MF_PENDING;

out_unset:
	xseg_get_req_data(peer->xseg, req, &dummy);
out_put:
	xseg_put_request(peer->xseg, req, peer->portno);
out_err:
	XSEGLOG2(&lc, E, "Map write for map %s failed.", map->volume);
	return -1;
}

static int read_map (struct peerd *peer, struct map *map, char *buf)
{
	char nulls[SHA256_DIGEST_SIZE];
	memset(nulls, 0, SHA256_DIGEST_SIZE);

	int r = !memcmp(buf, nulls, SHA256_DIGEST_SIZE);
	if (r) {
		//read error;
		return -1;
	}
	//type 1, our type, type 0 pithos map
	int type = !memcmp(buf, magic_sha256, SHA256_DIGEST_SIZE);
	XSEGLOG2(&lc, I, "Type %d detected for map %s", type, map->volume);
	uint64_t pos;
	uint64_t i, nr_objs;
	struct map_node *map_node;
	if (type) {
		pos = SHA256_DIGEST_SIZE;
		map->size = *(uint64_t *) (buf + pos);
		pos += sizeof(uint64_t);
		nr_objs = map->size / block_size;
		if (map->size % block_size)
			nr_objs++;
		map_node = calloc(nr_objs, sizeof(struct map_node));
		if (!map_node)
			return -1;

		for (i = 0; i < nr_objs; i++) {
			map_node[i].map = map;
			map_node[i].objectidx = i;
			xqindex *qidx = xq_alloc_empty(&map_node[i].pending, peer->nr_ops); //FIXME error check
			(void) qidx;
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
			if (!memcmp(buf+pos, nulls, SHA256_DIGEST_SIZE))
				break;
			map_node[i].objectidx = i;
			map_node[i].map = map;
			xqindex *qidx = xq_alloc_empty(&map_node[i].pending, peer->nr_ops); //FIXME error check
			(void) qidx;
			pithosmap_to_object(&map_node[i], buf + pos);
			pos += SHA256_DIGEST_SIZE; 
			r = insert_object(map, &map_node[i]); //FIXME error check
		}
		map->size = i * block_size; 
	}
	XSEGLOG2(&lc, I, "Map read for map %s completed", map->volume);
	return 0;

	//FIXME cleanup on error
}

/*
 * copy up functions
 */

static int __set_copyup_node(struct mapper_io *mio, struct xseg_request *req, struct map_node *mn)
{
	int r = 0;
	/*
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
	*/
	mio->copyup_node = mn;
	return r;
}

static struct map_node * __get_copyup_node(struct mapper_io *mio, struct xseg_request *req)
{
	/*
	struct map_node *mn;
	int r = xhash_lookup(mio->copyups_nodes, (xhashidx) req, (xhashidx *) &mn);
	if (r < 0)
		return NULL;
	return mn;
	*/
	return mio->copyup_node;
}

static int copyup_object(struct peerd *peer, struct map_node *mn, struct peer_req *pr)
{
	struct mapperd *mapper = __get_mapperd(peer);
	struct mapper_io *mio = __get_mapper_io(pr);
	struct map *map = mn->map;
	void *dummy;
	int r = -1, i;
	xport p;

	//struct sha256_ctx sha256ctx;
	uint32_t newtargetlen;
	char new_target[XSEG_MAX_TARGETLEN + 1]; 
	unsigned char buf[SHA256_DIGEST_SIZE];	//assert sha256_digest_size(32) <= MAXTARGETLEN 
	char new_object[XSEG_MAX_TARGETLEN + 20]; //20 is an arbitrary padding able to hold string representation of objectidx
	strncpy(new_object, map->volume, map->volumelen);
	sprintf(new_object + map->volumelen, "%u", mn->objectidx); //sprintf adds null termination
	new_object[XSEG_MAX_TARGETLEN + 19] = 0;

	gcry_md_hash_buffer(GCRY_MD_SHA256, buf, new_object, strlen(new_object));
	for (i = 0; i < SHA256_DIGEST_SIZE; ++i)
		sprintf (new_target + 2*i, "%02x", buf[i]);
	newtargetlen = SHA256_DIGEST_SIZE  * 2;

	if (!strncmp(mn->object, zero_block, (mn->objectlen < HEXLIFIED_SHA256_DIGEST_SIZE)? mn->objectlen : HEXLIFIED_SHA256_DIGEST_SIZE)) 
		goto copyup_zeroblock;

	struct xseg_request *req = xseg_get_request(peer->xseg, peer->portno, 
							mapper->bportno, X_ALLOC);
	if (!req)
		goto out_err;
	r = xseg_prep_request(peer->xseg, req, newtargetlen, 
				sizeof(struct xseg_request_copy));
	if (r < 0)
		goto out_put;

	char *target = xseg_get_target(peer->xseg, req);
	strncpy(target, new_target, newtargetlen);

	struct xseg_request_copy *xcopy = (struct xseg_request_copy *) xseg_get_data(peer->xseg, req);
	strncpy(xcopy->target, mn->object, mn->objectlen);
	xcopy->targetlen = mn->objectlen;

	req->offset = 0;
	req->size = block_size;
	req->op = X_COPY;
	r = xseg_set_req_data(peer->xseg, req, pr);
	if (r<0)
		goto out_put;
	r = __set_copyup_node(mio, req, mn);
	p = xseg_submit(peer->xseg, req, peer->portno, X_ALLOC);
	if (p == NoPort) {
		goto out_unset;
	}
	xseg_signal(peer->xseg, p);
	mio->copyups++;

	mn->flags |= MF_OBJECT_COPYING;
	XSEGLOG2(&lc, I, "Copying up object %s \n\t to %s", mn->object, new_target);
	return 0;

out_unset:
	r = __set_copyup_node(mio, req, NULL);
	xseg_get_req_data(peer->xseg, req, &dummy);
out_put:
	xseg_put_request(peer->xseg, req, peer->portno);
out_err:
	XSEGLOG2(&lc, E, "Copying up object %s \n\t to %s failed", mn->object, new_target);
	return -1;

copyup_zeroblock:
	XSEGLOG2(&lc, I, "Copying up of zero block is not needed."
			"Proceeding in writing the new object in map");
	/* construct a tmp map_node for writing purposes */
	struct map_node newmn = *mn;
	newmn.flags = MF_OBJECT_EXIST;
	strncpy(newmn.object, new_target, newtargetlen);
	newmn.object[newtargetlen] = 0;
	newmn.objectlen = newtargetlen;
	newmn.objectidx = mn->objectidx; 
	r = __set_copyup_node(mio, req, mn);
	r = object_write(peer, pr, map, &newmn);
	if (r != MF_PENDING){
		XSEGLOG2(&lc, E, "Object write returned error for object %s"
				"\n\t of map %s [%llu]",
				mn->object, map->volume, (unsigned long long) mn->objectidx);
		return -1;
	}
	mn->flags |= MF_OBJECT_WRITING;
	XSEGLOG2(&lc, I, "Object %s copy up completed. Pending writing.", mn->object);
	return 0;
}

/*
 * request handling functions
 */

static int handle_mapread(struct peerd *peer, struct peer_req *pr, 
				struct xseg_request *req)
{
	int r;
	xqindex idx;
	char buf[XSEG_MAX_TARGETLEN];
	struct mapperd *mapper = __get_mapperd(peer);
	//assert req->op = X_READ;
	char *target = xseg_get_target(peer->xseg, req);
	struct map *map = find_map(mapper, target, req->targetlen);
	if (!map)
		goto out_err;
	//assert map->flags & MF_MAP_LOADING

	if (req->state & XS_FAILED)
		goto out_fail;

	char *data = xseg_get_data(peer->xseg, req);
	r = read_map(peer, map, data);
	if (r < 0)
		goto out_fail;
	
	xseg_put_request(peer->xseg, req, peer->portno);
	map->flags &= ~MF_MAP_LOADING;
	print_map(map);
	XSEGLOG2(&lc, I, "Map %s loaded. Dispatching pending", map->volume);
	while((idx = __xq_pop_head(&map->pending)) != Noneidx){
		struct peer_req *preq = (struct peer_req *) idx;
		my_dispatch(peer, preq, preq->req);
	}
	return 0;

out_fail:
	XSEGLOG2(&lc, E, "Map read for map %s failed", map->volume);
	xseg_put_request(peer->xseg, req, peer->portno);
	map->flags &= ~MF_MAP_LOADING;
	while((idx = __xq_pop_head(&map->pending)) != Noneidx){
		struct peer_req *preq = (struct peer_req *) idx;
		fail(peer, preq);
	}
	remove_map(mapper, map);
	//FIXME not freeing up all objects + object hash
	free(map);
	return 0;

out_err:
	strncpy(buf, target, req->targetlen);
	buf[req->targetlen] = 0;
	XSEGLOG2(&lc, E, "Cannot find map for request target %s", buf);
	xseg_put_request(peer->xseg, req, peer->portno);
	return -1;
}

static int handle_mapwrite(struct peerd *peer, struct peer_req *pr,
				struct xseg_request *req)
{
	xqindex idx;
	char buf[XSEG_MAX_TARGETLEN];
	struct mapperd *mapper = __get_mapperd(peer);
	//assert req->op = X_WRITE;
	char *target = xseg_get_target(peer->xseg, req);
	struct map *map = find_map(mapper, target, req->targetlen);
	if (!map) {
		fprintf(stderr, "couldn't find map\n");
		goto out_err;
	}
	//assert map->flags & MF_MAP_WRITING

	if (req->state & XS_FAILED){
		fprintf(stderr, "write request failed\n");
		goto out_fail;
	}
	
	xseg_put_request(peer->xseg, req, peer->portno);
	map->flags &= ~MF_MAP_WRITING;
	XSEGLOG2(&lc, I, "Map %s written. Dispatching pending", map->volume);
	while((idx = __xq_pop_head(&map->pending)) != Noneidx){
		struct peer_req *preq = (struct peer_req *) idx;
		my_dispatch(peer, preq, preq->req);
	}
	return 0;


out_fail:
	XSEGLOG2(&lc, E, "Map write for map %s failed", map->volume);
	xseg_put_request(peer->xseg, req, peer->portno);
	map->flags &= ~MF_MAP_WRITING;
	while((idx = __xq_pop_head(&map->pending)) != Noneidx){
		struct peer_req *preq = (struct peer_req *) idx;
		fail(peer, preq);
	}
	remove_map(mapper, map);
	//FIXME not freeing up all objects + object hash
	free(map);
	return 0;

out_err:
	strncpy(buf, target, req->targetlen);
	buf[req->targetlen] = 0;
	XSEGLOG2(&lc, E, "Cannot find map for request target %s", buf);
	xseg_put_request(peer->xseg, req, peer->portno);
	return -1;
}

static int handle_clone(struct peerd *peer, struct peer_req *pr, 
				struct xseg_request *req)
{
	struct mapperd *mapper = __get_mapperd(peer);
	struct mapper_io *mio = __get_mapper_io(pr);
	(void) mio;
	int r;
	char buf[XSEG_MAX_TARGETLEN + 1];
	char *target;

	if (pr->req->op != X_CLONE) {
		//wtf??
		XSEGLOG2(&lc, E, "Unknown op %u", req->op);
		fail(peer, pr);
		return 0;
	}

	if (req->op == X_WRITE){
			//assert state = WRITING;
			r = handle_mapwrite(peer, pr ,req);
			if (r < 0){
				XSEGLOG2(&lc, E, "handle mapwrite returned error");
				fail(peer, pr);
			}
			return 0;
	}

	if (mio->state == WRITING) {
		target = xseg_get_target(peer->xseg, pr->req);
		strncpy(buf, target, req->targetlen);
		buf[req->targetlen] = 0;
		XSEGLOG2(&lc, I, "Completing clone request for map %s", buf);
		complete(peer, pr);
		return 0;
	}

	struct xseg_request_clone *xclone = (struct xseg_request_clone *) xseg_get_data(peer->xseg, pr->req);
	if (!xclone) {
		goto out_err;
	}
	struct map *map;
	r = find_or_load_map(peer, pr, xclone->target, xclone->targetlen, &map);
	if (r < 0){
		goto out_err;
	}
	else if (r == MF_PENDING)
		return 0;
	
	if (map->flags & MF_MAP_DESTROYED) {
		strncpy(buf, xclone->target, xclone->targetlen);
		buf[xclone->targetlen] = 0;
		XSEGLOG2(&lc, W, "Map %s destroyed", buf);
		target = xseg_get_target(peer->xseg, pr->req);
		strncpy(buf, target, req->targetlen);
		buf[req->targetlen] = 0;
		XSEGLOG2(&lc, W, "Cannont clone %s because base map destroyed", buf);
		fail(peer, pr);
		return 0;
	}

	struct map *clonemap = malloc(sizeof(struct map));
	if (!clonemap) {
		goto out_err;
	}
	/*
	FIXME check if clone map exists
	find_or_load_map(peer, pr, target, req->targetlen, &clonemap)
	... (on destroyed what ??
	if (clonemap) {
		target = xseg_get_target(peer->xseg, pr->req);
		strncpy(buf, target, req->targetlen);
		buf[req->targetlen] = 0;
		XSEGLOG2(&lc, W, "Map %s requested for clone exists", buf);
		fail(peer, pr);
		return 0;
	}
	*/
	//alloc and init struct map
	clonemap->objects = xhash_new(3, INTEGER);
	if (!clonemap->objects){
		goto out_err_clonemap;
	}
	xqindex *qidx = xq_alloc_empty(&clonemap->pending, peer->nr_ops);
	if (!qidx){
		goto out_err_objhash;
	}
	if (xclone->size < map->size) {
		target = xseg_get_target(peer->xseg, pr->req);
		strncpy(buf, target, req->targetlen);
		buf[req->targetlen] = 0;
		XSEGLOG2(&lc, W, "Requested clone size (%llu) < map size (%llu)"
				"\n\t for requested clone %s",
				(unsigned long long) xclone->size,
				(unsigned long long) map->size, buf);
		goto out_err_q;
	}
	if (xclone->size == -1)
		clonemap->size = map->size;
	else
		clonemap->size = xclone->size;
	clonemap->flags = 0;
	target = xseg_get_target(peer->xseg, pr->req);
	strncpy(clonemap->volume, target, pr->req->targetlen);
	clonemap->volumelen = pr->req->targetlen;
	clonemap->volume[clonemap->volumelen] = 0; //NULL TERMINATE

	//alloc and init map_nodes
	unsigned long c = clonemap->size/block_size + 1;
	struct map_node *map_nodes = calloc(c, sizeof(struct map_node));
	if (!map_nodes){
		goto out_err_q;
	}
	int i;
	for (i = 0; i < clonemap->size/block_size + 1; i++) {
		struct map_node *mn = find_object(map, i);
		if (mn) {
			strncpy(map_nodes[i].object, mn->object, mn->objectlen);
			map_nodes[i].objectlen = mn->objectlen;
		} else {
			strncpy(map_nodes[i].object, zero_block, strlen(zero_block)); //this should be SHA256_DIGEST_SIZE *2 ?
			map_nodes[i].objectlen = strlen(zero_block);
		}
		map_nodes[i].object[map_nodes[i].objectlen] = 0; //NULL terminate
		map_nodes[i].flags = 0;
		map_nodes[i].objectidx = i;
		map_nodes[i].map = clonemap;
		xq_alloc_empty(&map_nodes[i].pending, peer->nr_ops);
		r = insert_object(clonemap, &map_nodes[i]);
		if (r < 0){
			goto out_free_all;
		}
	}
	print_map(clonemap);
	//insert map
	r = insert_map(mapper, clonemap);
	if ( r < 0) {
		XSEGLOG2(&lc, E, "Cannot insert map %s", clonemap->volume);
		goto out_free_all;
	}
	r = map_write(peer, pr, clonemap);
	if (r < 0){
		XSEGLOG2(&lc, E, "Cannot write map %s", clonemap->volume);
		goto out_remove;
	}
	else if (r == MF_PENDING) {
		//maybe move this to map_write
		XSEGLOG2(&lc, I, "Writing map %s", clonemap->volume);
		__xq_append_tail(&clonemap->pending, (xqindex) pr);
		mio->state = WRITING;
		return 0;
	} else {
		//unknown state
		XSEGLOG2(&lc, I, "Map write for map %s returned unknown value", clonemap->volume);
		goto out_remove;
	}
	
	return 0;

out_remove:
	remove_map(mapper, clonemap);
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
	target = xseg_get_target(peer->xseg, pr->req);
	strncpy(buf, target, req->targetlen);
	buf[req->targetlen] = 0;
	XSEGLOG2(&lc, E, "Clone map for %s failed", buf);
	fail(peer, pr);
	return -1;
}

static int req2objs(struct peerd *peer, struct peer_req *pr, 
					struct map *map, int write)
{
	char *target = xseg_get_target(peer->xseg, pr->req);
	uint32_t nr_objs = calc_nr_obj(pr->req);
	uint64_t size = sizeof(struct xseg_reply_map) + 
			nr_objs * sizeof(struct xseg_reply_map_scatterlist);

	XSEGLOG2(&lc, D, "Calculated %u nr_objs", nr_objs);
	/* resize request to fit reply */
	char buf[XSEG_MAX_TARGETLEN];
	strncpy(buf, target, pr->req->targetlen);
	int r = xseg_resize_request(peer->xseg, pr->req, pr->req->targetlen, size);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Cannot resize request");
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
	uint64_t obj_size =  (obj_offset + rem_size > block_size) ? block_size - obj_offset : rem_size;
	struct map_node * mn = find_object(map, obj_index);
	if (!mn) {
		XSEGLOG2(&lc, E, "Cannot find obj_index %llu\n", (unsigned long long) obj_index);
		goto out_err;
	}
	if (write && (mn->flags & MF_OBJECT_NOT_READY)) 
		goto out_object_copying;
	if (write && !(mn->flags & MF_OBJECT_EXIST)) {
		//calc new_target, copy up object
		r = copyup_object(peer, mn, pr);
		if (r < 0) {
			XSEGLOG2(&lc, E, "Error in copy up object");
			goto out_err_copy;
		}
		goto out_object_copying;
	}

//	XSEGLOG2(&lc, D, "pr->req->offset: %llu, pr->req->size %llu, block_size %u\n", 
//				(unsigned long long) pr->req->offset, 
//				(unsigned long long) pr->req->size, 
//				block_size);
	strncpy(reply->segs[idx].target, mn->object, mn->objectlen);
	reply->segs[idx].targetlen = mn->objectlen;
	reply->segs[idx].target[mn->objectlen] = 0;
	reply->segs[idx].offset = obj_offset;
	reply->segs[idx].size = obj_size;
//	XSEGLOG2(&lc, D, "Added object: %s, size: %llu, offset: %llu", mn->object,
//					(unsigned long long) reply->segs[idx].size,
//					(unsigned long long) reply->segs[idx].offset);
	rem_size -= obj_size;
	while (rem_size > 0) {
		idx++;
		obj_index++;
		obj_offset = 0;
		obj_size = (rem_size >  block_size) ? block_size : rem_size;
		rem_size -= obj_size;
		mn = find_object(map, obj_index);
		if (!mn) {
			XSEGLOG2(&lc, E, "Cannot find obj_index %llu\n", (unsigned long long) obj_index);
			goto out_err;
		}
		if (write && (mn->flags & MF_OBJECT_NOT_READY)) 
			goto out_object_copying;
		if (write && !(mn->flags & MF_OBJECT_EXIST)) {
			//calc new_target, copy up object
			r = copyup_object(peer, mn, pr);
			if (r < 0) {
				XSEGLOG2(&lc, E, "Error in copy up object");
				goto out_err_copy;
			}
			goto out_object_copying;
		}
		strncpy(reply->segs[idx].target, mn->object, mn->objectlen);
		reply->segs[idx].targetlen = mn->objectlen;
		reply->segs[idx].target[mn->objectlen] = 0;
		reply->segs[idx].offset = obj_offset;
		reply->segs[idx].size = obj_size;
//		XSEGLOG2(&lc, D, "Added object: %s, size: %llu, offset: %llu", mn->object,
//				(unsigned long long) reply->segs[idx].size,
//				(unsigned long long) reply->segs[idx].offset);
	}
	if (reply->cnt != (idx + 1)){
		XSEGLOG2(&lc, E, "reply->cnt %u, idx+1: %u", reply->cnt, idx+1);
		goto out_err;
	}

	return 0;

out_object_copying:
	//printf("r2o mn: %lx\n", mn);
	//printf("volume %s pending on %s\n", map->volume, mn->object);
	//assert write
	if(__xq_append_tail(&mn->pending, (xqindex) pr) == Noneidx)
		XSEGLOG2(&lc, E, "Cannot append pr to tail");
	XSEGLOG2(&lc, I, "object %s is pending \n\t idx:%llu of map %s",
			mn->object, (unsigned long long) mn->objectidx, map->volume);
	return MF_PENDING;

out_err_copy:
out_err:
	return -1;
}

static int handle_mapr(struct peerd *peer, struct peer_req *pr, 
				struct xseg_request *req)
{
	struct mapperd *mapper = __get_mapperd(peer);
	struct mapper_io *mio = __get_mapper_io(pr);
	(void)mapper;
	(void)mio;
	//get_map
	char *target = xseg_get_target(peer->xseg, pr->req);
	struct map *map;
	int r = find_or_load_map(peer, pr, target, pr->req->targetlen, &map);
	if (r < 0) {
		fail(peer, pr);
		return -1;
	}
	else if (r == MF_PENDING)
		return 0;
	
	if (map->flags & MF_MAP_DESTROYED) {
		fail(peer, pr);
		return 0;
	}
	
	//get_object
	r = req2objs(peer, pr, map, 0);
	if  (r < 0){
		XSEGLOG2(&lc, I, "Map r of map %s, range: %llu-%llu failed",
				map->volume, 
				(unsigned long long) pr->req->offset, 
				(unsigned long long) (pr->req->offset + pr->req->size));
		fail(peer, pr);
	}
	else if (r == 0)
		XSEGLOG2(&lc, I, "Map r of map %s, range: %llu-%llu completed",
				map->volume, 
				(unsigned long long) pr->req->offset, 
				(unsigned long long) (pr->req->offset + pr->req->size));
		XSEGLOG2(&lc, D, "Req->offset: %llu, req->size: %llu",
				(unsigned long long) req->offset,
				(unsigned long long) req->size);
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
	xqindex idx;
	struct map_node *mn = __get_copyup_node(mio, req);
	if (!mn)
		goto out_err;

	mn->flags &= ~MF_OBJECT_COPYING;
	if (req->state & XS_FAILED && !(req->state & XS_SERVED)){
		XSEGLOG2(&lc, E, "Copy up of object %s failed", mn->object);
		goto out_fail;
	}
	struct map *map = mn->map;
	if (!map){
		XSEGLOG2(&lc, E, "Object %s has not map back pointer", mn->object);
		goto out_fail;
	}
	
	/* construct a tmp map_node for writing purposes */
	char *target = xseg_get_target(peer->xseg, req);
	struct map_node newmn = *mn;
	newmn.flags = MF_OBJECT_EXIST;
	strncpy(newmn.object, target, req->targetlen);
	newmn.object[req->targetlen] = 0;
	newmn.objectlen = req->targetlen;
	newmn.objectidx = mn->objectidx; 
	r = object_write(peer, pr, map, &newmn);
	if (r != MF_PENDING){
		XSEGLOG2(&lc, E, "Object write returned error for object %s"
				"\n\t of map %s [%llu]",
				mn->object, map->volume, (unsigned long long) mn->objectidx);
		goto out_fail;
	}
	mn->flags |= MF_OBJECT_WRITING;
	xseg_put_request(peer->xseg, req, peer->portno);
	XSEGLOG2(&lc, I, "Object %s copy up completed. Pending writing.", mn->object);
	return 0;

out_fail:
	xseg_put_request(peer->xseg, req, peer->portno);
	__set_copyup_node(mio, req, NULL);
	while ((idx = __xq_pop_head(&mn->pending)) != Noneidx){
		struct peer_req * preq = (struct peer_req *) idx;
		fail(peer, preq);
	}
	return 0;

out_err:
	XSEGLOG2(&lc, E, "Cannot get map node");
	return -1;
}

static int handle_objectwrite(struct peerd *peer, struct peer_req *pr,
				struct xseg_request *req)
{
	xqindex idx;
	struct mapperd *mapper = __get_mapperd(peer);
	struct mapper_io *mio = __get_mapper_io(pr);
	//assert req->op = X_WRITE;
	char *target = xseg_get_target(peer->xseg, req);
	(void)target;
	(void)mapper;
	//printf("handle object write replyi\n");
	struct map_node *mn = __get_copyup_node(mio, req);
	if (!mn)
		goto out_err;
	
	__set_copyup_node(mio, req, NULL);
	
	//assert mn->flags & MF_OBJECT_WRITING
	mn->flags &= ~MF_OBJECT_WRITING;
	if (req->state & XS_FAILED)
		goto out_fail;

	struct map_node tmp;
	char *data = xseg_get_data(peer->xseg, req);
	map_to_object(&tmp, data);
	mn->flags |= MF_OBJECT_EXIST;
	if (mn->flags != MF_OBJECT_EXIST){
		XSEGLOG2(&lc, E, "map node %s has wrong flags", mn->object);
		return *(int *) 0;
	}
	//assert mn->flags & MF_OBJECT_EXIST
	strncpy(mn->object, tmp.object, tmp.objectlen);
	mn->object[tmp.objectlen] = 0;
	mn->objectlen = tmp.objectlen;
	xseg_put_request(peer->xseg, req, peer->portno);

	print_map(mn->map);
	XSEGLOG2(&lc, I, "Object write of %s completed successfully", mn->object);
	while ((idx = __xq_pop_head(&mn->pending)) != Noneidx){
		struct peer_req * preq = (struct peer_req *) idx;
		my_dispatch(peer, preq, preq->req);
	}
	return 0;

out_fail:
	XSEGLOG2(&lc, E, "Write of object %s failed", mn->object);
	xseg_put_request(peer->xseg, req, peer->portno);
	while((idx = __xq_pop_head(&mn->pending)) != Noneidx){
		struct peer_req *preq = (struct peer_req *) idx;
		fail(peer, preq);
	}
	return 0;

out_err:
	XSEGLOG2(&lc, E, "Cannot find map node. Failure!");
	xseg_put_request(peer->xseg, req, peer->portno);
	return -1;
}

static int handle_mapw(struct peerd *peer, struct peer_req *pr, 
				struct xseg_request *req)
{
	struct mapperd *mapper = __get_mapperd(peer);
	struct mapper_io *mio = __get_mapper_io(pr);
	(void) mapper;
	(void) mio;
	/* handle copy up replies separately */
	if (req->op == X_COPY){
		if (handle_copyup(peer, pr, req) < 0){
			XSEGLOG2(&lc, E, "Handle copy up returned error");
			fail(peer, pr);
			return -1;
		} else {
			return 0;
		}
	}
	else if(req->op == X_WRITE){
		/* handle replies of object write operations */
		if (handle_objectwrite(peer, pr, req) < 0) {
			XSEGLOG2(&lc, E, "Handle object write returned error");
			fail(peer, pr);
			return -1;
		} else {
			return 0;
		}
	}

	char *target = xseg_get_target(peer->xseg, pr->req);
	struct map *map;
	int r = find_or_load_map(peer, pr, target, pr->req->targetlen, &map);
	if (r < 0) {
		fail(peer, pr);
		return -1;
	}
	else if (r == MF_PENDING)
		return 0;
	
	if (map->flags & MF_MAP_DESTROYED) {
		fail(peer, pr);
		return 0;
	}

	r = req2objs(peer, pr, map, 1);
	if (r < 0){
		XSEGLOG2(&lc, I, "Map r of map %s, range: %llu-%llu failed",
				map->volume, 
				(unsigned long long) pr->req->offset, 
				(unsigned long long) (pr->req->offset + pr->req->size));
		fail(peer, pr);
	}
	if (r == 0){
		XSEGLOG2(&lc, I, "Map r of map %s, range: %llu-%llu completed",
				map->volume, 
				(unsigned long long) pr->req->offset, 
				(unsigned long long) (pr->req->offset + pr->req->size));
		XSEGLOG2(&lc, D, "Req->offset: %llu, req->size: %llu",
				(unsigned long long) req->offset,
				(unsigned long long) req->size);
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
		complete(peer, pr);
	}
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
	(void) mapper;
	(void) mio;
	char *target = xseg_get_target(peer->xseg, pr->req);
	if (!target) {
		fail(peer, pr);
		return 0;
	}
	//printf("Handle info\n");
	struct map *map;
	int r = find_or_load_map(peer, pr, target, pr->req->targetlen, &map);
	if (r < 0) {
		fail(peer, pr);
		return -1;
	}
	else if (r == MF_PENDING)
		return 0;
	if (map->flags & MF_MAP_DESTROYED) {
		fail(peer, pr);
		return 0;
	}
	
	struct xseg_reply_info *xinfo = (struct xseg_reply_info *) xseg_get_data(peer->xseg, pr->req);
	xinfo->size = map->size;
	complete(peer, pr);

	return 0;
}

static int delete_object(struct peerd *peer, struct peer_req *pr,
				struct map_node *mn)
{
	void *dummy;
	struct mapperd *mapper = __get_mapperd(peer);
	struct mapper_io *mio = __get_mapper_io(pr);

	if (!(mn->flags && MF_OBJECT_EXIST)){
		//cant delete not existing object

	}
	if (xq_count(&mn->pending) != 0) {
		mio->delobj = mn->objectidx;
		__xq_append_tail(&mn->pending, (xqindex) pr); //FIXME err check
		XSEGLOG2(&lc, I, "Object %s has pending requests. Adding to pending",
				mn->object);
		return MF_PENDING;
	}

	struct xseg_request *req = xseg_get_request(peer->xseg, peer->portno, 
							mapper->bportno, X_ALLOC);
	if (!req)
		goto out_err;
	int r = xseg_prep_request(peer->xseg, req, mn->objectlen, 0);
	if (r < 0)
		goto out_put;
	char *target = xseg_get_target(peer->xseg, req);
	strncpy(target, mn->object, req->targetlen);
	req->op = X_DELETE;
	req->size = req->datalen;
	req->offset = 0;

	r = xseg_set_req_data(peer->xseg, req, pr);
	if (r < 0)
		goto out_put;
	__set_copyup_node(mio, req, mn);
	xport p = xseg_submit(peer->xseg, req, peer->portno, X_ALLOC);
	if (p == NoPort)
		goto out_unset;
	r = xseg_signal(peer->xseg, p);
	mn->flags |= MF_OBJECT_DELETING;
	XSEGLOG2(&lc, I, "Object %s deletion pending", mn->object);
	return MF_PENDING;

out_unset:
	xseg_get_req_data(peer->xseg, req, &dummy);
out_put:
	xseg_put_request(peer->xseg, req, peer->portno);
out_err:
	XSEGLOG2(&lc, I, "Object %s deletion failed", mn->object);
	return -1;
}
static int handle_object_delete(struct peerd *peer, struct peer_req *pr, 
				 struct map_node *mn, int err)
{
	struct mapperd *mapper = __get_mapperd(peer);
	struct mapper_io *mio = __get_mapper_io(pr);
	uint64_t idx;
	struct map *map = mn->map;
	int r;
	(void) mio;
	//if object deletion failed, map deletion must continue
	//and report OK, since map block has been deleted succesfully
	//so, no check for err

	//assert object flags OK
	//free map_node_resources
	map->flags &= ~MF_OBJECT_DELETING;
	xq_free(&mn->pending);
	//find next object
	idx = mn->objectidx;
	//remove_object(map, idx);
	idx++;
	mn = find_object(map, idx);
	while (!mn && idx < calc_map_obj(map)) {
		idx++;
		mn = find_object(map, idx);
	}
	if (mn) {
		//delete next object or complete;
		r = delete_object(peer, pr, mn);
		if (r < 0) {
			XSEGLOG2(&lc, E, "Object %s delete object return error"
					 "\n\t Map: %s [%llu]", 
					 mn->object, mn->map->volume, 
					 (unsigned long long) mn->objectidx);
			goto del_completed;
		}
		XSEGLOG2(&lc, I, "Handle object delete OK");
	} else {
del_completed:
		//assert map flags OK
		map->flags &= ~MF_MAP_DELETING;
		map->flags |= MF_MAP_DESTROYED;
		XSEGLOG2(&lc, I, "Map %s deleted", map->volume);
		//make all pending requests on map to fail
		while ((idx = __xq_pop_head(&map->pending)) != Noneidx){
			struct peer_req * preq = (struct peer_req *) idx;
			my_dispatch(peer, preq, preq->req);
		}
		//free map resources;
		remove_map(mapper, map);
		mn = find_object(map, 0);
		free(mn);
		xq_free(&map->pending);
		free(map);
	}
	return 0;
}

static int delete_map(struct peerd *peer, struct peer_req *pr,
			struct map *map)
{
	void *dummy;
	struct mapperd *mapper = __get_mapperd(peer);
	struct mapper_io *mio = __get_mapper_io(pr);
	struct xseg_request *req = xseg_get_request(peer->xseg, peer->portno, 
							mapper->mbportno, X_ALLOC);
	if (!req)
		goto out_err;
	int r = xseg_prep_request(peer->xseg, req, map->volumelen, 0);
	if (r < 0)
		goto out_put;
	char *target = xseg_get_target(peer->xseg, req);
	strncpy(target, map->volume, req->targetlen);
	req->op = X_DELETE;
	req->size = req->datalen;
	req->offset = 0;

	r = xseg_set_req_data(peer->xseg, req, pr);
	if (r < 0)
		goto out_put;
	__set_copyup_node(mio, req, NULL);
	xport p = xseg_submit(peer->xseg, req, peer->portno, X_ALLOC);
	if (p == NoPort)
		goto out_unset;
	r = xseg_signal(peer->xseg, p);
	map->flags |= MF_MAP_DELETING;
	XSEGLOG2(&lc, I, "Map %s deletion pending", map->volume);
	return MF_PENDING;

out_unset:
	xseg_get_req_data(peer->xseg, req, &dummy);
out_put:
	xseg_put_request(peer->xseg, req, peer->portno);
out_err:
	XSEGLOG2(&lc, I, "Map %s deletion failed", map->volume);
	return -1;
}

static int handle_map_delete(struct peerd *peer, struct peer_req *pr, 
				struct map *map, int err)
{
	struct mapperd *mapper = __get_mapperd(peer);
	struct mapper_io *mio = __get_mapper_io(pr);
	xqindex idx;
	int r;
	(void) mio;
	map->flags &= ~MF_MAP_DELETING;
	if (err) {
		XSEGLOG2(&lc, E, "Map %s deletion failed", map->volume);
		//dispatch all pending
		while ((idx = __xq_pop_head(&map->pending)) != Noneidx){
			struct peer_req * preq = (struct peer_req *) idx;
			my_dispatch(peer, preq, preq->req);
		}
	} else {
		map->flags |= MF_MAP_DESTROYED;
		//delete all objects
		XSEGLOG2(&lc, E, "Map %s map block deleted. Deleting objects", map->volume);
		struct map_node *mn = find_object(map, 0);
		if (!mn) {
			XSEGLOG2(&lc, E, "Map %s has no object 0", map->volume);
			//this should never happen
			//make all pending requests on map to fail
			while ((idx = __xq_pop_head(&map->pending)) != Noneidx){
				struct peer_req * preq = (struct peer_req *) idx;
				my_dispatch(peer, preq, preq->req);
			}
			//free map resources;
			remove_map(mapper, map);
			xq_free(&map->pending);
			free(map);
			return 0;
		}
		r = delete_object(peer, pr, mn);
		if (r < 0) {
			XSEGLOG2(&lc, E, "Deleting first object of map %s returned error"
					"\n\t Dispatching pending requests",
					map->volume);
			//dispatch all pending
			while ((idx = __xq_pop_head(&map->pending)) != Noneidx){
				struct peer_req * preq = (struct peer_req *) idx;
				my_dispatch(peer, preq, preq->req);
			}
		}
	}
	return 0;
}

static int handle_delete(struct peerd *peer, struct peer_req *pr, 
				struct xseg_request *req)
{
	struct mapperd *mapper = __get_mapperd(peer);
	struct mapper_io *mio = __get_mapper_io(pr);
	struct map_node *mn;
	struct map *map;
	int err = 0;
	if (req->state & XS_FAILED && !(req->state &XS_SERVED)) 
		err = 1;
	
	mn = __get_copyup_node(mio, req);
	__set_copyup_node(mio, req, NULL);
	char *target = xseg_get_target(peer->xseg, req);
	if (!mn) {
		//map block delete
		map = find_map(mapper, target, req->targetlen);
		if (!map) {
			xseg_put_request(peer->xseg, req, peer->portno);
			return -1;
		}
		handle_map_delete(peer, pr, map, err);
	} else {
		//object delete
		map = mn->map;
		if (!map) {
			xseg_put_request(peer->xseg, req, peer->portno);
			return -1;
		}
		handle_object_delete(peer, pr, mn, err);
	}
	xseg_put_request(peer->xseg, req, peer->portno);
	return 0;
}

static int handle_destroy(struct peerd *peer, struct peer_req *pr, 
				struct xseg_request *req)
{
	struct mapperd *mapper = __get_mapperd(peer);
	struct mapper_io *mio = __get_mapper_io(pr);
	(void) mapper;
	int r;

	if (pr->req != req && req->op == X_DELETE) {
		//assert mio->state == DELETING
		r = handle_delete(peer, pr, req);
		if (r < 0) {
			XSEGLOG2(&lc, E, "Handle delete returned error");
			fail(peer, pr);
			return -1;
		} else {
			return 0;
		}
	}

	struct map *map;
	char *target = xseg_get_target(peer->xseg, pr->req);
	r = find_or_load_map(peer, pr, target, pr->req->targetlen, &map);
	if (r < 0) {
		fail(peer, pr);
		return -1;
	}
	else if (r == MF_PENDING)
		return 0;
	if (map->flags & MF_MAP_DESTROYED) {
		if (mio->state == DELETING){
			XSEGLOG2(&lc, I, "Map %s destroyed", map->volume);
			complete(peer, pr);
		}
		else{
			XSEGLOG2(&lc, I, "Map %s already destroyed", map->volume);
			fprintf(stderr, "map destroyed\n");
			fail(peer, pr);
		}
		return 0;
	}
	if (mio->state == DELETING) {
		//continue deleting map objects;
		struct map_node *mn = find_object(map, mio->delobj);
		if (!mn) {
			complete(peer, pr);
			return 0;
		}
		r = delete_object(peer, pr, mn);
		if (r < 0) {
			complete(peer, pr);
		}
		return 0;
	}
	//delete map block
	r = delete_map(peer, pr, map);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Map delete for map %s returned error", map->volume);
		fail(peer, pr);
		return -1;
	} else if (r == MF_PENDING) {
		XSEGLOG2(&lc, I, "Map %s delete pending", map->volume);
		__xq_append_tail(&map->pending, (xqindex) pr);
		mio->state = DELETING;
		return 0;
	}
	//unreachable
	XSEGLOG2(&lc, E, "Destroy unreachable");
	fail(peer, pr);
	return 0;
}

static int my_dispatch(struct peerd *peer, struct peer_req *pr, struct xseg_request *req)
{
	struct mapperd *mapper = __get_mapperd(peer);
	(void) mapper;
	struct mapper_io *mio = __get_mapper_io(pr);
	(void) mio;

	if (req->op == X_READ) {
		/* catch map reads requests here */
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
		default: fprintf(stderr, "mydispatch: unknown up\n"); break;
	}
	return 0;
}

int dispatch(struct peerd *peer, struct peer_req *pr, struct xseg_request *req)
{
	struct mapperd *mapper = __get_mapperd(peer);
	(void) mapper;
	struct mapper_io *mio = __get_mapper_io(pr);
	(void) mio;

	if (pr->req == req)
		mio->state = ACCEPTED;
	my_dispatch(peer, pr ,req);
	return 0;
}

int custom_peer_init(struct peerd *peer, int argc, char *argv[])
{
	int i;
	unsigned char buf[SHA256_DIGEST_SIZE];
	char *zero;

	gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);

       	/* Version check should be the very first call because it
          makes sure that important subsystems are intialized. */
       	gcry_check_version (NULL);
     
       	/* Disable secure memory.  */
       	gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
     
       	/* Tell Libgcrypt that initialization has completed. */
       	gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

	/* calculate out magic sha hash value */
	gcry_md_hash_buffer(GCRY_MD_SHA256, magic_sha256, magic_string, strlen(magic_string));

	/* calculate zero block */
	//FIXME check hash value
	zero = malloc(block_size);
	memset(zero, 0, block_size);
	gcry_md_hash_buffer(GCRY_MD_SHA256, buf, zero, block_size);
	for (i = 0; i < SHA256_DIGEST_SIZE; ++i)
		sprintf(zero_block + 2*i, "%02x", buf[i]);
	printf("%s \n", zero_block);
	free(zero);

	//FIXME error checks
	struct mapperd *mapper = malloc(sizeof(struct mapperd));
	mapper->hashmaps = xhash_new(3, STRING);
	peer->priv = mapper;
	
	for (i = 0; i < peer->nr_ops; i++) {
		struct mapper_io *mio = malloc(sizeof(struct mapper_io));
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
		if (!strcmp(argv[i], "-mbp") && (i+1) < argc){
			mapper->mbportno = atoi(argv[i+1]);
			i += 1;
			continue;
		}
		/* enforce only one thread */
		if (!strcmp(argv[i], "-t") && (i+1) < argc){
			int t = atoi(argv[i+1]);
			if (t != 1) {
				printf("ERROR: mapperd supports only one thread for the moment\nExiting ...\n");
				return -1;
			}
			i += 1;
			continue;
		}
	}

//	test_map(peer);

	return 0;
}

void print_obj(struct map_node *mn)
{
	fprintf(stderr, "[%llu]object name: %s[%u] exists: %c\n", 
			(unsigned long long) mn->objectidx, mn->object, 
			(unsigned int) mn->objectlen, 
			(mn->flags & MF_OBJECT_EXIST) ? 'y' : 'n');
}

void print_map(struct map *m)
{
	uint64_t nr_objs = m->size/block_size;
	if (m->size % block_size)
		nr_objs++;
	fprintf(stderr, "Volume name: %s[%u], size: %llu, nr_objs: %llu\n", 
			m->volume, m->volumelen, 
			(unsigned long long) m->size, 
			(unsigned long long) nr_objs);
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

/*
void test_map(struct peerd *peer)
{
	int i,j, ret;
	//struct sha256_ctx sha256ctx;
	unsigned char buf[SHA256_DIGEST_SIZE];
	char buf_new[XSEG_MAX_TARGETLEN + 20];
	struct map *m = malloc(sizeof(struct map));
	strncpy(m->volume, "012345678901234567890123456789ab012345678901234567890123456789ab", XSEG_MAX_TARGETLEN + 1);
	m->volume[XSEG_MAX_TARGETLEN] = 0;
	strncpy(buf_new, m->volume, XSEG_MAX_TARGETLEN);
	buf_new[XSEG_MAX_TARGETLEN + 19] = 0;
	m->volumelen = XSEG_MAX_TARGETLEN;
	m->size = 100*block_size;
	m->objects = xhash_new(3, INTEGER);
	struct map_node *map_node = calloc(100, sizeof(struct map_node));
	for (i = 0; i < 100; i++) {
		sprintf(buf_new +XSEG_MAX_TARGETLEN, "%u", i);
		gcry_md_hash_buffer(GCRY_MD_SHA256, buf, buf_new, strlen(buf_new));
		
		for (j = 0; j < SHA256_DIGEST_SIZE; j++) {
			sprintf(map_node[i].object + 2*j, "%02x", buf[j]);
		}
		map_node[i].objectidx = i;
		map_node[i].objectlen = XSEG_MAX_TARGETLEN;
		map_node[i].flags = MF_OBJECT_EXIST;
		ret = insert_object(m, &map_node[i]);
	}

	char *data = malloc(block_size);
	mapheader_to_map(m, data);
	uint64_t pos = mapheader_size;

	for (i = 0; i < 100; i++) {
		map_node = find_object(m, i);
		if (!map_node){
			printf("no object node %d \n", i);
			exit(1);
		}
		object_to_map(data+pos, map_node);
		pos += objectsize_in_map;
	}
//	print_map(m);

	struct map *m2 = malloc(sizeof(struct map));
	strncpy(m2->volume, "012345678901234567890123456789ab012345678901234567890123456789ab", XSEG_MAX_TARGETLEN +1);
	m->volume[XSEG_MAX_TARGETLEN] = 0;
	m->volumelen = XSEG_MAX_TARGETLEN;

	m2->objects = xhash_new(3, INTEGER);
	ret = read_map(peer, m2, data);
//	print_map(m2);

	int fd = open(m->volume, O_CREAT|O_WRONLY, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH);
	ssize_t r, sum = 0;
	while (sum < block_size) {
		r = write(fd, data + sum, block_size -sum);
		if (r < 0){
			perror("write");
			printf("write error\n");
			exit(1);
		} 
		sum += r;
	}
	close(fd);
	map_node = find_object(m, 0);
	free(map_node);
	free(m);
}
*/
