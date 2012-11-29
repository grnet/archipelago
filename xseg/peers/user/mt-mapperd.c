#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>
#include <xseg/xseg.h>
#include <peer.h>
#include <time.h>
#include <xtypes/xlock.h>
#include <xtypes/xhash.h>
#include <xseg/protocol.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <sys/syscall.h>
#include <openssl/sha.h>

/* general mapper flags */
#define MF_LOAD 	(1 << 0)
#define MF_EXCLUSIVE 	(1 << 1)
#define MF_FORCE 	(1 << 2)
#define MF_ARCHIP	(1 << 3)

#ifndef SHA256_DIGEST_SIZE
#define SHA256_DIGEST_SIZE 32
#endif
/* hex representation of sha256 value takes up double the sha256 size */
#define HEXLIFIED_SHA256_DIGEST_SIZE (SHA256_DIGEST_SIZE << 1)

#define block_size (1<<22) //FIXME this should be defined here?

/* transparency byte + max object len in disk */
#define objectsize_in_map (1 + SHA256_DIGEST_SIZE)

/* Map header contains:
 * 	map version
 * 	volume size
 */
#define mapheader_size (sizeof (uint32_t) + sizeof(uint64_t))


#define MAPPER_PREFIX "archip_"
#define MAPPER_PREFIX_LEN 7

#define MAX_REAL_VOLUME_LEN (XSEG_MAX_TARGETLEN - MAPPER_PREFIX_LEN)
#define MAX_VOLUME_LEN (MAPPER_PREFIX_LEN + MAX_REAL_VOLUME_LEN)

#if MAX_VOLUME_LEN > XSEG_MAX_TARGETLEN
#error 	"XSEG_MAX_TARGETLEN should be at least MAX_VOLUME_LEN"
#endif

#define MAX_OBJECT_LEN (MAPPER_PREFIX_LEN + HEXLIFIED_SHA256_DIGEST_SIZE)

#if MAX_OBJECT_LEN > XSEG_MAX_TARGETLEN
#error 	"XSEG_MAX_TARGETLEN should be at least MAX_OBJECT_LEN"
#endif

#define MAX_VOLUME_SIZE \
((uint64_t) (((block_size-mapheader_size)/objectsize_in_map)* block_size))


char *zero_block="0000000000000000000000000000000000000000000000000000000000000000";
#define ZERO_BLOCK_LEN (64) /* strlen(zero_block) */

/* dispatch_internal mapper states */
enum mapper_state {
	ACCEPTED = 0,
	WRITING = 1,
	COPYING = 2,
	DELETING = 3,
	DROPPING_CACHE = 4
};

typedef void (*cb_t)(struct peer_req *pr, struct xseg_request *req);


/* mapper object flags */
#define MF_OBJECT_EXIST		(1 << 0)
#define MF_OBJECT_COPYING	(1 << 1)
#define MF_OBJECT_WRITING	(1 << 2)
#define MF_OBJECT_DELETING	(1 << 3)
#define MF_OBJECT_DESTROYED	(1 << 5)

#define MF_OBJECT_NOT_READY	(MF_OBJECT_COPYING|MF_OBJECT_WRITING|\
					MF_OBJECT_DELETING)
struct map_node {
	uint32_t flags;
	uint32_t objectidx;
	uint32_t objectlen;
	char object[MAX_OBJECT_LEN + 1]; 	/* NULL terminated string */
	struct map *map;
	uint32_t ref;
	uint32_t waiters;
	st_cond_t cond;
};


#define wait_on_pr(__pr, __condition__) 	\
	while (__condition__){			\
		ta--;				\
		__get_mapper_io(pr)->active = 0;\
		XSEGLOG2(&lc, D, "Waiting on pr %lx, ta: %u",  pr, ta); \
		st_cond_wait(__pr->cond);	\
	}

#define wait_on_mapnode(__mn, __condition__)	\
	while (__condition__){			\
		ta--;				\
		__mn->waiters++;		\
		XSEGLOG2(&lc, D, "Waiting on map node %lx %s, waiters: %u, \
			ta: %u",  __mn, __mn->object, __mn->waiters, ta);  \
		st_cond_wait(__mn->cond);	\
	}

#define wait_on_map(__map, __condition__)	\
	while (__condition__){			\
		ta--;				\
		__map->waiters++;		\
		XSEGLOG2(&lc, D, "Waiting on map %lx %s, waiters: %u, ta: %u",\
				   __map, __map->volume, __map->waiters, ta); \
		st_cond_wait(__map->cond);	\
	}

#define signal_pr(__pr)				\
	do { 					\
		if (!__get_mapper_io(pr)->active){\
			ta++;			\
			XSEGLOG2(&lc, D, "Signaling  pr %lx, ta: %u",  pr, ta);\
			__get_mapper_io(pr)->active = 1;\
			st_cond_signal(__pr->cond);	\
		}				\
	}while(0)

#define signal_map(__map)			\
	do { 					\
		if (__map->waiters) {		\
			ta += 1;		\
			XSEGLOG2(&lc, D, "Signaling map %lx %s, waiters: %u, \
			ta: %u",  __map, __map->volume, __map->waiters, ta); \
			__map->waiters--;	\
			st_cond_signal(__map->cond);	\
		}				\
	}while(0)

#define signal_mapnode(__mn)			\
	do { 					\
		if (__mn->waiters) {		\
			ta += __mn->waiters;	\
			XSEGLOG2(&lc, D, "Signaling map node %lx %s, waiters: \
			%u, ta: %u",  __mn, __mn->object, __mn->waiters, ta); \
			__mn->waiters = 0;	\
			st_cond_broadcast(__mn->cond);	\
		}				\
	}while(0)


/* map flags */
#define MF_MAP_LOADING		(1 << 0)
#define MF_MAP_DESTROYED	(1 << 1)
#define MF_MAP_WRITING		(1 << 2)
#define MF_MAP_DELETING		(1 << 3)
#define MF_MAP_DROPPING_CACHE	(1 << 4)
#define MF_MAP_EXCLUSIVE	(1 << 5)
#define MF_MAP_OPENING		(1 << 6)
#define MF_MAP_CLOSING		(1 << 7)
#define MF_MAP_DELETED		(1 << 8)

#define MF_MAP_NOT_READY	(MF_MAP_LOADING|MF_MAP_WRITING|MF_MAP_DELETING|\
					MF_MAP_DROPPING_CACHE|MF_MAP_OPENING)

struct map {
	uint32_t version;
	uint32_t flags;
	uint64_t size;
	uint32_t volumelen;
	char volume[MAX_VOLUME_LEN + 1]; /* NULL terminated string */
	xhash_t *objects; 	/* obj_index --> map_node */
	uint32_t ref;
	uint32_t waiters;
	st_cond_t cond;
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
	volatile int err;			/* error flag */
	volatile uint64_t del_pending;
	uint64_t delobj;
	uint64_t dcobj;
	cb_t cb;
	enum mapper_state state;
	volatile int active;
};

/* global vars */
struct mapperd *mapper;

void print_map(struct map *m);


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
	if (map->size == -1)
		return 0;
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

/* hexlify function. 
 * Unsafe. Doesn't check if data length is odd!
 */
static void hexlify(unsigned char *data, char *hex)
{
	int i;
	for (i=0; i<SHA256_DIGEST_LENGTH; i++)
		sprintf(hex+2*i, "%02x", data[i]);
}

static void unhexlify(char *hex, unsigned char *data)
{
	int i;
	char c;
	for (i=0; i<SHA256_DIGEST_LENGTH; i++){
		data[i] = 0;
		c = hex[2*i];
		if (isxdigit(c)){
			if (isdigit(c)){
				c-= '0';
			}
			else {
				c = tolower(c);
				c = c-'a' + 10;
			}
		}
		else {
			c = 0;
		}
		data[i] |= (c << 4) & 0xF0;
		c = hex[2*i+1];
		if (isxdigit(c)){
			if (isdigit(c)){
				c-= '0';
			}
			else {
				c = tolower(c);
				c = c-'a' + 10;
			}
		}
		else {
			c = 0;
		}
		data[i] |= c & 0x0F;
	}
}
/*
 * Maps handling functions
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
	if (flags & MF_ARCHIP){
		strncpy(buf, MAPPER_PREFIX, MAPPER_PREFIX_LEN);
		strncpy(buf + MAPPER_PREFIX_LEN, target, targetlen);
		buf[MAPPER_PREFIX_LEN + targetlen] = 0;
		targetlen += MAPPER_PREFIX_LEN;
	}
	else {
		strncpy(buf, target, targetlen);
		buf[targetlen] = 0;
	}

	if (targetlen > MAX_VOLUME_LEN){
		XSEGLOG2(&lc, E, "Namelen %u too long. Max: %d",
					targetlen, MAX_VOLUME_LEN);
		return NULL;
	}

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
	while (r == -XHASH_ERESIZE) {
		xhashidx shift = xhash_shrink_size_shift(mapper->hashmaps);
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

static struct xseg_request * __close_map(struct peer_req *pr, struct map *map)
{
	int r;
	xport p;
	struct peerd *peer = pr->peer;
	struct xseg_request *req;
	struct mapperd *mapper = __get_mapperd(peer);
	void *dummy;

	XSEGLOG2(&lc, I, "Closing map %s", map->volume);

	req = xseg_get_request(peer->xseg, pr->portno, mapper->mbportno, X_ALLOC);
	if (!req){
		XSEGLOG2(&lc, E, "Cannot allocate request for map %s",
				map->volume);
		goto out_err;
	}

	r = xseg_prep_request(peer->xseg, req, map->volumelen, 0);
	if (r < 0){
		XSEGLOG2(&lc, E, "Cannot prepare request for map %s",
				map->volume);
		goto out_put;
	}

	char *reqtarget = xseg_get_target(peer->xseg, req);
	if (!reqtarget)
		goto out_put;
	strncpy(reqtarget, map->volume, req->targetlen);
	req->op = X_CLOSE;
	req->size = 0;
	req->offset = 0;
	r = xseg_set_req_data(peer->xseg, req, pr);
	if (r < 0){
		XSEGLOG2(&lc, E, "Cannot set request data for map %s",
				map->volume);
		goto out_put;
	}
	p = xseg_submit(peer->xseg, req, pr->portno, X_ALLOC);
	if (p == NoPort){
		XSEGLOG2(&lc, E, "Cannot submit request for map %s",
				map->volume);
		goto out_unset;
	}
	r = xseg_signal(peer->xseg, p);

	XSEGLOG2(&lc, I, "Map %s closing", map->volume);
	return req;

out_unset:
	xseg_get_req_data(peer->xseg, req, &dummy);
out_put:
	xseg_put_request(peer->xseg, req, pr->portno);
out_err:
	return NULL;
}

static int close_map(struct peer_req *pr, struct map *map)
{
	int err;
	struct xseg_request *req;
	struct peerd *peer = pr->peer;

	map->flags |= MF_MAP_CLOSING;
	req = __close_map(pr, map);
	if (!req)
		return -1;
	wait_on_pr(pr, (!((req->state & XS_FAILED)||(req->state & XS_SERVED))));
	map->flags &= ~MF_MAP_CLOSING;
	err = req->state & XS_FAILED;
	xseg_put_request(peer->xseg, req, pr->portno);
	if (err)
		return -1;
	return 0;
}

/*
static int find_or_load_map(struct peerd *peer, struct peer_req *pr, 
				char *target, uint32_t targetlen, struct map **m)
{
	struct mapperd *mapper = __get_mapperd(peer);
	int r;
	*m = find_map(mapper, target, targetlen);
	if (*m) {
		XSEGLOG2(&lc, D, "Found map %s (%u)", (*m)->volume, (unsigned long) *m);
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
	r = open_map(peer, pr, target, targetlen, 0);
	if (r < 0)
		return -1; //error
	return MF_PENDING;	
}
*/
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
	hexlify(buf, mn->object);
	mn->object[HEXLIFIED_SHA256_DIGEST_SIZE] = 0;
	mn->objectlen = HEXLIFIED_SHA256_DIGEST_SIZE;
	mn->flags = MF_OBJECT_EXIST;
}

static inline void map_to_object(struct map_node *mn, unsigned char *buf)
{
	char c = buf[0];
	mn->flags = 0;
	if (c){
		mn->flags |= MF_OBJECT_EXIST;
		strcpy(mn->object, MAPPER_PREFIX);
		hexlify(buf+1, mn->object + MAPPER_PREFIX_LEN);
		mn->object[MAX_OBJECT_LEN] = 0;
		mn->objectlen = strlen(mn->object);
	}
	else {
		hexlify(buf+1, mn->object);
		mn->object[HEXLIFIED_SHA256_DIGEST_SIZE] = 0;
		mn->objectlen = strlen(mn->object);
	}

}

static inline void object_to_map(char* buf, struct map_node *mn)
{
	buf[0] = (mn->flags & MF_OBJECT_EXIST)? 1 : 0;
	if (buf[0]){
		/* strip common prefix */
		unhexlify(mn->object+MAPPER_PREFIX_LEN, (unsigned char *)(buf+1));
	}
	else {
		unhexlify(mn->object, (unsigned char *)(buf+1));
	}
}

static inline void mapheader_to_map(struct map *m, char *buf)
{
	uint64_t pos = 0;
	memcpy(buf + pos, &m->version, sizeof(m->version));
	pos += sizeof(m->version);
	memcpy(buf + pos, &m->size, sizeof(m->size));
	pos += sizeof(m->size);
}


static struct xseg_request * object_write(struct peerd *peer, struct peer_req *pr,
				struct map *map, struct map_node *mn)
{
	void *dummy;
	struct mapperd *mapper = __get_mapperd(peer);
	struct xseg_request *req = xseg_get_request(peer->xseg, pr->portno,
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
	strncpy(target, map->volume, req->targetlen);
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
	xport p = xseg_submit(peer->xseg, req, pr->portno, X_ALLOC);
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

	return req;

out_unset:
	xseg_get_req_data(peer->xseg, req, &dummy);
out_put:
	xseg_put_request(peer->xseg, req, pr->portno);
out_err:
	XSEGLOG2(&lc, E, "Object write for object %s failed. \n\t"
			"(Map: %s [%llu]",
			mn->object, map->volume, (unsigned long long) mn->objectidx);
	return NULL;
}

static struct xseg_request * __write_map(struct peer_req* pr, struct map *map)
{
	void *dummy;
	struct peerd *peer = pr->peer;
	struct mapperd *mapper = __get_mapperd(peer);
	struct map_node *mn;
	uint64_t i, pos, max_objidx = calc_map_obj(map);
	struct xseg_request *req = xseg_get_request(peer->xseg, pr->portno,
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
	xport p = xseg_submit(peer->xseg, req, pr->portno, X_ALLOC);
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
	return req;

out_unset:
	xseg_get_req_data(peer->xseg, req, &dummy);
out_put:
	xseg_put_request(peer->xseg, req, pr->portno);
out_err:
	XSEGLOG2(&lc, E, "Map write for map %s failed.", map->volume);
	return NULL;
}

static int write_map(struct peer_req* pr, struct map *map)
{
	int r = 0;
	struct peerd *peer = pr->peer;
	map->flags |= MF_MAP_WRITING;
	struct xseg_request *req = __write_map(pr, map);
	if (!req)
		return -1;
	wait_on_pr(pr, (!(req->state & XS_FAILED || req->state & XS_SERVED)));
	if (req->state & XS_FAILED)
		r = -1;
	xseg_put_request(peer->xseg, req, pr->portno);
	map->flags &= ~MF_MAP_WRITING;
	return r;
}

static struct xseg_request * __load_map(struct peer_req *pr, struct map *m)
{
	int r;
	xport p;
	struct xseg_request *req;
	struct peerd *peer = pr->peer;
	struct mapperd *mapper = __get_mapperd(peer);
	void *dummy;

	XSEGLOG2(&lc, I, "Loading ng map %s", m->volume);

	req = xseg_get_request(peer->xseg, pr->portno, mapper->mbportno, X_ALLOC);
	if (!req){
		XSEGLOG2(&lc, E, "Cannot allocate request for map %s",
				m->volume);
		goto out_fail;
	}

	r = xseg_prep_request(peer->xseg, req, m->volumelen, block_size);
	if (r < 0){
		XSEGLOG2(&lc, E, "Cannot prepare request for map %s",
				m->volume);
		goto out_put;
	}

	char *reqtarget = xseg_get_target(peer->xseg, req);
	if (!reqtarget)
		goto out_put;
	strncpy(reqtarget, m->volume, req->targetlen);
	req->op = X_READ;
	req->size = block_size;
	req->offset = 0;
	r = xseg_set_req_data(peer->xseg, req, pr);
	if (r < 0){
		XSEGLOG2(&lc, E, "Cannot set request data for map %s",
				m->volume);
		goto out_put;
	}
	p = xseg_submit(peer->xseg, req, pr->portno, X_ALLOC);
	if (p == NoPort){ 
		XSEGLOG2(&lc, E, "Cannot submit request for map %s",
				m->volume);
		goto out_unset;
	}
	r = xseg_signal(peer->xseg, p);
	
	XSEGLOG2(&lc, I, "Map %s loading", m->volume);
	return req;

out_unset:
	xseg_get_req_data(peer->xseg, req, &dummy);
out_put:
	xseg_put_request(peer->xseg, req, pr->portno);
out_fail:
	return NULL;
}

static int read_map (struct map *map, unsigned char *buf)
{
	char nulls[SHA256_DIGEST_SIZE];
	memset(nulls, 0, SHA256_DIGEST_SIZE);

	int r = !memcmp(buf, nulls, SHA256_DIGEST_SIZE);
	if (r) {
		XSEGLOG2(&lc, D, "Read zeros");
		//read error;
		return -1;
	}
	//type 1, archip type, type 0 pithos map
	int type = !memcmp(map->volume, MAPPER_PREFIX, MAPPER_PREFIX_LEN);
	XSEGLOG2(&lc, I, "Type %d detected for map %s", type, map->volume);
	uint64_t pos;
	uint64_t i, nr_objs;
	struct map_node *map_node;
	if (type) {
		uint64_t pos = 0;
		map->version = *(uint32_t *) (buf + pos);
		pos += sizeof(uint32_t);
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
			map_node[i].waiters = 0;
			map_node[i].ref = 1;
			map_node[i].cond = st_cond_new(); //FIXME err check;
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
			map_node[i].waiters = 0;
			map_node[i].ref = 1;
			map_node[i].cond = st_cond_new(); //FIXME err check;
			pithosmap_to_object(&map_node[i], buf + pos);
			pos += SHA256_DIGEST_SIZE;
			r = insert_object(map, &map_node[i]); //FIXME error check
		}
		map->size = i * block_size;
	}
	print_map(map);
	XSEGLOG2(&lc, I, "Map read for map %s completed", map->volume);
	return 0;

	//FIXME cleanup on error
}

static int load_map(struct peer_req *pr, struct map *map)
{
	int r = 0;
	struct xseg_request *req;
	struct peerd *peer = pr->peer;
	map->flags |= MF_MAP_LOADING;
	req = __load_map(pr, map);
	if (!req)
		return -1;
	wait_on_pr(pr, (!(req->state & XS_FAILED || req->state & XS_SERVED)));
	map->flags &= ~MF_MAP_LOADING;
	if (req->state & XS_FAILED){
		XSEGLOG2(&lc, E, "Map load failed for map %s", map->volume);
		xseg_put_request(peer->xseg, req, pr->portno);
		return -1;
	}
	r = read_map(map, (unsigned char *) xseg_get_data(peer->xseg, req));
	xseg_put_request(peer->xseg, req, pr->portno);
	return r;
}

static struct xseg_request * __open_map(struct peer_req *pr, struct map *m,
						uint32_t flags)
{
	int r;
	xport p;
	struct xseg_request *req;
	struct peerd *peer = pr->peer;
	struct mapperd *mapper = __get_mapperd(peer);
	void *dummy;

	XSEGLOG2(&lc, I, "Opening map %s", m->volume);

	req = xseg_get_request(peer->xseg, pr->portno, mapper->mbportno, X_ALLOC);
	if (!req){
		XSEGLOG2(&lc, E, "Cannot allocate request for map %s",
				m->volume);
		goto out_fail;
	}

	r = xseg_prep_request(peer->xseg, req, m->volumelen, block_size);
	if (r < 0){
		XSEGLOG2(&lc, E, "Cannot prepare request for map %s",
				m->volume);
		goto out_put;
	}

	char *reqtarget = xseg_get_target(peer->xseg, req);
	if (!reqtarget)
		goto out_put;
	strncpy(reqtarget, m->volume, req->targetlen);
	req->op = X_OPEN;
	req->size = block_size;
	req->offset = 0;
	if (!(flags & MF_FORCE))
		req->flags = XF_NOSYNC;
	r = xseg_set_req_data(peer->xseg, req, pr);
	if (r < 0){
		XSEGLOG2(&lc, E, "Cannot set request data for map %s",
				m->volume);
		goto out_put;
	}
	p = xseg_submit(peer->xseg, req, pr->portno, X_ALLOC);
	if (p == NoPort){ 
		XSEGLOG2(&lc, E, "Cannot submit request for map %s",
				m->volume);
		goto out_unset;
	}
	r = xseg_signal(peer->xseg, p);
	
	XSEGLOG2(&lc, I, "Map %s opening", m->volume);
	return req;

out_unset:
	xseg_get_req_data(peer->xseg, req, &dummy);
out_put:
	xseg_put_request(peer->xseg, req, pr->portno);
out_fail:
	return NULL;
}

static int open_map(struct peer_req *pr, struct map *map, uint32_t flags)
{
	int err;
	struct xseg_request *req;
	struct peerd *peer = pr->peer;

	map->flags |= MF_MAP_OPENING;
	req = __open_map(pr, map, flags);
	if (!req){
		map->flags &= ~MF_MAP_OPENING;
		return -1;
	}
	wait_on_pr(pr, (!((req->state & XS_FAILED)||(req->state & XS_SERVED))));
	map->flags &= ~MF_MAP_OPENING;
	err = req->state & XS_FAILED;
	xseg_put_request(peer->xseg, req, pr->portno);
	if (err)
		return -1;
	else 
		map->flags |= MF_MAP_EXCLUSIVE;
	return 0;
}

/*
 * copy up functions
 */

static int __set_copyup_node(struct mapper_io *mio, struct xseg_request *req, struct map_node *mn)
{
	int r = 0;
	if (mn){
		XSEGLOG2(&lc, D, "Inserting (req: %lx, mapnode: %lx) on mio %lx",
				req, mn, mio);
		r = xhash_insert(mio->copyups_nodes, (xhashidx) req, (xhashidx) mn);
		if (r == -XHASH_ERESIZE) {
			xhashidx shift = xhash_grow_size_shift(mio->copyups_nodes);
			xhash_t *new_hashmap = xhash_resize(mio->copyups_nodes, shift, NULL);
			if (!new_hashmap)
				goto out;
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
			xhash_t *new_hashmap = xhash_resize(mio->copyups_nodes, shift, NULL);
			if (!new_hashmap)
				goto out;
			mio->copyups_nodes = new_hashmap;
			r = xhash_delete(mio->copyups_nodes, (xhashidx) req);
		}
		if (r < 0)
			XSEGLOG2(&lc, E, "Deletion of %lx on mio %lx failed",
					req, mio);
	}
out:
	return r;
}

static struct map_node * __get_copyup_node(struct mapper_io *mio, struct xseg_request *req)
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

static struct xseg_request * copyup_object(struct peerd *peer, struct map_node *mn, struct peer_req *pr)
{
	struct mapperd *mapper = __get_mapperd(peer);
	struct mapper_io *mio = __get_mapper_io(pr);
	struct map *map = mn->map;
	void *dummy;
	int r = -1;
	xport p;

	uint32_t newtargetlen;
	char new_target[MAX_OBJECT_LEN + 1];
	unsigned char sha[SHA256_DIGEST_SIZE];

	strncpy(new_target, MAPPER_PREFIX, MAPPER_PREFIX_LEN);

	char tmp[XSEG_MAX_TARGETLEN + 1];
	uint32_t tmplen;
	strncpy(tmp, map->volume, map->volumelen);
	sprintf(tmp + map->volumelen, "_%u", mn->objectidx);
	tmp[XSEG_MAX_TARGETLEN] = 0;
	tmplen = strlen(tmp);
	SHA256((unsigned char *)tmp, tmplen, sha);
	hexlify(sha, new_target+MAPPER_PREFIX_LEN);
	newtargetlen = MAPPER_PREFIX_LEN + HEXLIFIED_SHA256_DIGEST_SIZE;


	if (!strncmp(mn->object, zero_block, ZERO_BLOCK_LEN))
		goto copyup_zeroblock;

	struct xseg_request *req = xseg_get_request(peer->xseg, pr->portno,
						mapper->bportno, X_ALLOC);
	if (!req){
		XSEGLOG2(&lc, E, "Cannot get request for object %s", mn->object);
		goto out_err;
	}
	r = xseg_prep_request(peer->xseg, req, newtargetlen, 
				sizeof(struct xseg_request_copy));
	if (r < 0){
		XSEGLOG2(&lc, E, "Cannot prepare request for object %s", mn->object);
		goto out_put;
	}

	char *target = xseg_get_target(peer->xseg, req);
	strncpy(target, new_target, req->targetlen);

	struct xseg_request_copy *xcopy = (struct xseg_request_copy *) xseg_get_data(peer->xseg, req);
	strncpy(xcopy->target, mn->object, mn->objectlen);
	xcopy->targetlen = mn->objectlen;

	req->offset = 0;
	req->size = block_size;
	req->op = X_COPY;
	r = xseg_set_req_data(peer->xseg, req, pr);
	if (r<0){
		XSEGLOG2(&lc, E, "Cannot set request data for object %s", mn->object);
		goto out_put;
	}
	r = __set_copyup_node(mio, req, mn);
	if (r < 0)
		goto out_unset;
	p = xseg_submit(peer->xseg, req, pr->portno, X_ALLOC);
	if (p == NoPort) {
		XSEGLOG2(&lc, E, "Cannot submit for object %s", mn->object);
		goto out_mapper_unset;
	}
	xseg_signal(peer->xseg, p);
//	mio->copyups++;

	mn->flags |= MF_OBJECT_COPYING;
	XSEGLOG2(&lc, I, "Copying up object %s \n\t to %s", mn->object, new_target);
	return req;

out_mapper_unset:
	__set_copyup_node(mio, req, NULL);
out_unset:
	xseg_get_req_data(peer->xseg, req, &dummy);
out_put:
	xseg_put_request(peer->xseg, req, pr->portno);
out_err:
	XSEGLOG2(&lc, E, "Copying up object %s \n\t to %s failed", mn->object, new_target);
	return NULL;

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
	req = object_write(peer, pr, map, &newmn);
	r = __set_copyup_node(mio, req, mn);
	if (r < 0)
		return NULL;
	if (!req){
		XSEGLOG2(&lc, E, "Object write returned error for object %s"
				"\n\t of map %s [%llu]",
				mn->object, map->volume, (unsigned long long) mn->objectidx);
		return NULL;
	}
	mn->flags |= MF_OBJECT_WRITING;
	XSEGLOG2(&lc, I, "Object %s copy up completed. Pending writing.", mn->object);
	return req;
}

static struct xseg_request * delete_object(struct peer_req *pr, struct map_node *mn)
{
	void *dummy;
	struct peerd *peer = pr->peer;
	struct mapperd *mapper = __get_mapperd(peer);
	struct mapper_io *mio = __get_mapper_io(pr);
	struct xseg_request *req = xseg_get_request(peer->xseg, pr->portno, 
							mapper->bportno, X_ALLOC);
	XSEGLOG2(&lc, I, "Deleting mapnode %s", mn->object);
	if (!req){
		XSEGLOG2(&lc, E, "Cannot get request for object %s", mn->object);
		goto out_err;
	}
	int r = xseg_prep_request(peer->xseg, req, mn->objectlen, 0);
	if (r < 0){
		XSEGLOG2(&lc, E, "Cannot prep request for object %s", mn->object);
		goto out_put;
	}
	char *target = xseg_get_target(peer->xseg, req);
	strncpy(target, mn->object, req->targetlen);
	req->op = X_DELETE;
	req->size = req->datalen;
	req->offset = 0;
	r = xseg_set_req_data(peer->xseg, req, pr);
	if (r < 0){
		XSEGLOG2(&lc, E, "Cannot set req data for object %s", mn->object);
		goto out_put;
	}
	r = __set_copyup_node(mio, req, mn);
	if (r < 0)
		goto out_unset;
	xport p = xseg_submit(peer->xseg, req, pr->portno, X_ALLOC);
	if (p == NoPort){
		XSEGLOG2(&lc, E, "Cannot submit request for object %s", mn->object);
		goto out_mapper_unset;
	}
	r = xseg_signal(peer->xseg, p);
	XSEGLOG2(&lc, I, "Object %s deletion pending", mn->object);
	return req;

out_mapper_unset:
	__set_copyup_node(mio, req, NULL);
out_unset:
	xseg_get_req_data(peer->xseg, req, &dummy);
out_put:
	xseg_put_request(peer->xseg, req, pr->portno);
out_err:
	XSEGLOG2(&lc, I, "Object %s deletion failed", mn->object);
	return NULL;
}

static struct xseg_request * delete_map(struct peer_req *pr, struct map *map)
{
	void *dummy;
	struct peerd *peer = pr->peer;
	struct mapperd *mapper = __get_mapperd(peer);
	struct mapper_io *mio = __get_mapper_io(pr);
	struct xseg_request *req = xseg_get_request(peer->xseg, pr->portno, 
							mapper->mbportno, X_ALLOC);
	XSEGLOG2(&lc, I, "Deleting map %s", map->volume);
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
	__set_copyup_node(mio, req, NULL);
	xport p = xseg_submit(peer->xseg, req, pr->portno, X_ALLOC);
	if (p == NoPort){
		XSEGLOG2(&lc, E, "Cannot submit request for map %s", map->volume);
		goto out_unset;
	}
	r = xseg_signal(peer->xseg, p);
	map->flags |= MF_MAP_DELETING;
	XSEGLOG2(&lc, I, "Map %s deletion pending", map->volume);
	return req;

out_unset:
	xseg_get_req_data(peer->xseg, req, &dummy);
out_put:
	xseg_put_request(peer->xseg, req, pr->portno);
out_err:
	XSEGLOG2(&lc, E, "Map %s deletion failed", map->volume);
	return  NULL;
}


static inline struct map_node * get_mapnode(struct map *map, uint32_t index)
{
	struct map_node *mn = find_object(map, index);
	if (mn)
		mn->ref++;
	return mn;
}

static inline void put_mapnode(struct map_node *mn)
{
	mn->ref--;
	if (!mn->ref){
		//clean up mn
		st_cond_destroy(mn->cond);
	}
}

static inline void __get_map(struct map *map)
{
	map->ref++;
}

static inline void put_map(struct map *map)
{
	struct map_node *mn;
	map->ref--;
	if (!map->ref){
		XSEGLOG2(&lc, I, "Freeing map %s", map->volume);
		//clean up map
		uint64_t i;
		for (i = 0; i < calc_map_obj(map); i++) {
			mn = get_mapnode(map, i);
			if (mn) {
				//make sure all pending operations on all objects are completed
				if (mn->flags & MF_OBJECT_NOT_READY){
					//this should never happen...
					wait_on_mapnode(mn, mn->flags & MF_OBJECT_NOT_READY);
				}
				mn->flags &= MF_OBJECT_DESTROYED;
				put_mapnode(mn); //matchin mn->ref = 1 on mn init
				put_mapnode(mn); //matcing get_mapnode;
				//assert mn->ref == 0;
			}
		}
		mn = find_object(map, 0);
		if (mn)
			free(mn);
		XSEGLOG2(&lc, I, "Freed map %s", map->volume);
		free(map);
	}
}

static struct map * create_map(struct mapperd *mapper, char *name,
				uint32_t namelen, uint32_t flags)
{
	int r;
	if (namelen + MAPPER_PREFIX_LEN > MAX_VOLUME_LEN){
		XSEGLOG2(&lc, E, "Namelen %u too long. Max: %d",
					namelen, MAX_VOLUME_LEN);
		return NULL;
	}
	struct map *m = malloc(sizeof(struct map));
	if (!m){
		XSEGLOG2(&lc, E, "Cannot allocate map ");
		goto out_err;
	}
	m->size = -1;
	if (flags & MF_ARCHIP){
		strncpy(m->volume, MAPPER_PREFIX, MAPPER_PREFIX_LEN);
		strncpy(m->volume + MAPPER_PREFIX_LEN, name, namelen);
		m->volume[MAPPER_PREFIX_LEN + namelen] = 0;
		m->volumelen = MAPPER_PREFIX_LEN + namelen;
		m->version = 1; /* keep this hardcoded for now */
	}
	else {
		strncpy(m->volume, name, namelen);
		m->volume[namelen] = 0;
		m->volumelen = namelen;
		m->version = 0; /* version 0 should be pithos maps */
	}
	m->flags = 0;
	m->objects = xhash_new(3, INTEGER); 
	if (!m->objects){
		XSEGLOG2(&lc, E, "Cannot allocate object hashmap for map %s",
				m->volume);
		goto out_map;
	}
	m->ref = 1;
	m->waiters = 0;
	m->cond = st_cond_new(); //FIXME err check;
	r = insert_map(mapper, m);
	if (r < 0){
		XSEGLOG2(&lc, E, "Cannot insert map %s", m->volume);
		goto out_hash;
	}

	return m;

out_hash:
	xhash_free(m->objects);
out_map:
	XSEGLOG2(&lc, E, "failed to create map %s", m->volume);
	free(m);
out_err:
	return NULL;
}



void deletion_cb(struct peer_req *pr, struct xseg_request *req)
{
	struct peerd *peer = pr->peer;
	struct mapperd *mapper = __get_mapperd(peer);
	(void)mapper;
	struct mapper_io *mio = __get_mapper_io(pr);
	struct map_node *mn = __get_copyup_node(mio, req);

	__set_copyup_node(mio, req, NULL);

	XSEGLOG2(&lc, D, "mio: %lx, del_pending: %llu", mio, mio->del_pending);
	mio->del_pending--;
	if (req->state & XS_FAILED){
		mio->err = 1;
	}
	if (mn){
		XSEGLOG2(&lc, D, "Found mapnode %lx %s for mio: %lx, req: %lx",
				mn, mn->object, mio, req);
		signal_mapnode(mn);
	}
	else {
		XSEGLOG2(&lc, E, "Cannot get map node for mio: %lx, req: %lx",
				mio, req);
	}
	xseg_put_request(peer->xseg, req, pr->portno);
	signal_pr(pr);
}

void copyup_cb(struct peer_req *pr, struct xseg_request *req)
{
	struct peerd *peer = pr->peer;
	struct mapperd *mapper = __get_mapperd(peer);
	(void)mapper;
	struct mapper_io *mio = __get_mapper_io(pr);
	struct map_node *mn = __get_copyup_node(mio, req);
	if (!mn){
		XSEGLOG2(&lc, E, "Cannot get map node");
		goto out_err;
	}
	__set_copyup_node(mio, req, NULL);

	if (req->state & XS_FAILED){
		XSEGLOG2(&lc, E, "Req failed");
		mn->flags &= ~MF_OBJECT_COPYING;
		mn->flags &= ~MF_OBJECT_WRITING;
		goto out_err;
	}
	if (req->op == X_WRITE) {
		char *target = xseg_get_target(peer->xseg, req);
		(void)target;
		//printf("handle object write replyi\n");
		__set_copyup_node(mio, req, NULL);
		//assert mn->flags & MF_OBJECT_WRITING
		mn->flags &= ~MF_OBJECT_WRITING;

		struct map_node tmp;
		char *data = xseg_get_data(peer->xseg, req);
		map_to_object(&tmp, (unsigned char *) data);
		mn->flags |= MF_OBJECT_EXIST;
		if (mn->flags != MF_OBJECT_EXIST){
			XSEGLOG2(&lc, E, "map node %s has wrong flags", mn->object);
			goto out_err;
		}
		//assert mn->flags & MF_OBJECT_EXIST
		strncpy(mn->object, tmp.object, tmp.objectlen);
		mn->object[tmp.objectlen] = 0;
		mn->objectlen = tmp.objectlen;
		XSEGLOG2(&lc, I, "Object write of %s completed successfully", mn->object);
		mio->copyups--;
		signal_mapnode(mn);
	} else if (req->op == X_COPY) {
	//	issue write_object;
		mn->flags &= ~MF_OBJECT_COPYING;
		struct map *map = mn->map;
		if (!map){
			XSEGLOG2(&lc, E, "Object %s has not map back pointer", mn->object);
			goto out_err;
		}

		/* construct a tmp map_node for writing purposes */
		char *target = xseg_get_target(peer->xseg, req);
		struct map_node newmn = *mn;
		newmn.flags = MF_OBJECT_EXIST;
		strncpy(newmn.object, target, req->targetlen);
		newmn.object[req->targetlen] = 0;
		newmn.objectlen = req->targetlen;
		newmn.objectidx = mn->objectidx; 
		struct xseg_request *xreq = object_write(peer, pr, map, &newmn);
		if (!xreq){
			XSEGLOG2(&lc, E, "Object write returned error for object %s"
					"\n\t of map %s [%llu]",
					mn->object, map->volume, (unsigned long long) mn->objectidx);
			goto out_err;
		}
		mn->flags |= MF_OBJECT_WRITING;
		__set_copyup_node (mio, xreq, mn);

		XSEGLOG2(&lc, I, "Object %s copy up completed. Pending writing.", mn->object);
	} else {
		//wtf??
		;
	}

out:
	xseg_put_request(peer->xseg, req, pr->portno);
	return;

out_err:
	mio->copyups--;
	XSEGLOG2(&lc, D, "Mio->copyups: %u", mio->copyups);
	mio->err = 1;
	if (mn)
		signal_mapnode(mn);
	goto out;

}

struct r2o {
	struct map_node *mn;
	uint64_t offset;
	uint64_t size;
};

static int req2objs(struct peer_req *pr, struct map *map, int write)
{
	int r = 0;
	struct peerd *peer = pr->peer;
	struct mapper_io *mio = __get_mapper_io(pr);
	char *target = xseg_get_target(peer->xseg, pr->req);
	uint32_t nr_objs = calc_nr_obj(pr->req);
	uint64_t size = sizeof(struct xseg_reply_map) + 
			nr_objs * sizeof(struct xseg_reply_map_scatterlist);
	uint32_t idx, i, ready;
	uint64_t rem_size, obj_index, obj_offset, obj_size; 
	struct map_node *mn;
	mio->copyups = 0;
	XSEGLOG2(&lc, D, "Calculated %u nr_objs", nr_objs);

	/* get map_nodes of request */
	struct r2o *mns = malloc(sizeof(struct r2o)*nr_objs);
	if (!mns){
		XSEGLOG2(&lc, E, "Cannot allocate mns");
		return -1;
	}
	idx = 0;
	rem_size = pr->req->size;
	obj_index = pr->req->offset / block_size;
	obj_offset = pr->req->offset & (block_size -1); //modulo
	obj_size =  (obj_offset + rem_size > block_size) ? block_size - obj_offset : rem_size;
	mn = get_mapnode(map, obj_index);
	if (!mn) {
		XSEGLOG2(&lc, E, "Cannot find obj_index %llu\n", (unsigned long long) obj_index);
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
		obj_size = (rem_size >  block_size) ? block_size : rem_size;
		rem_size -= obj_size;
		mn = get_mapnode(map, obj_index);
		if (!mn) {
			XSEGLOG2(&lc, E, "Cannot find obj_index %llu\n", (unsigned long long) obj_index);
			r = -1;
			goto out;
		}
		mns[idx].mn = mn;
		mns[idx].offset = obj_offset;
		mns[idx].size = obj_size;
	}
	if (write) {
		ready = 0;
		int can_wait = 0;
		mio->cb=copyup_cb;
		while (ready < (idx + 1)){
			ready = 0;
			for (i = 0; i < (idx+1); i++) {
				mn = mns[i].mn;
				//do copyups
				if (mn->flags & MF_OBJECT_NOT_READY) {
					if (can_wait){
						wait_on_mapnode(mn, mn->flags & MF_OBJECT_NOT_READY);
						if (mn->flags & MF_OBJECT_DESTROYED){
							mio->err = 1;
						}
						if (mio->err){
							XSEGLOG2(&lc, E, "Mio-err, pending_copyups: %d", mio->copyups);
							if (!mio->copyups){
								r = -1;
								goto out;
							}
						}
					}
				}
				else if (!(mn->flags & MF_OBJECT_EXIST)) {
					//calc new_target, copy up object
					if (copyup_object(peer, mn, pr) == NULL){
						XSEGLOG2(&lc, E, "Error in copy up object");
						mio->err = 1;
					} else {
						mio->copyups++;
					}
				} else {
					ready++;
				}
			}
			can_wait = 1;
		}
		/*
pending_copyups:
		while(mio->copyups > 0){
			mio->cb = copyup_cb;
			wait_on_pr(pr, 0);
			ta--;
			st_cond_wait(pr->cond);
		}
		*/
	}

	if (mio->err){
		r = -1;
		XSEGLOG2(&lc, E, "Mio->err");
		goto out;
	}

	/* resize request to fit reply */
	char buf[XSEG_MAX_TARGETLEN];
	strncpy(buf, target, pr->req->targetlen);
	r = xseg_resize_request(peer->xseg, pr->req, pr->req->targetlen, size);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Cannot resize request");
		goto out;
	}
	target = xseg_get_target(peer->xseg, pr->req);
	strncpy(target, buf, pr->req->targetlen);

	/* structure reply */
	struct xseg_reply_map *reply = (struct xseg_reply_map *) xseg_get_data(peer->xseg, pr->req);
	reply->cnt = nr_objs;
	for (i = 0; i < (idx+1); i++) {
		strncpy(reply->segs[i].target, mns[i].mn->object, mns[i].mn->objectlen);
		reply->segs[i].targetlen = mns[i].mn->objectlen;
		reply->segs[i].offset = mns[i].offset;
		reply->segs[i].size = mns[i].size;
	}
out:
	for (i = 0; i < idx; i++) {
		put_mapnode(mns[i].mn);
	}
	free(mns);
	return r;
}

static int do_dropcache(struct peer_req *pr, struct map *map)
{
	struct map_node *mn;
	struct peerd *peer = pr->peer;
	struct mapperd *mapper = __get_mapperd(peer);
	uint64_t i;
	XSEGLOG2(&lc, I, "Dropping cache for map %s", map->volume);
	map->flags |= MF_MAP_DROPPING_CACHE;
	for (i = 0; i < calc_map_obj(map); i++) {
		mn = get_mapnode(map, i);
		if (mn) {
			if (!(mn->flags & MF_OBJECT_DESTROYED)){
				//make sure all pending operations on all objects are completed
				if (mn->flags & MF_OBJECT_NOT_READY){
					wait_on_mapnode(mn, mn->flags & MF_OBJECT_NOT_READY);
				}
				mn->flags &= MF_OBJECT_DESTROYED;
			}
			put_mapnode(mn);
		}
	}
	map->flags &= ~MF_MAP_DROPPING_CACHE;
	map->flags |= MF_MAP_DESTROYED;
	remove_map(mapper, map);
	XSEGLOG2(&lc, I, "Dropping cache for map %s completed", map->volume);
	put_map(map);	// put map here to destroy it (matches m->ref = 1 on map create)
	return 0;
}

static int do_info(struct peer_req *pr, struct map *map)
{
	struct peerd *peer = pr->peer;
	struct xseg_reply_info *xinfo = (struct xseg_reply_info *) xseg_get_data(peer->xseg, pr->req);
	xinfo->size = map->size;
	return 0;
}


static int do_close(struct peer_req *pr, struct map *map)
{
	if (map->flags & MF_MAP_EXCLUSIVE){
		/* do not drop cache if close failed and map not deleted */
		if (close_map(pr, map) < 0 && !(map->flags & MF_MAP_DELETED))
			return -1;
	}
	return do_dropcache(pr, map);
}

static int do_destroy(struct peer_req *pr, struct map *map)
{
	uint64_t i;
	struct peerd *peer = pr->peer;
	struct mapper_io *mio = __get_mapper_io(pr);
	struct map_node *mn;
	struct xseg_request *req;
	
	XSEGLOG2(&lc, I, "Destroying map %s", map->volume);
	map->flags |= MF_MAP_DELETING;
	req = delete_map(pr, map);
	if (!req)
		return -1;
	wait_on_pr(pr, (!((req->state & XS_FAILED)||(req->state & XS_SERVED))));
	if (req->state & XS_FAILED){
		xseg_put_request(peer->xseg, req, pr->portno);
		map->flags &= ~MF_MAP_DELETING;
		return -1;
	}
	xseg_put_request(peer->xseg, req, pr->portno);
	//FIXME
	uint64_t nr_obj = calc_map_obj(map);
	uint64_t deleted = 0;
	while (deleted < nr_obj){ 
		deleted = 0;
		for (i = 0; i < nr_obj; i++){
			mn = get_mapnode(map, i);
			if (mn) {
				if (!(mn->flags & MF_OBJECT_DESTROYED)){
					if (mn->flags & MF_OBJECT_EXIST){
						//make sure all pending operations on all objects are completed
						if (mn->flags & MF_OBJECT_NOT_READY){
							wait_on_mapnode(mn, mn->flags & MF_OBJECT_NOT_READY);
						}
						req = delete_object(pr, mn);
						if (!req)
							if (mio->del_pending){
								goto wait_pending;
							} else {
								continue;
							}
						else {
							mio->del_pending++;
						}
					}
					mn->flags &= MF_OBJECT_DESTROYED;
				}
				put_mapnode(mn);
			}
			deleted++;
		}
wait_pending:
		mio->cb = deletion_cb;
		wait_on_pr(pr, mio->del_pending > 0);
	}
	mio->cb = NULL;
	map->flags &= ~MF_MAP_DELETING;
	map->flags |= MF_MAP_DELETED;
	XSEGLOG2(&lc, I, "Destroyed map %s", map->volume);
	return do_close(pr, map);
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
	int r = req2objs(pr, map, 1);
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
	/*
	FIXME check if clone map exists
	clonemap = get_map(pr, target, targetlen, MF_LOAD);
	if (clonemap)
		do_dropcache(pr, clonemap); // drop map here, rely on get_map_function to drop
					//	cache on non-exclusive opens or declare a NO_CACHE flag ?
		return -1;
	*/

	int r;
	char buf[XSEG_MAX_TARGETLEN];
	struct peerd *peer = pr->peer;
	struct mapperd *mapper = __get_mapperd(peer);
	char *target = xseg_get_target(peer->xseg, pr->req);
	struct xseg_request_clone *xclone = (struct xseg_request_clone *) xseg_get_data(peer->xseg, pr->req);
	XSEGLOG2(&lc, I, "Cloning map %s", map->volume);
	struct map *clonemap = create_map(mapper, target, pr->req->targetlen,
						MF_ARCHIP);
	if (!clonemap) 
		return -1;

	if (xclone->size == -1)
		clonemap->size = map->size;
	else
		clonemap->size = xclone->size;
	if (clonemap->size < map->size){
		target = xseg_get_target(peer->xseg, pr->req);
		strncpy(buf, target, pr->req->targetlen);
		buf[pr->req->targetlen] = 0;
		XSEGLOG2(&lc, W, "Requested clone size (%llu) < map size (%llu)"
				"\n\t for requested clone %s",
				(unsigned long long) xclone->size,
				(unsigned long long) map->size, buf);
		goto out_err;
	}

	//alloc and init map_nodes
	unsigned long c = clonemap->size/block_size + 1;
	struct map_node *map_nodes = calloc(c, sizeof(struct map_node));
	if (!map_nodes){
		goto out_err;
	}
	int i;
	for (i = 0; i < clonemap->size/block_size + 1; i++) {
		struct map_node *mn = get_mapnode(map, i);
		if (mn) {
			strncpy(map_nodes[i].object, mn->object, mn->objectlen);
			map_nodes[i].objectlen = mn->objectlen;
			put_mapnode(mn);
		} else {
			strncpy(map_nodes[i].object, zero_block, ZERO_BLOCK_LEN);
			map_nodes[i].objectlen = ZERO_BLOCK_LEN;
		}
		map_nodes[i].object[map_nodes[i].objectlen] = 0; //NULL terminate
		map_nodes[i].flags = 0;
		map_nodes[i].objectidx = i;
		map_nodes[i].map = clonemap;
		map_nodes[i].ref = 1;
		map_nodes[i].waiters = 0;
		map_nodes[i].cond = st_cond_new(); //FIXME errcheck;
		r = insert_object(clonemap, &map_nodes[i]);
		if (r < 0){
			XSEGLOG2(&lc, E, "Cannot insert object %d to map %s", i, clonemap->volume);
			goto out_err;
		}
	}
	r = write_map(pr, clonemap);
	if (r < 0){
		XSEGLOG2(&lc, E, "Cannot write map %s", clonemap->volume);
		goto out_err;
	}
	return 0;

out_err:
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
	if (!map){
		if (flags & MF_LOAD){
			map = create_map(mapper, name, namelen, flags);
			if (!map)
				return NULL;
			r = open_load_map(pr, map, flags);
			if (r < 0){
				do_dropcache(pr, map);
				return NULL;
			}
		} else {
			return NULL;
		}
	} else if (map->flags & MF_MAP_DESTROYED){
		return NULL;
	}
	__get_map(map);
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
	if (map->flags & MF_MAP_NOT_READY){
		wait_on_map(map, (map->flags & MF_MAP_NOT_READY));
		put_map(map);
		goto start;
	}
	int r = action(pr, map);
	//always drop cache if map not read exclusively
	if (!(map->flags & MF_MAP_EXCLUSIVE))
		do_dropcache(pr, map);
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
	struct xseg_request_clone *xclone = (struct xseg_request_clone *) xseg_get_data(peer->xseg, pr->req);
	if (!xclone) {
		r = -1;
		goto out;
	}
	if (xclone->targetlen){
		//support clone only from pithos
		r = map_action(do_clone, pr, xclone->target, xclone->targetlen,
					MF_LOAD);
	} else {
		if (!xclone->size){
			r = -1;
		} else {
			//FIXME
			struct map *map;
			char *target = xseg_get_target(peer->xseg, pr->req);
			XSEGLOG2(&lc, I, "Creating volume");
			map = get_map(pr, target, pr->req->targetlen,
						MF_ARCHIP|MF_LOAD);
			if (map){
				XSEGLOG2(&lc, E, "Volume %s exists", map->volume);
				if (map->ref <= 2) //initial one + one ref from __get_map
					do_dropcache(pr, map); //we are the only ones usining this map. Drop the cache. 
				put_map(map); //matches get_map
				r = -1;
				goto out;
			}
			//create a new empty map of size
			map = create_map(mapper, target, pr->req->targetlen,
						MF_ARCHIP);
			if (!map){
				r = -1;
				goto out;
			}
			map->size = xclone->size;
			//populate_map with zero objects;
			uint64_t nr_objs = xclone->size / block_size;
			if (xclone->size % block_size)
				nr_objs++;

			struct map_node *map_nodes = calloc(nr_objs, sizeof(struct map_node));
			if (!map_nodes){
				do_dropcache(pr, map); //Since we just created the map, dropping cache should be sufficient.
				r = -1;
				goto out;
			}
			uint64_t i;
			for (i = 0; i < nr_objs; i++) {
				strncpy(map_nodes[i].object, zero_block, ZERO_BLOCK_LEN);
				map_nodes[i].objectlen = ZERO_BLOCK_LEN;
				map_nodes[i].object[map_nodes[i].objectlen] = 0; //NULL terminate
				map_nodes[i].flags = 0;
				map_nodes[i].objectidx = i;
				map_nodes[i].map = map;
				map_nodes[i].ref = 1;
				map_nodes[i].waiters = 0;
				map_nodes[i].cond = st_cond_new(); //FIXME errcheck;
				r = insert_object(map, &map_nodes[i]);
				if (r < 0){
					do_dropcache(pr, map);
					r = -1;
					goto out;
				}
			}
			r = write_map(pr, map);
			if (r < 0){
				XSEGLOG2(&lc, E, "Cannot write map %s", map->volume);
				do_dropcache(pr, map);
				goto out;
			}
			XSEGLOG2(&lc, I, "Volume %s created", map->volume);
			r = 0;
			do_dropcache(pr, map); //drop cache here for consistency
		}
	}
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
	int r = map_action(do_destroy, pr, target, pr->req->targetlen,
				MF_ARCHIP|MF_LOAD|MF_EXCLUSIVE|MF_FORCE);
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

int dispatch_accepted(struct peerd *peer, struct peer_req *pr, 
			struct xseg_request *req)
{
	//struct mapperd *mapper = __get_mapperd(peer);
	struct mapper_io *mio = __get_mapper_io(pr);
	void *(*action)(struct peer_req *) = NULL;

	mio->state = ACCEPTED;
	mio->err = 0;
	mio->cb = NULL;
	switch (pr->req->op) {
		/* primary xseg operations of mapper */
		case X_CLONE: action = handle_clone; break;
		case X_MAPR: action = handle_mapr; break;
		case X_MAPW: action = handle_mapw; break;
//		case X_SNAPSHOT: handle_snap(peer, pr, req); break;
		case X_INFO: action = handle_info; break;
		case X_DELETE: action = handle_destroy; break;
		case X_CLOSE: action = handle_close; break;
		default: fprintf(stderr, "mydispatch: unknown up\n"); break;
	}
	if (action){
		ta++;
		mio->active = 1;
		st_thread_create(action, pr, 0, 0);
	}
	return 0;

}

int dispatch(struct peerd *peer, struct peer_req *pr, struct xseg_request *req,
		enum dispatch_reason reason)
{
	struct mapperd *mapper = __get_mapperd(peer);
	(void) mapper;
	struct mapper_io *mio = __get_mapper_io(pr);
	(void) mio;


	if (reason == dispatch_accept)
		dispatch_accepted(peer, pr, req);
	else {
		if (mio->cb){
			mio->cb(pr, req);
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
	struct mapperd *mapperd = malloc(sizeof(struct mapperd));
	peer->priv = mapperd;
	mapper = mapperd;
	mapper->hashmaps = xhash_new(3, STRING);

	printf("%llu \n", MAX_VOLUME_SIZE);
	for (i = 0; i < peer->nr_ops; i++) {
		struct mapper_io *mio = malloc(sizeof(struct mapper_io));
		mio->copyups_nodes = xhash_new(3, INTEGER);
		mio->copyups = 0;
		mio->err = 0;
		mio->active = 0;
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

	const struct sched_param param = { .sched_priority = 99 };
	sched_setscheduler(syscall(SYS_gettid), SCHED_FIFO, &param);


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
	struct xseg_request *req, *received;
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
		xseg_wait_signal(xseg, 1000000UL);
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
	int r;
	struct map *map;
	struct xseg_request *req;
	xhash_iter_t it;
	xhashidx key, val;
	xhash_iter_init(mapper->hashmaps, &it);
	while (xhash_iterate(mapper->hashmaps, &it, &key, &val)){
		map = (struct map *)val;
		if (!(map->flags & MF_MAP_EXCLUSIVE))
			continue;
		map->flags |= MF_MAP_CLOSING;
		req = __close_map(pr, map);
		if (!req)
			continue;
		wait_reply(peer, req);
		if (!(req->state & XS_SERVED))
			XSEGLOG2(&lc, E, "Couldn't close map %s", map->volume);
		map->flags &= ~MF_MAP_CLOSING;
		xseg_put_request(peer->xseg, req, pr->portno);
	}
	return;


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
