/*
 * Copyright 2013 GRNET S.A. All rights reserved.
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

#ifndef MAPPER_H

#define MAPPER_H

#include <unistd.h>
#include <xseg/xseg.h>
#include <hash.h>
#include <peer.h>
#include <xseg/protocol.h>
#include <mapper-version0.h>
#include <mapper-version1.h>
#include <mapper-version2.h>

/* Alternative, each header file could define an appropriate MAP_V# */
enum {MAP_V0, MAP_V1, MAP_V2};
#define MAP_LATEST_VERSION MAP_V2
#define MAP_LATEST_MOPS &v2_ops

struct header_struct {
	uint32_t signature;
	uint32_t version;
	unsigned char pad[504];
} __attribute__((packed));

#define MAX_MAPHEADER_SIZE (sizeof(struct header_struct))

/* should always be the maximum objectlen of all versions */
#define MAX_OBJECT_LEN 128

/* since object names are cacluclated from the volume names, the limit of the
 * maximum volume len is calculated from the maximum object len, statically for
 * all map versions.
 *
 * How the object name is calculated is reflected in this formula:
 *
 * volume-index-epoch
 */
#define MAX_VOLUME_LEN (MAX_OBJECT_LEN - HEXLIFIED_INDEX - HEXLIFIED_EPOCH - 2)


/* Some compile time checks */
#if MAX_OBJECT_LEN > XSEG_MAX_TARGETLEN
#error 	"XSEG_MAX_TARGETLEN should be at least MAX_OBJECT_LEN"
#endif

#if MAX_OBJECT_LEN < v2_max_objectlen
#error "MAX_OBJECT_LEN is smaller than v2_max_objectlen"
#endif

#if MAX_OBJECT_LEN < v1_max_objectlen
#error "MAX_OBJECT_LEN is smaller than v1_max_objectlen"
#endif

#if MAX_OBJECT_LEN < v0_max_objectlen
#error "MAX_OBJECT_LEN is smaller than v0_max_objectlen"
#endif

/* TODO Use some form of static assert for the following. Comment out for now.

#if MAX_MAPHEADER_SIZE < v2_mapheader_size
#error "MAX_MAPHEADER_SIZE is smaller than v2_mapheader_size"
#endif

#if MAX_MAPHEADER_SIZE < v1_mapheader_size
#error "MAX_MAPHEADER_SIZE is smaller than v1_mapheader_size"
#endif

#if MAX_MAPHEADER_SIZE < v0_mapheader_size
#error "MAX_MAPHEADER_SIZE is smaller than v0_mapheader_size"
#endif

*/

/*
#if MAX_VOLUME_LEN > XSEG_MAX_TARGETLEN
#error 	"XSEG_MAX_TARGETLEN should be at least MAX_VOLUME_LEN"
#endif
*/

struct map;
struct map_node;
/* Map I/O ops */
struct map_ops {
	void (*object_to_map)(unsigned char *buf, struct map_node *mn);
	int (*read_object)(struct map_node *mn, unsigned char *buf);
	struct xseg_request * (*prepare_write_object)(struct peer_req *pr,
			struct map *map, struct map_node *mn);
	int (*load_map_data)(struct peer_req *pr, struct map *map);
	int (*write_map_data)(struct peer_req *pr, struct map *map);
	int (*delete_map_data)(struct peer_req *pr, struct map *map);
};

/* general mapper flags */
#define MF_LOAD 	(1 << 0)
#define MF_EXCLUSIVE 	(1 << 1)
#define MF_FORCE 	(1 << 2)
#define MF_ARCHIP	(1 << 3)

#define MAPPER_DEFAULT_BLOCKSIZE (1<<22)

#define MAPPER_PREFIX "archip_"
#define MAPPER_PREFIX_LEN 7

/* These values come straight from the size of map_node->objectidx and
 * map->epoch.
 */
#define HEXLIFIED_EPOCH (sizeof(uint64_t) << 1)
#define HEXLIFIED_INDEX (sizeof(uint64_t) << 1)



extern char *zero_block;
#define ZERO_BLOCK_LEN (64) /* strlen(zero_block) */

/* callback function type */
typedef void (*cb_t)(struct peer_req *pr, struct xseg_request *req);


/* map object flags */
#define MF_OBJECT_WRITABLE	(1 << 0)
#define MF_OBJECT_ARCHIP	(1 << 1)
#define MF_OBJECT_ZERO		(1 << 2)
#define MF_OBJECT_DELETED	(1 << 3)

/* run time map object state flags */
#define MF_OBJECT_COPYING	(1 << 0)
#define MF_OBJECT_WRITING	(1 << 1)
#define MF_OBJECT_DELETING	(1 << 2)
//#define MF_OBJECT_DESTROYED	(1 << 3)
#define MF_OBJECT_SNAPSHOTTING	(1 << 4)

#define MF_OBJECT_NOT_READY	(MF_OBJECT_COPYING|MF_OBJECT_WRITING|\
				MF_OBJECT_DELETING|MF_OBJECT_SNAPSHOTTING)
struct map_node {
	uint32_t flags;
	volatile uint32_t state;
	uint64_t objectidx;	/* FIXME this is probably not needed */
	uint32_t objectlen;
	char object[MAX_OBJECT_LEN + 1]; 	/* NULL terminated string */
	struct map *map;
	volatile uint32_t ref;
	volatile uint32_t waiters;
	st_cond_t cond;
};


/* map flags */
#define MF_MAP_READONLY		(1 << 0)
#define MF_MAP_DELETED		(1 << 1)

/* run time map state flags */
#define MF_MAP_LOADING		(1 << 0)
#define MF_MAP_DESTROYED	(1 << 1)
#define MF_MAP_WRITING		(1 << 2)
#define MF_MAP_DELETING		(1 << 3)
#define MF_MAP_DROPPING_CACHE	(1 << 4)
#define MF_MAP_EXCLUSIVE	(1 << 5)
#define MF_MAP_OPENING		(1 << 6)
#define MF_MAP_CLOSING		(1 << 7)
//#define MF_MAP_DELETED		(1 << 8)
#define MF_MAP_SNAPSHOTTING	(1 << 9)
#define MF_MAP_SERIALIZING	(1 << 10)
#define MF_MAP_HASHING		(1 << 11)
#define MF_MAP_RENAMING		(1 << 12)
#define MF_MAP_CANCACHE		(1 << 13)
#define MF_MAP_NOT_READY	(MF_MAP_LOADING|MF_MAP_WRITING|MF_MAP_DELETING|\
				MF_MAP_DROPPING_CACHE|MF_MAP_OPENING|	       \
				MF_MAP_SNAPSHOTTING|MF_MAP_SERIALIZING|        \
				MF_MAP_HASHING|MF_MAP_RENAMING)


/* hex value of "AMF." 
 * Stands for Archipelago Map Format */
#define MAP_SIGNATURE (uint32_t)(0x414d462e)

struct map {
	uint32_t version;
	uint32_t signature;
	uint64_t epoch;
	uint32_t flags;
	volatile uint32_t state;
	uint64_t size;
	uint32_t blocksize;
	uint64_t nr_objs;
	uint32_t volumelen;
	char volume[MAX_VOLUME_LEN + 1]; /* NULL terminated string */
	struct map_node *objects;
	volatile uint32_t ref;
	volatile uint32_t waiters;
	st_cond_t cond;
	uint64_t opened_count;
	struct map_ops *mops;

	volatile uint32_t users;
	volatile uint32_t waiters_users;
	st_cond_t users_cond;
};

struct mapperd {
	xport bportno;		/* blocker that accesses data */
	xport mbportno;		/* blocker that accesses maps */
	xhash_t *hashmaps; // hash_function(target) --> struct map
};

struct mapper_io {
	xhash_t *copyups_nodes;		/* hash map (xseg_request) --> (corresponding map_node of copied up object)*/
	volatile int err;		/* error flag */
	cb_t cb;
	volatile int active;
	void *priv;
	volatile uint64_t pending_reqs;
	uint64_t count;
};

/* usefull abstraction macros for context switching */

#define wait_on_pr(__pr, __condition__) 	\
	do {					\
		ta--;				\
		__get_mapper_io(pr)->active = 0;\
		XSEGLOG2(&lc, D, "Waiting on pr %lx, ta: %u",  pr, ta); \
		st_cond_wait(__pr->cond);	\
	} while (__condition__)

#define wait_on_mapnode(__mn, __condition__)	\
	do {					\
		ta--;				\
		__mn->waiters++;		\
		XSEGLOG2(&lc, D, "Waiting on map node %lx %s, waiters: %u, \
			ta: %u",  __mn, __mn->object, __mn->waiters, ta);  \
		st_cond_wait(__mn->cond);	\
	} while (__condition__)

#define wait_on_map(__map, __condition__)	\
	do {					\
		ta--;				\
		__map->waiters++;		\
		XSEGLOG2(&lc, D, "Waiting on map %lx %s, waiters: %u, ta: %u",\
				   __map, __map->volume, __map->waiters, ta); \
		st_cond_wait(__map->cond);	\
	} while (__condition__)

#define wait_all_objects_ready(__map)	\
	do {					\
		ta--;				\
		__map->waiters_users++;		\
		XSEGLOG2(&lc, D, "Waiting for objects ready on map %lx %s, waiters: %u, ta: %u",\
				   __map, __map->volume, __map->waiters_users, ta); \
		st_cond_wait(__map->users_cond);	\
	} while (__map->users)

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
		XSEGLOG2(&lc, D, "Checking map %lx %s. Waiters %u, ta: %u", \
				__map, __map->volume, __map->waiters, ta);  \
		if (__map->waiters) {		\
			ta += __map->waiters;		\
			XSEGLOG2(&lc, D, "Signaling map %lx %s, waiters: %u, \
			ta: %u",  __map, __map->volume, __map->waiters, ta); \
			__map->waiters = 0;	\
			st_cond_broadcast(__map->cond);	\
		}				\
	}while(0)

#define signal_all_objects_ready(__map)			\
	do { 					\
		/* assert __map->users == 0 */ \
		if (__map->waiters_users) {		\
			ta += __map->waiters_users;		\
			XSEGLOG2(&lc, D, "Signaling objects ready for map %lx %s, waiters: %u, \
			ta: %u",  __map, __map->volume, __map->waiters_users, ta); \
			__map->waiters_users = 0;	\
			st_cond_broadcast(__map->users_cond);	\
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


/* Helper functions */
static inline struct mapperd * __get_mapperd(struct peerd *peer)
{
	return (struct mapperd *) peer->priv;
}

static inline struct mapper_io * __get_mapper_io(struct peer_req *pr)
{
	return (struct mapper_io *) pr->priv;
}

static inline uint64_t __calc_map_obj(uint64_t size, uint32_t blocksize)
{
	uint64_t nr_objs;

	nr_objs = size / blocksize;
	if (size % blocksize)
		nr_objs++;

	return nr_objs;
}

static inline uint64_t calc_map_obj(struct map *map)
{
	return __calc_map_obj(map->size, map->blocksize);
}

static inline int is_valid_blocksize(uint64_t x) {
	   return x && !(x & (x - 1));
}

/* map handling functions */
struct xseg_request * __open_map(struct peer_req *pr, struct map *m,
						uint32_t flags);
int open_map(struct peer_req *pr, struct map *map, uint32_t flags);
struct xseg_request * __close_map(struct peer_req *pr, struct map *map);
int close_map(struct peer_req *pr, struct map *map);
struct xseg_request * __write_map(struct peer_req* pr, struct map *map);
int write_map(struct peer_req* pr, struct map *map);
int write_map_metadata(struct peer_req* pr, struct map *map);
struct xseg_request * __load_map(struct peer_req *pr, struct map *m);
int read_map(struct map *map, unsigned char *buf);
int load_map(struct peer_req *pr, struct map *map);
struct xseg_request * __copyup_object(struct peer_req *pr, struct map_node *mn);
void copyup_cb(struct peer_req *pr, struct xseg_request *req);
struct xseg_request * __object_write(struct peerd *peer, struct peer_req *pr,
				struct map *map, struct map_node *mn);
int __set_node(struct mapper_io *mio, struct xseg_request *req,
			struct map_node *mn);
struct map_node * __get_node(struct mapper_io *mio, struct xseg_request *req);
int send_request(struct peer_req *pr, struct xseg_request *req);
struct xseg_request * get_request(struct peer_req *pr, xport dst, char * target,
		uint32_t targetlen, uint64_t datalen);
void put_request(struct peer_req *pr, struct xseg_request *req);
struct xseg_request * __load_map_metadata(struct peer_req *pr, struct map *map);
int load_map_metadata(struct peer_req *pr, struct map *map);
int delete_map_data(struct peer_req *pr, struct map *map);
int initialize_map_objects(struct map *map);
int hash_map(struct peer_req *pr, struct map *map, struct map *hashed_map);
struct map_node * get_mapnode(struct map *map, uint64_t objindex);
void put_mapnode(struct map_node *mn);
struct xseg_request * __object_delete(struct peer_req *pr, struct map_node *mn);
void object_delete_cb(struct peer_req *pr, struct xseg_request *req);
#endif /* end MAPPER_H */
