#ifndef XPOOL_H
#define XPOOL_H

#include <sys/util.h>
#include <xtypes/xlock.h>
//#include <xseg/xseg.h>

typedef uint64_t xpool_index;
typedef uint64_t xpool_data;
#define NoIndex ((xpool_index) -1)


struct xpool_node {
	xpool_data data;
	//XPTR_TYPE(struct xpool_node) next;
	//XPTR_TYPE(struct xpool_node) prev;
	xpool_index next;
	xpool_index prev;
};

struct xpool {
	struct xlock lock;
	//XPTR_TYPE(struct xpool_node) list;
	//XPTR_TYPE(struct xpool_node) free;
	xpool_index list;
	xpool_index free;
	uint64_t size;
	XPTR_TYPE(struct xpool_node) mem;
};

void xpool_init(struct xpool *xp, uint64_t size, struct xpool_node* mem);
void xpool_clear(struct xpool *xp, uint32_t who);
xpool_index xpool_add(struct xpool *xp, xpool_data data, uint32_t who);
xpool_index xpool_remove(struct xpool *xp, xpool_index idx, xpool_data *data, uint32_t who);
xpool_index xpool_peek(struct xpool *xp, xpool_data *data, uint32_t who);
xpool_index xpool_peek_idx(struct xpool *xp, xpool_index idx, xpool_data *data, uint32_t who);
xpool_index xpool_peek_and_fwd(struct xpool *xp, xpool_data *data, uint32_t who);
xpool_index xpool_set_idx(struct xpool *xp, xpool_index idx, xpool_data data, uint32_t who);

void __xpool_clear(struct xpool *xp);
xpool_index __xpool_add(struct xpool *xp, xpool_data data);
xpool_index __xpool_remove(struct xpool *xp, xpool_index idx, xpool_data *data);
xpool_index __xpool_peek(struct xpool *xp, xpool_data *data);
xpool_index __xpool_peek_idx(struct xpool *xp, xpool_index idx, xpool_data *data);
xpool_index __xpool_peek_and_fwd(struct xpool *xp, xpool_data *data);
xpool_index __xpool_set_idx(struct xpool *xp, xpool_index idx, xpool_data data);

#endif /* XPOOL_H */
