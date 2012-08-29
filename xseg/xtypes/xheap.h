#ifndef __XHEAP_H__
#define __XHEAP_H__

#include <sys/util.h>
#include <xtypes/xlock.h>

struct xheap_header {
	XPTR_TYPE(struct xheap) heap;
	uint64_t size;
};

struct xheap {
	uint32_t alignment_unit;
	uint64_t size;
	uint64_t cur;
	struct xlock lock;
	XPTR_TYPE(void) mem;
};

uint64_t xheap_get_chunk_size(void *ptr);
int xheap_init(struct xheap *xheap, uint64_t size, uint32_t alignment_unit, void *mem);
void* xheap_allocate(struct xheap *xheap, uint64_t bytes);
void xheap_free(void *ptr);

#endif
