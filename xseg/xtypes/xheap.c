#include <xtypes/xheap.h>
#include <xtypes/domain.h>
//#include "xheap.h"
//#include "domain.h"
//#include <stdio.h>

//aligned alloc bytes with header size
static inline uint64_t __get_alloc_bytes(struct xheap *xheap, uint64_t bytes)
{
	return __align(bytes + sizeof(struct xheap_header), xheap->alignment_unit);
}

static inline struct xheap_header* __get_header(void *ptr)
{
	return (struct xheap_header *) (ptr - sizeof(struct xheap_header));
}

static inline int __get_index(struct xheap *heap, uint64_t bytes)
{
	bytes = __get_alloc_bytes(heap, bytes) - sizeof(struct xheap_header);
	return (sizeof(bytes)*8 - __builtin_clzl(bytes -1));
}

uint64_t xheap_get_chunk_size(void *ptr)
{
	struct xheap_header *h = __get_header(ptr);
	return h->size;
}

/* return a pointer to a memory of size 
 * __align(bytes, xheap->alignment_unit) - sizeof(xheap_header)
 */
void* xheap_allocate(struct xheap *heap, uint64_t bytes)
{
	struct xheap_header *h;
	int r = __get_index(heap, bytes);
	void *mem = XPTR(&heap->mem), *addr = NULL;
	xptr *free_list = (xptr *) mem;
	xptr head, next;

	xlock_acquire(&heap->lock, 1);

	head = free_list[r];
	//printf("(r: %d) list[%x]: %lu\n", r, &free_list[r], list);
	if (!head)
		goto alloc;
	next = *(xptr *)(((unsigned long) mem) + head);
	free_list[r] = next;
//	printf("popped %llu out of list. list is now %llu\n", head, next);
	addr = (void *) (((unsigned long)mem) + head);
	goto out;

alloc:
	bytes = __get_alloc_bytes(heap, bytes);
//	printf("before heap->cur: %llu\n", heap->cur);
//	printf("bytes: %llu\n", bytes);
	if (heap->cur + bytes > heap->size)
		goto out;
	addr = (void *) (((unsigned long) mem) + heap->cur + sizeof(struct xheap_header));
//	printf("after heap->cur: %llu\n", heap->cur);
	h = (struct xheap_header *) (((unsigned long) mem) + heap->cur);
	h->size = bytes - sizeof(struct xheap_header);
	XPTRSET(&h->heap, heap);
	heap->cur += bytes;

out:
	xlock_release(&heap->lock);
//	printf("alloced: %lx (size: %llu) (xptr: %llu)\n", addr, __get_header(addr)->size,
//			addr-mem);
	return addr;
}

void __add_in_free_list(struct xheap *heap, xptr* list, void *ptr)
{
	void *mem = XPTR(&heap->mem);
	xptr abs_ptr = (xptr) ((unsigned long)ptr - (unsigned long) mem);
	xptr cur, *node = (xptr *) ptr;

	xlock_acquire(&heap->lock, 2);

	cur = *(volatile xptr *)list;
	*node = cur;
	*list = abs_ptr;
	//printf("cur: %llu, next: %llu\n", cur, abs_ptr);
	//printf("next points to %llu\n", *(xptr *) ptr);

	xlock_release(&heap->lock);
}

void xheap_free(void *ptr)
{
	struct xheap_header *h = __get_header(ptr);
	struct xheap *heap = XPTR(&h->heap);
	void *mem = XPTR(&heap->mem);
	uint64_t size = xheap_get_chunk_size(ptr);
	xptr *free_list = (xptr *) mem;
	int r = __get_index(heap, size);
	//printf("size: %llu, r: %d\n", size, r);
	__add_in_free_list(heap, &free_list[r], ptr);
//	printf("freed %lx (size: %llu)\n", ptr, __get_header(ptr)->size);
	return;
}

int xheap_init(struct xheap *heap, uint64_t size, uint32_t alignment_unit, void *mem)
{
	//int r = (sizeof(size)*8 - __builtin_clzl(size));
	int r, i;
	void *al_mem = (void *) __align((unsigned long)mem, alignment_unit);
	uint64_t diff = (uint64_t) ((unsigned long)al_mem - (unsigned long)mem);
	uint64_t heap_page = 1 << alignment_unit;
	xptr * free_list;

	heap->cur = diff;
	heap->size = size;
	heap->alignment_unit = alignment_unit;
	XPTRSET(&heap->mem, mem);
	
	r = __get_index(heap, size);
	
	/* minimum alignment unit required */
	if (heap_page < sizeof(struct xheap_header))
		return -1;
	//if (heap_page < sizeof(xptr *) * r)
	//	return -1;

	/* make sure unused space in heap start can hold a header*/
	if (heap->cur < sizeof(struct xheap_header)) {
		heap->cur += heap_page;
	}
	heap->cur -= sizeof(struct xheap_header);

	/* make sure there is enough unused space in heap start to be
	 * used as an indexing array
	 */
	while (heap->cur < sizeof(xptr *) * r)
			heap->cur += heap_page;

	/* clean up index array */
	free_list = (xptr *) mem;
	for (i = 0; i < r; i++) {
		free_list[i] = 0;
	}	

	/* make sure there is at least one "heap_page" to allocate */
	if (heap->cur >= size - heap_page)
		return -1;
	xlock_release(&heap->lock);

	return 0;
}
