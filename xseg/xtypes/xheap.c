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

#include <xtypes/xheap.h>
#include <xtypes/domain.h>

// small allocations are considered those  < 1 << (alignment_unit + SMALL_LIMIT)
#define SMALL_LIMIT 5	
// medium allocations are considered those < 1 << (alignment_unit + MEDIUM_LIMIT)
#define MEDIUM_LIMIT 10	

//This (the -3) ensures that the space that is allocated
//beyond the requested bytes is less than 12.5 % of requested space
#define MEDIUM_AL_UNIT (SMALL_LIMIT - 3) 
#define LARGE_AL_UNIT (MEDIUM_LIMIT - 3) 

/*
 * Heap allocation sizes:
 * 0 - SMALL_LIMIT -> bytes round up to (1 << alignment_unit)
 * SMALL_LIMIT - MEDIUM_LIMIT -> bytes round up to (1 << (alignment_unit+ MEDIUM_AL_UNIT))
 * MEDIUM_LIMIT - ... -> bytes round up to ( 1 << (alignment_unit + LARGE_AL_UNIT) )
 */

//aligned alloc bytes with header size
static inline uint64_t __get_alloc_bytes(struct xheap *xheap, uint64_t bytes)
{
	if (bytes < 1<<(xheap->alignment_unit + SMALL_LIMIT))
		return __align(bytes + sizeof(struct xheap_header), 
				xheap->alignment_unit);
	else if (bytes < 1<<(xheap->alignment_unit + MEDIUM_LIMIT))
		return __align(bytes + sizeof(struct xheap_header),
				xheap->alignment_unit + MEDIUM_AL_UNIT);
	else
		return __align(bytes + sizeof(struct xheap_header), 
				xheap->alignment_unit + LARGE_AL_UNIT);
}

static inline struct xheap_header* __get_header(void *ptr)
{
	return (struct xheap_header *) ((unsigned long)ptr - sizeof(struct xheap_header));
}

static inline int __get_index(struct xheap *heap, uint64_t bytes)
{
	int r;
	uint32_t alignment_unit = heap->alignment_unit;
	bytes = __get_alloc_bytes(heap, bytes) - sizeof(struct xheap_header);

	if (bytes < (1<<(alignment_unit + SMALL_LIMIT)))
		r = bytes >> alignment_unit;
	else if (bytes < (1 << (alignment_unit + MEDIUM_LIMIT))) {
		r = (1 << SMALL_LIMIT);
		//r -= (1 << (alignment_unit+SMALL_LIMIT)) / (1 << (alignment_unit + MEDIUM_AL_UNIT));
		r -= (1 << (SMALL_LIMIT - MEDIUM_AL_UNIT));
		//XSEGLOG("%u, %u, r %d\n",((1<<alignment_unit) * 32), (1 << (alignment_unit +2)), r);
		r += (bytes >> (alignment_unit + MEDIUM_AL_UNIT));
	}
	else {
		r = (1 << SMALL_LIMIT) + (1 << MEDIUM_LIMIT);
		r -= 1 << (SMALL_LIMIT - MEDIUM_AL_UNIT);
		r -= 1 << (MEDIUM_LIMIT - (LARGE_AL_UNIT - MEDIUM_AL_UNIT));
		r += bytes >> (alignment_unit + LARGE_AL_UNIT);
	}
	return r;
}

uint64_t xheap_get_chunk_size(void *ptr)
{
	struct xheap_header *h = __get_header(ptr);
	return h->size;
}

void* xheap_allocate(struct xheap *heap, uint64_t bytes)
{
	struct xheap_header *h;
	int r = __get_index(heap, bytes);
	void *mem = XPTR(&heap->mem), *addr = NULL;
	xptr *free_list = (xptr *) mem;
	xptr head, next;
	uint64_t req_bytes = bytes;

	xlock_acquire(&heap->lock, 1);

	head = free_list[r];
	//printf("(r: %d) list[%x]: %lu\n", r, &free_list[r], list);
	if (!head)
		goto alloc;
	if (head > heap->cur) {
		XSEGLOG("invalid xptr %llu found in chunk lists\n", head);
		goto out;
	}
	next = *(xptr *)(((unsigned long) mem) + head);
	free_list[r] = next;
//	XSEGLOG("alloced %llu bytes from list %d\n", bytes, r);
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
	h->magic = 0xdeadbeaf;
	XPTRSET(&h->heap, heap);
	heap->cur += bytes;

out:
	xlock_release(&heap->lock);
//	printf("alloced: %lx (size: %llu) (xptr: %llu)\n", addr, __get_header(addr)->size,
//			addr-mem);
	if (addr && xheap_get_chunk_size(addr) < req_bytes){
		XSEGLOG("requested %llu bytes but heap returned %llu", 
				req_bytes, xheap_get_chunk_size(addr));
		addr = NULL;
	}
	if (addr && xheap_get_chunk_size(addr) != (__get_alloc_bytes(heap, req_bytes) - 
					sizeof(struct xheap_header))) {
		XSEGLOG("allocated chunk size %llu, but it should be %llu (req_bytes %llu)",
			xheap_get_chunk_size(addr), __get_alloc_bytes(heap, req_bytes), req_bytes);
		addr = NULL;
	}
	return addr;
}

static inline void __add_in_free_list(struct xheap *heap, xptr* list, void *ptr)
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
	void *mem;
	uint64_t size;
	int r;
	xptr *free_list;
	if (h->magic != 0xdeadbeaf) {
		XSEGLOG("for ptr: %lx, magic %lx != 0xdeadbeaf", ptr, h->magic);
	}
	mem = XPTR(&heap->mem);
	size = xheap_get_chunk_size(ptr);
	free_list = (xptr *) mem;
	r = __get_index(heap, size);
	//printf("size: %llu, r: %d\n", size, r);
	__add_in_free_list(heap, &free_list[r], ptr);
//	printf("freed %lx (size: %llu)\n", ptr, __get_header(ptr)->size);
//	XSEGLOG("freed %llu bytes to list %d\n", size, r);
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
