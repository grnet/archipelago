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

#include <xtypes/xobj.h>
#include <xtypes/xhash.h>
#include <xtypes/domain.h>

int xobj_handler_init(struct xobject_h *obj_h, void *container,
		uint32_t magic,	uint64_t size, struct xheap *heap)
{
	//uint64_t bytes;
	xhash_t *xhash;
	obj_h->magic = magic;
	/* minimum object size */
	if (size < sizeof(struct xobject))
		obj_h->obj_size = sizeof(struct xobject);
	else
		obj_h->obj_size = size;

	//TODO convert this to xset
	/* request space of an xhash of sizeshift 3 */
	xhash = (xhash_t *) xheap_allocate(heap, xhash_get_alloc_size(3));
	if (!xhash)
		return -1;

	//FIXME
	/* but initialize an xhash with sizeshift based on
	 * allocated space. should be at least the above sizeshift
	 */
	//bytes = xheap_get_chunk_size(xhash);

	xhash_init(xhash, 3, INTEGER);
	obj_h->allocated = XPTR_MAKE(xhash, container);
	obj_h->list = 0;
	obj_h->flags = 0;
	obj_h->nr_free = 0;
	obj_h->nr_allocated = 0;
	obj_h->allocated_space = 0;
	obj_h->heap = XPTR_MAKE(heap, container);
	XPTRSET(&obj_h->container, container);
	xlock_release(&obj_h->lock);
	return 0;

}

int xobj_alloc_obj(struct xobject_h * obj_h, uint64_t nr)
{
	void *container = XPTR(&obj_h->container);
	struct xheap *heap = XPTR_TAKE(obj_h->heap, container);
	struct xobject *obj = NULL;

	uint64_t used, bytes = nr * obj_h->obj_size;
	xptr ptr, objptr;
	xhash_t *allocated = XPTR_TAKE(obj_h->allocated, container);
	int r;

	void *mem = xheap_allocate(heap, bytes);
	if (!mem)
		return -1;

	bytes = xheap_get_chunk_size(mem);
	used = 0;
	while (used + obj_h->obj_size < bytes) {
		objptr = XPTR_MAKE(((unsigned long) mem) + used, container);
		obj = XPTR_TAKE(objptr, container);
		used += obj_h->obj_size;
		obj->magic = obj_h->magic;
		obj->size = obj_h->obj_size;
		obj->next = XPTR_MAKE(((unsigned long) mem) + used, container); //point to the next obj
	}
	if (!obj)
		goto err;

	/* keep track of allocated objects.
	 * Since the whole allocated space is split up into objects,
	 * we can calculate allocated objects from the allocated heap
	 * space and object size.
	 */
	ptr = XPTR_MAKE(mem, container);
	r = xhash_insert(allocated, ptr, ptr);
	//ugly
	if (r == -XHASH_ERESIZE) {
		xhashidx sizeshift = xhash_grow_size_shift(allocated);
		uint64_t size;
		xhash_t *new;
		size = xhash_get_alloc_size(sizeshift);
		new = xheap_allocate(heap, size);
		if (!new)
			goto err;
		xhash_resize(allocated, sizeshift, new);
		xheap_free(allocated);
		allocated = new;
		obj_h->allocated = XPTR_MAKE(allocated, container);
		r = xhash_insert(allocated, ptr, ptr);
	}
	if (r < 0)
		goto err;

	obj_h->allocated_space += bytes;
	obj_h->nr_free += bytes/obj_h->obj_size;
	obj_h->nr_allocated += bytes/obj_h->obj_size;
	obj->next = obj_h->list;
	obj_h->list = ptr;
	return 0;

err:
	xheap_free(mem);
	return -1;

}
void xobj_put_obj(struct xobject_h * obj_h, void *ptr)
{
	struct xobject *obj = (struct xobject *) ptr;
	void *container = XPTR(&obj_h->container);
	xptr list, objptr = XPTR_MAKE(obj, container);

	xlock_acquire(&obj_h->lock, 1);
	list = obj_h->list;
	obj->magic = obj_h->magic;
	obj->size = obj_h->obj_size;
	obj->next = list;
	obj_h->list = objptr;
	obj_h->nr_free++;
	xlock_release(&obj_h->lock);
}

void * xobj_get_obj(struct xobject_h * obj_h, uint32_t flags)
{

	void *container = XPTR(&obj_h->container);
	struct xobject *obj = NULL;
	int r;
	xptr list, objptr;

	xlock_acquire(&obj_h->lock, 1);
retry:
	list = obj_h->list;
	if (!list)
		goto alloc;
	obj = XPTR_TAKE(list, container);
	objptr = obj->next;
	obj_h->list = objptr;
	obj_h->nr_free--;
	goto out;

alloc:
	if (!(flags & X_ALLOC))
		goto out;
	//allocate minimum 64 objects
	r = xobj_alloc_obj(obj_h, 64);
	if (r<0)
		goto out;
	goto retry;
out:
	xlock_release(&obj_h->lock);
	return obj;
}

/* lock must be held, while using iteration on object handler
 * or we risk hash resize and invalid memory access
 */
void xobj_iter_init(struct xobject_h *obj_h, struct xobject_iter *it)
{
	void *container = XPTR(&obj_h->container);

	xhash_t *allocated = XPTR_TAKE(obj_h->allocated, container);
	it->obj_h = obj_h;
	xhash_iter_init(allocated, &it->xhash_it);
	it->chunk = NULL;
	it->cnt = 0;
}

int xobj_iterate(struct xobject_h *obj_h, struct xobject_iter *it, void **obj)
{
	int r = 0;
	void *container = XPTR(&obj_h->container);
	xhash_t *allocated = XPTR_TAKE(obj_h->allocated, container);
	xhashidx key, val;

	if (!it->chunk ||
	     it->cnt >= xheap_get_chunk_size(it->chunk)/obj_h->obj_size){
		r = xhash_iterate(allocated, &it->xhash_it, &key, &val);
		if (!r)
			return 0;
		it->chunk = XPTR_TAKE(key, container);
		it->cnt = 0;
	}

	*obj = (void *) ((unsigned long) it->chunk +
			(unsigned long) it->cnt * obj_h->obj_size);
	it->cnt++;

	return 1;

}

//FIXME make it smarter. aka check if ptr in mem chunk range and offset is
//consistent wit obj_size
int __xobj_check(struct xobject_h *obj_h, void *ptr)
{
	xhash_iter_t it;
	uint64_t i, nr_objs;
	xhashidx key, val;
	void *mem;
	void *obj;
	void *container = XPTR(&obj_h->container);
	xhash_t *allocated = XPTR_TAKE(obj_h->allocated, container);
	xhash_iter_init(allocated, &it);
	while (xhash_iterate(allocated, &it, &key, &val)){
		mem = XPTR_TAKE(key, container);
		nr_objs = xheap_get_chunk_size(mem)/obj_h->obj_size;
		for (i = 0; i < nr_objs; i++) {
			obj = (void *) ((unsigned long) mem +
					(unsigned long) i * obj_h->obj_size);
			if (obj == ptr) {
				return 1;
			}
		}
	}
	return 0;
}

int xobj_check(struct xobject_h *obj_h, void *ptr)
{
	int r;
	xlock_acquire(&obj_h->lock, 1);
	r = __xobj_check(obj_h, ptr);
	xlock_release(&obj_h->lock);
	return r;
}

int __xobj_isFree(struct xobject_h *obj_h, void *ptr)
{
	void *container = XPTR(&obj_h->container);
	xptr node;
	struct xobject *obj;


	node = obj_h->list;
	while (node){
		obj = XPTR_TAKE(node, container);
		if (obj == ptr){
			return 1;
		}
		node = obj->next;
	}


	return 0;
}

int xobj_isFree(struct xobject_h *obj_h, void *ptr)
{
	int r;
	xlock_acquire(&obj_h->lock, 1);
	r = __xobj_isFree(obj_h, ptr);
	xlock_release(&obj_h->lock);
	return r;
}


#ifdef __KERNEL__
#include <linux/module.h>
#include <xtypes/xobj_exports.h>
#endif
