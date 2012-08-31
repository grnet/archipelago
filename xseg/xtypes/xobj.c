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
	
	xhash_init(xhash, 3);
	obj_h->allocated = XPTR_MAKE(xhash, container);
	obj_h->list = 0;
	obj_h->flags = 0;
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

	unsigned long i = 0;

	uint64_t used, bytes = nr * obj_h->obj_size;
	xptr objptr;
	xhash_t *allocated = XPTR_TAKE(obj_h->allocated, container);
	int r;
	
	void *mem = xheap_allocate(heap, bytes);

	if (!mem)
		return -1;

	bytes = xheap_get_chunk_size(mem);
//	printf("memory: %lu\n", XPTR_MAKE(mem, container));
	used = 0;
	while (used + obj_h->obj_size < bytes) {
//		printf("obj_size: %llu, used: %llu, bytes: %llu\n", obj_h->obj_size, used, bytes);
		objptr = XPTR_MAKE(((unsigned long) mem) + used, container);
//		printf("objptr: %lu\n", objptr);
		obj = XPTR_TAKE(objptr, container);
		used += obj_h->obj_size;
		obj->magic = obj_h->magic;
		obj->size = obj_h->obj_size;
		obj->next = XPTR_MAKE(((unsigned long) mem) + used, container); //point to the next obj
//		printf("foo: %lx\n", &obj->next);
		
		i++;

retry:
		r = xhash_insert(allocated, objptr, objptr); //keep track of allocated objects
		//ugly
		if (r == -XHASH_ERESIZE) {
			ul_t sizeshift = grow_size_shift(allocated);
//			printf("new sizeshift: %lu\n", sizeshift);
			uint64_t size;
			xhash_t *new;
			size = xhash_get_alloc_size(sizeshift); 
//			printf("new size: %lu\n", size);
//			printf("%llu\n", xheap_get_chunk_size(allocated));
			new = xheap_allocate(heap, size);
//			printf("requested %llu, got %llu\n", size, xheap_get_chunk_size(new));
			if (!new) {
				xheap_free(mem);
				return -1;
			}
			xhash_resize(allocated, sizeshift, new);
			xheap_free(allocated);
			allocated = new;
			obj_h->allocated = XPTR_MAKE(allocated, container);
			goto retry;
		}
	}
	XSEGLOG("allocated %lu elements\n", i);
	if (!obj)
		return -1;
	objptr = obj_h->list;
	obj->next = objptr; 
	obj_h->list = XPTR_MAKE((unsigned long) mem, container);
	return 0;
}

void xobj_put_obj(struct xobject_h * obj_h, void *ptr)
{
	struct xobject *obj = (struct xobject *) ptr;
	void *container = XPTR(&obj_h->container);
	xptr list, objptr = XPTR_MAKE(obj, container);
	xlock_acquire(&obj_h->lock, 1);
	list = obj_h->list;
	obj->next = list;
	obj_h->list = objptr;
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

