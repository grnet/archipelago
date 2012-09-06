#include <xtypes/xpool.h>

static inline int __validate_idx(struct xpool *xp, xpool_index idx) 
{
	struct xpool_node *node = XPTR(&xp->mem)+idx;
	return (idx < xp->size && node->prev != NoIndex);
}

void __xpool_clear(struct xpool *xp)
{
	uint64_t i;
	uint64_t size = xp->size;
	struct xpool_node *mem = XPTR(&xp->mem);

	xp->list = NoIndex;
	for (i = 1; i < size; i++) {
		mem[i-1].prev = NoIndex;
		mem[i-1].next = i;
	}
	mem[size-1].prev = NoIndex;
	mem[size-1].next = NoIndex;
	xp->free = 0;
}

void xpool_clear(struct xpool *xp, uint32_t who)
{
	xlock_acquire(&xp->lock, who);
	__xpool_clear(xp);
	xlock_release(&xp->lock);
}

void xpool_init(struct xpool *xp, uint64_t size, struct xpool_node* mem)
{
	xp->size = size;
	XPTRSET(&xp->mem, mem);
	xlock_release(&xp->lock);
	__xpool_clear(xp);
}

xpool_index __xpool_add(struct xpool *xp, xpool_data data)
{
	struct xpool_node *new, *list, *prev;
	xpool_index idx;

	idx = xp->free;
	if (idx == NoIndex){
		return NoIndex;
	}
	new = XPTR(&xp->mem) + idx;
	xp->free = new->next;
	new->data = data;

	if (xp->list != NoIndex) {
		list = XPTR(&xp->mem) + xp->list;
		new->next = xp->list;
		new->prev = list->prev;

		prev = XPTR(&xp->mem) + list->prev;
		prev->next = idx;
		list->prev = idx;
	} else {
		new->next = idx;
		new->prev = idx;
		xp->list =idx;
	}
	/*
	idx = xp->list;
	list = XPTR(&xp->mem) + idx;
	printf("xpool data: %llu(%llu), ", xp->list, list->data );
	do {
	idx = list->next;
	list = XPTR(&xp->mem) + idx;
	printf("%llu(%llu), ", idx, list->data);
	}while(idx != xp->list);
	printf("\n");
	*/
	
	return idx;
}

xpool_index xpool_add(struct xpool *xp, xpool_data data, uint32_t who)
{
	xpool_index idx;
	xlock_acquire(&xp->lock, who);
	idx = __xpool_add(xp, data);
	xlock_release(&xp->lock);
	return idx;
}
/*
xpool_index xpool_add(struct xpool *xp, xpool_data data)
{
	struct xpool_node *new, *list, *free, *next, *prev;
	//acquire lock
	xlock_acquire(&xp->lock, 1);
	free = XPTR(&xp->free);
	list = XPTR(&xp->list);
	new = free;
	if (new == NULL){
		xlock_release(&xp->lock);
		return NoIndex;
	}
	free = XPTR(&new->next);
	XPTRSET(&xp->free, free);
	if (list) {
		//new->next = xp->list;
		XPTRSET(&new->next, list);

		prev = XPTR(&list->prev);
		XPTRSET(&new->prev, prev);
		//new->prev = xp->list->prev;

		next = XPTR(&prev->next);
		XPTRSET(&prev->next, new);
		//xp->list->prev->next = new;
		
		XPTRSET(&list->prev, new);
		//xp->list->prev = new;
	} else {
		XPTRSET(&new->next ,new);
		//new->next = new;
		XPTRSET(&new->prev, new);
		//new->prev = new;
		XPTRSET(&xp->list, new);
		//xp->list = new;
	}
	new->data = data;
	//release lock
	xlock_release(&xp->lock);
	return (new - XPTR(&xp->mem));
}
*/
/*
xpool_index xpool_remove(struct xpool *xp, xpool_index idx, xpool_data *data)
{
	struct xpool_node *node, *list, *free, *prev, *next;
	//acquire lock
	xlock_acquire(&xp->lock, 1);
	if (!__validate_idx(xp, idx)){ // idx < xp->size && node->prev != NULL
		xlock_release(&xp->lock);
		return NoIndex;
	}
	node = XPTR(&xp->mem) + idx;
	*data = node->data;
	list = XPTR(&xp->list);
	free = XPTR(&xp->free);
	next = XPTR(&node->next);
	prev = XPTR(&node->prev);
	if (node == list){
		if (node == next)
			XPTRSET(&xp->list, NULL);
			//xp->list = NULL;
		else
			XPTRSET(&xp->list, next);
			//xp->list = node->next;
	}
	XPTRSET(&prev->next, next);
	//node->prev->next = node->next;
	XPTRSET(&next->prev, prev);
	//node->next->prev = node->prev;
	XPTRSET(&node->prev, NULL);
	//node->prev = NULL;
	XPTRSET(&node->next, free);
	//node->next = xp->free;
	free = node;
	XPTRSET(&xp->free, free);
	//xp->free = node;
	
	//release lock
	xlock_release(&xp->lock);
	return idx;
}
*/
xpool_index __xpool_remove(struct xpool *xp, xpool_index idx, xpool_data *data)
{
	struct xpool_node *node, *prev, *next;
	if (!__validate_idx(xp, idx)){ // idx < xp->size && node->prev != NULL
		return NoIndex;
	}
	node = XPTR(&xp->mem) + idx;
	*data = node->data;

	if (idx == xp->list){
		if ( idx == node->next)
			xp->list = NoIndex;
		else
			xp->list = node->next;
	}
	prev = XPTR(&xp->mem) + node->prev;
	prev->next = node->next;
	
	next = XPTR(&xp->mem) + node->next;
	next->prev = node->prev;

	node->prev = NoIndex;
	node->next = xp->free;
	xp->free = idx;
	return idx;
}

xpool_index xpool_remove(struct xpool *xp, xpool_index idx, xpool_data *data, uint32_t who)
{
	xpool_index ret;
	xlock_acquire(&xp->lock, who);
	ret = __xpool_remove(xp, idx, data);
	xlock_release(&xp->lock);
	return ret;
}

xpool_index __xpool_peek(struct xpool *xp, xpool_data *data)
{
	struct xpool_node *list;
	xpool_index ret;
	if (xp->list == NoIndex){
		return NoIndex;
	}
	ret = xp->list;
	list = XPTR(&xp->mem) + xp->list;
	*data = list->data;
	return ret;
}

xpool_index xpool_peek(struct xpool *xp, xpool_data *data, uint32_t who)
{
	xpool_index ret;
	xlock_acquire(&xp->lock, who);
	ret = __xpool_peek(xp, data);
	xlock_release(&xp->lock);
	return ret;
}

xpool_index __xpool_peek_idx(struct xpool *xp, xpool_index idx, xpool_data *data)
{
	struct xpool_node *node;
	if (!__validate_idx(xp, idx)){
		return NoIndex;
	}
	node = XPTR(&xp->mem) + idx;
	*data = node->data;
	return idx;
}

xpool_index xpool_peek_idx(struct xpool *xp, xpool_index idx, xpool_data *data, uint32_t who)
{
	xpool_index ret;
	xlock_acquire(&xp->lock, who);
	ret = __xpool_peek_idx(xp,idx,data);
	xlock_release(&xp->lock);
	return ret;
}

xpool_index __xpool_peek_and_fwd(struct xpool *xp, xpool_data *data)
{
	struct xpool_node *list;
	xpool_index ret;
	if (xp->list == NoIndex){
		return NoIndex;
	}
	ret = xp->list;
	list = XPTR(&xp->mem) + xp->list;
	*data = list->data;
	xp->list = list->next;
	return ret;
}

xpool_index xpool_peek_and_fwd(struct xpool *xp, xpool_data *data, uint32_t who)
{
	xpool_index ret;
	xlock_acquire(&xp->lock, who);
	ret = __xpool_peek_and_fwd(xp,data);
	xlock_release(&xp->lock);
	return ret;
}

/*
xpool_index xpool_peek_and_fwd(struct xpool *xp, xpool_data *data)
{
	struct xpool_node *list, *next;
	//acquire lock
	xlock_acquire(&xp->lock, 1);
	list = XPTR(&xp->list);
	if (!list){
		xlock_release(&xp->lock);
		return NoIndex;
	}
	*data = list->data;
	next = XPTR(&list->next);
	XPTRSET(&xp->list, next);
	//xp->list = xp->list->next;
	//release lock
	xlock_release(&xp->lock);
	return (list - XPTR(&xp->mem));
}
*/

xpool_index __xpool_set_idx(struct xpool *xp, xpool_index idx, xpool_data data)
{
	struct xpool_node *node;
	if (!__validate_idx(xp, idx)){
		return NoIndex;
	}
	node = XPTR(&xp->mem) + idx;
	node->data = data;
	return idx;
}

xpool_index xpool_set_idx(struct xpool *xp, xpool_index idx, xpool_data data, uint32_t who)
{
	xpool_index ret;
	xlock_acquire(&xp->lock, who);
	ret = __xpool_set_idx(xp, idx, data);
	xlock_release(&xp->lock);
	return ret;
}


#ifdef __KERNEL__
#include <linux/module.h>
#include <xtypes/xpool_exports.h>
#endif
