#ifndef _XLIST_H
#define _XLIST_H

#include <xq/xq.h>

struct xlist_node {
	XPTR_TYPE(struct xlist_node) head;
	XPTR_TYPE(struct xlist_node) tail;
	XPTR_TYPE(struct xlist) list;
};

struct xlist {
	XPTR_TYPE(struct xlist_node) node;
};

xqindex xlist_add(struct xlist *list, struct xlist_node *node);
void xlist_del(struct xlist_node *node);

#endif
