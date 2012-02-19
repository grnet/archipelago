#include <xq/xlist.h>

void __xlist_detach(struct xlist_node *node)
{
	struct xlist_node *head, *tail;
	head = XPTR(&node->head);
	tail = XPTR(&node->tail);
	if (head)
		XPTRSET(&head->tail, tail);
	if (tail)
		XPTRSET(&tail->head, head);
	XPTRSET(&node->pool, NULL);
}

void __xlist_attach(	struct xlist_node *head,
			struct xlist_node *tail,
			struct xlist_node *node	)
{
	struct xlist *list = XPTR(node->list);
	xqindex nr = XPTRI(&list->node.list);

	if (!list || !nr)
		return;

	XPTRSET(&node->head, head);
	XPTRSET(&node->tail, tail);
	XPTRSET(&head->tail, node);
	XPTRSET(&tail->head, node);
	XPTRISET(&list->node.list, nr - 1);
}

xqindex xlist_add_head(struct xlist *list, struct xlist_node *node)
{
	struct xlist_node *head;
	xqindex nr = XPTRI(&list->node.list) + 1;

	if (nr == None)
		goto out;

	__xlist_detach(node);
	head = XPTR(&node->head);
	__xlist_attach(head, &list->node, node);

	XPTRISET(&list->node.list, nr);
out:
	return nr;
}

xqindex xlist_add_tail(struct xlist *list, struct xlist_node *node)
{
	struct xlist_node *tail;
	xqindex nr = XPTRI(&list->node.list) + 1;

	if (nr == None)
		goto out;

	__xlist_detach(node);
	tail = XPTR(&node->tail);
	__xlist_attach(&list->node, tail, node);

	XPTRISET(&list->node.list, nr);
out:
	return nr;
}

struct xlist *xlist_detach(struct xlist_node *node)
{
	struct xlist *list = node->list;
	__xlist_detach(node);
	return list;
}

#endif
