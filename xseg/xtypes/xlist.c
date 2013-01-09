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

	if (nr == Noneidx)
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

	if (nr == Noneidx)
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
