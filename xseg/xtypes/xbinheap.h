/*
 * Copyright 2013 GRNET S.A. All rights reserved.
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


#ifndef __XBINHEAP_H
#define __XBINHEAP_H

#include <xtypes/domain.h>
#include <sys/util.h>

typedef uint64_t xbinheapidx;
typedef xbinheapidx xbinheap_handler;
#define NoNode (xbinheapidx)-1
#define XBINHEAP_MAX (uint32_t)(1<<0)
#define XBINHEAP_MIN (uint32_t)(1<<1)

struct xbinheap_node {
	xbinheapidx key;
	xbinheapidx value;
	xbinheapidx h;
};

struct xbinheap {
	xbinheapidx size;
	xbinheapidx count;
	uint32_t flags;
	xbinheapidx *indexes;
	struct xbinheap_node *nodes;
};

xbinheap_handler xbinheap_insert(struct xbinheap *h, xbinheapidx key,
		xbinheapidx value);
int xbinheap_empty(struct xbinheap *h);
xbinheapidx xbinheap_peak(struct xbinheap *h);
xbinheapidx xbinheap_extract(struct xbinheap *h);
int xbinheap_increasekey(struct xbinheap *h, xbinheap_handler idx,
		xbinheapidx newkey);
int xbinheap_decreasekey(struct xbinheap *h, xbinheap_handler idx,
		xbinheapidx newkey);
xbinheapidx xbinheap_getkey(struct xbinheap *h, xbinheap_handler idx);
int xbinheap_init(struct xbinheap *h, xbinheapidx size, uint32_t flags, void *mem);
void xbinheap_free(struct xbinheap *h);

#endif /* __XBINHEAP_H */
