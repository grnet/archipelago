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

#ifndef XPOOL_H
#define XPOOL_H

#include <sys/util.h>
#include <xtypes/xlock.h>

typedef uint64_t xpool_index;
typedef uint64_t xpool_data;
#define NoIndex ((xpool_index) -1)


struct xpool_node {
	xpool_data data;
	//XPTR_TYPE(struct xpool_node) next;
	//XPTR_TYPE(struct xpool_node) prev;
	xpool_index next;
	xpool_index prev;
};

struct xpool {
	struct xlock lock;
	//XPTR_TYPE(struct xpool_node) list;
	//XPTR_TYPE(struct xpool_node) free;
	xpool_index list;
	xpool_index free;
	uint64_t size;
	XPTR_TYPE(struct xpool_node) mem;
};

void xpool_init(struct xpool *xp, uint64_t size, struct xpool_node* mem);
void xpool_clear(struct xpool *xp, uint32_t who);
xpool_index xpool_add(struct xpool *xp, xpool_data data, uint32_t who);
xpool_index xpool_remove(struct xpool *xp, xpool_index idx, xpool_data *data, uint32_t who);
xpool_index xpool_peek(struct xpool *xp, xpool_data *data, uint32_t who);
xpool_index xpool_peek_idx(struct xpool *xp, xpool_index idx, xpool_data *data, uint32_t who);
xpool_index xpool_peek_and_fwd(struct xpool *xp, xpool_data *data, uint32_t who);
xpool_index xpool_set_idx(struct xpool *xp, xpool_index idx, xpool_data data, uint32_t who);

void __xpool_clear(struct xpool *xp);
xpool_index __xpool_add(struct xpool *xp, xpool_data data);
xpool_index __xpool_remove(struct xpool *xp, xpool_index idx, xpool_data *data);
xpool_index __xpool_peek(struct xpool *xp, xpool_data *data);
xpool_index __xpool_peek_idx(struct xpool *xp, xpool_index idx, xpool_data *data);
xpool_index __xpool_peek_and_fwd(struct xpool *xp, xpool_data *data);
xpool_index __xpool_set_idx(struct xpool *xp, xpool_index idx, xpool_data data);

#endif /* XPOOL_H */
