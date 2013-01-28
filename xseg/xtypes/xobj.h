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

#ifndef __XOBJ_H__
#define __XOBJ_H__

#include <sys/util.h>
#include <xtypes/xlock.h>
#include <xtypes/xheap.h>
#include <xtypes/domain.h>
#include <xtypes/xhash.h>

struct xobject_header {
	XPTR_TYPE(struct xseg_object_handler) obj_h;
};

struct xobject {
	uint32_t magic;
	uint64_t size;
	xptr next;
};

struct xobject_h {
	struct xlock lock;
	uint32_t magic;
	uint64_t obj_size;
	uint32_t flags;
	XPTR_TYPE(void) container;
	xptr heap;
	xptr allocated;
	uint64_t nr_allocated;
	uint64_t allocated_space;
	xptr list;
	uint64_t nr_free;
};

struct xobject_iter {
	struct xobject_h *obj_h;
	xhash_iter_t xhash_it;
	void *chunk;
	xhashidx cnt;
};

void *xobj_get_obj(struct xobject_h * obj_h, uint32_t flags);
void xobj_put_obj(struct xobject_h * obj_h, void *ptr);
int xobj_alloc_obj(struct xobject_h * obj_h, uint64_t nr);
int xobj_handler_init(struct xobject_h *obj_h, void *container,
		uint32_t magic,	uint64_t size, struct xheap *heap);

void xobj_iter_init(struct xobject_h *obj_h, struct xobject_iter *it);
int xobj_iterate(struct xobject_h *obj_h, struct xobject_iter *it, void **obj);
int xobj_check(struct xobject_h *obj_h, void *obj);
int xobj_isFree(struct xobject_h *obj_h, void *obj);

int __xobj_check(struct xobject_h *obj_h, void *obj);
int __xobj_isFree(struct xobject_h *obj_h, void *obj);

//TODO 
//xobj_handler_destroy()
//releases allocated pages
//
//maybe we need lock free versions of get/put obj
//
//also an
//unsigned long xobj_get_objs(obj_h, flags, uint64_t nr, void **buf)
//which will put nr objects in buf
#endif
