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

#ifndef _XQ_H
#define _XQ_H

#include <sys/util.h>

typedef uint64_t xqindex;

#include "xlock.h"

struct xq {
        struct xlock lock;
        xqindex head, tail;
        XPTR_TYPE(xqindex) queue;
        xqindex size;
};

xqindex    * xq_alloc_empty  ( struct xq  * xq,
                               xqindex      size );

void         xq_init_empty   ( struct xq  * xq,
                               xqindex      size,
                               void       * mem );

xqindex    * xq_alloc_map    ( struct xq  * xq,
                               xqindex      size,
                               xqindex      count,
                               xqindex   (* mapfn ) (xqindex) );

void         xq_init_map     ( struct xq  * xq,
                               xqindex      size,
                               xqindex      count,
                               xqindex   (* mapfn ) (xqindex),
                               void       * mem );

xqindex    * xq_alloc_seq    ( struct xq  * xq,
                               xqindex      size,
                               xqindex      count );

void         xq_init_seq     ( struct xq  * xq,
                               xqindex      size,
                               xqindex      count,
                               void       * mem );

void         xq_free         ( struct xq  * xq  );

xqindex      __xq_append_head( struct xq  * xq,
                               xqindex      xqi );

xqindex      xq_append_head  ( struct xq  * xq,
                               xqindex      xqi,
			       unsigned long who);

xqindex      __xq_pop_head   ( struct xq  * xq  );
xqindex      xq_pop_head     ( struct xq  * xq,
			       unsigned long who);

xqindex      __xq_append_tail( struct xq  * xq,
                               xqindex      xqi );

xqindex      xq_append_tail  ( struct xq  * xq,
                               xqindex      xqi,
			       unsigned long who);


xqindex      __xq_peek_head    ( struct xq  * xq);

xqindex      xq_peek_head    ( struct xq  * xq,
			       unsigned long who);

xqindex      __xq_peek_tail    ( struct xq  * xq);

xqindex      xq_peek_tail    ( struct xq  * xq,
			       unsigned long who);

xqindex      __xq_pop_tail   ( struct xq  * xq  );

xqindex      xq_pop_tail     ( struct xq  * xq,
			       unsigned long who);

int          xq_head_to_tail ( struct xq  * hq,
                               struct xq  * tq,
                               xqindex      nr ,
			       unsigned long who);

xqindex      xq_size         ( struct xq  * xq  );

xqindex      xq_count        ( struct xq  * xq  );

void         xq_print        ( struct xq  * xq  );

int 	     __xq_check      ( struct xq  * xq, 
		               xqindex      idx );

int 	     xq_check        ( struct xq  * xq, 
		               xqindex      idx,
			       unsigned long who );

xqindex      __xq_resize     ( struct xq  * xq,
		               struct xq  * newxq);

xqindex      xq_resize       ( struct xq  * xq,
		               struct xq  * newxq,
	                       unsigned long who );
#endif

