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
#endif

