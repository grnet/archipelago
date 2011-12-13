#ifndef _XQ_H
#define _XQ_H

typedef unsigned int xqindex;

#define None (xqindex)-1

#include <sys/util.h>
#include "xq_lock.h"

struct xq {
        struct xq_lock lock;
        xqindex head, tail;
        xqindex *queue;
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

xqindex      xq_append_head  ( struct xq  * xq,
                               xqindex      xqi );

xqindex      xq_pop_head     ( struct xq  * xq  );

xqindex      xq_append_tail  ( struct xq  * xq,
                               xqindex      xqi );

xqindex      xq_pop_tail     ( struct xq  * xq  );

int          xq_head_to_tail ( struct xq  * hq,
                               struct xq  * tq,
                               xqindex      nr  );

xqindex      xq_size         ( struct xq  * xq  );

xqindex      xq_count        ( struct xq  * xq  );

void         xq_print        ( struct xq  * xq  );

#endif

