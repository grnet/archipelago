#ifndef _XSEG_SYS_UTIL_H
#define _XSEG_SYS_UTIL_H

#include <_sysutil.h>
#include <sys/domain.h>

/* log stuff */



#define FMTARG(fmt, arg, format, ...) fmt format "%s", arg, ## __VA_ARGS__
#define XSEGLOG(...) (xseg_snprintf(__xseg_errbuf, 4096, FMTARG("%s: ", __func__, ## __VA_ARGS__, "")), \
                    __xseg_errbuf[4095] = 0, __xseg_log(__xseg_errbuf))

#define XSEGLOG2(__ctx, __level, ...) 		\
		do { 				\
			if (__level <= ((__ctx)->log_level)) { \
				__xseg_log2(__ctx, __level, FMTARG("%s: ", __func__, ## __VA_ARGS__ ,"")); \
			}	\
		} while(0)

/*
void log_request(struct log_context *lc, struct xseg *xseg,  struct xseg_request *req)
{
	__xseg_log2(lc, I, "\n\t"
	"Request %lx: target[%u](xptr: %llu): %s, data[%llu](xptr: %llu): %s \n\t"
	"offset: %llu, size: %llu, serviced; %llu, op: %u, state: %u, flags: %u \n\t"
	"src: %u, src_transit: %u, dst: %u, dst_transit: %u",
	(unsigned long) req, req->targetlen, (unsigned long long)req->target,
	xseg_get_target(xseg, req),
	(unsigned long long) req->datalen, (unsigned long long) req->data,
	xseg_get_data(xseg, req),
	(unsigned long long) req->offset, (unsigned long long) req->size,
	(unsigned long long) req->serviced, req->op, req->state, req->flags,
	(unsigned int) req->src_portno, (unsigned int) req->src_transit_portno,
	(unsigned int) req->dst_portno, (unsigned int) req->dst_transit_portno);
}
*/

/* general purpose xflags */
#define X_ALLOC    ((uint32_t) (1 << 0))
#define X_LOCAL    ((uint32_t) (1 << 1))
#define X_NONBLOCK ((uint32_t) (1 << 2))


typedef uint64_t xpointer;

/* type to be used as absolute pointer
 * this should be the same as xqindex
 * and must fit into a pointer type
 */
typedef uint64_t xptr; 

#define Noneidx ((xqindex)-1)
#define Null ((xpointer)-1)

#define __align(x, shift) (((((x) -1) >> (shift)) +1) << (shift))

#define XPTR_TYPE(ptrtype)	\
	union {			\
		ptrtype *t;	\
		xpointer x;	\
	}

#define XPTRI(xptraddr)		\
	(	(xpointer)(unsigned long)(xptraddr) +	\
		(xptraddr)->x				)

#define XPTRISET(xptraddr, ptrval)	\
	((xptraddr)->x	=	(xpointer)(ptrval) -			\
				(xpointer)(unsigned long)(xptraddr)	)

#define XPTR(xptraddr)		\
	(	(typeof((xptraddr)->t))				\
		(unsigned long)					\
		(	(xpointer)(unsigned long)(xptraddr) +	\
			(xptraddr)->x		)		)

#define XPTRSET(xptraddr, ptrval)	\
	((xptraddr)->x	=	(xpointer)(unsigned long)(ptrval) -	\
				(xpointer)(unsigned long)(xptraddr)	)



#define XPTR_OFFSET(base, ptr) ((unsigned long)(ptr) - (unsigned long)(base))

#define XPTR_MAKE(ptrval, base) ((xptr) XPTR_OFFSET(base, ptrval))

#define XPTR_TAKE(xptrval, base)	\
	( (void *) ( (unsigned long) base + (unsigned long) xptrval))

#endif
