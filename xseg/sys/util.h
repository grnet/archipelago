#ifndef _XSEG_SYS_UTIL_H
#define _XSEG_SYS_UTIL_H

#include <_sysutil.h>
#include <sys/domain.h>

#define FMTARG(fmt, arg, format, ...) fmt format "%s", arg, ## __VA_ARGS__
#define XSEGLOG(...) (xseg_snprintf(__xseg_errbuf, 4096, FMTARG("%s: ", __func__, ## __VA_ARGS__, "")), \
                    __xseg_errbuf[4095] = 0, __xseg_log(__xseg_errbuf))

/* general purpose xflags */
#define X_ALLOC ((uint32_t) (1 << 0))
#define X_LOCAL ((uint32_t) (1 << 1))


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
