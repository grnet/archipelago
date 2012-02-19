#ifndef XSEG_UTIL_H
#define XSEG_UTIL_H

#ifdef __KERNEL__

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>

#else

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#endif

void __xseg_log(const char *msg);
extern char __xseg_errbuf[4096];
extern int (*xseg_snprintf)(char *str, size_t size, const char *format, ...);
void *xq_malloc(unsigned long size);
void xq_mfree(void *ptr);

#define FMTARG(fmt, arg, format, ...) fmt format "%s", arg, ## __VA_ARGS__
#define LOGMSG(...) xseg_snprintf(__xseg_errbuf, 4096, FMTARG("%s: ", __func__, ## __VA_ARGS__, "")), \
                    __xseg_errbuf[4095] = 0, __xseg_log(__xseg_errbuf)

typedef uint64_t xpointer;

#define None ((xqindex)-1)
#define Null ((xpointer)-1)


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

#endif
