#ifndef _XATOMIC_H
#define _XATOMIC_H

#include <stdint.h>

typedef struct xatomic {
	__uint128_t value;
} xatomic;

#define MAX64	(0xffffffffffffffffUL)
#define MAX128	(~(__uint128_t)0)
#define Z128	((__uint128_t)0)
#define U128	((__uint128_t)1)

#define declare_cas(at, var)						\
	uint64_t var, __xatomic_val_##var;				\
	__uint128_t __xatomic_serial_##var;				\
	xatomic *__xatomic_##var = (at)

#define cas_read(var)							\
	__xatomic_##var##_restart:					\
	__xatomic_serial_##var = ((__xatomic_##var)->value >> 64);	\
	var = __xatomic_val_##var =					\
		((__xatomic_##var)->value & (0xffffffffffffffffUL)

#define cas_begin(at, var)				\
	uint64_t var, __xatomic_val_##var;		\
	xatomic *__xatomic_##var = (at);		\
	__xatomic_##var##_restart:			\
	var = __xatomic_val_##var = (__xatomic_##var)->value

#define cas_update(var)				\
	__sync_bool_compare_and_swap	(	\
		&(__xatomic_##var)->value,	\
		__xatomic_val_##var,		\
		var				\
	)

#define cas_restart(var)	\
	goto __xatomic_##var##_restart


static inline uint64_t xatomic_read(xatomic *atomic)
{
	return (uint64_t)atomic->value;
}

static inline void xatomic_write(xatomic *atomic, uint64_t newval)
{
	cas_begin(atomic, val);
	val = newval;
	if (!cas_update(val))
		cas_restart(val);
}

static inline uint64_t xatomic_inc(xatomic *atomic, uint64_t inc)
{
	uint64_t retval;

	cas_begin(atomic, val);
	retval = val;
	val += inc;
	if (!cas_update(val))
		cas_restart(val);

	return retval;
}

static inline uint64_t xatomic_dec(xatomic *atomic, uint64_t dec)
{
	uint64_t retval;

	cas_begin(atomic, val);
	retval = val;
	val -= dec;
	if (!cas_update(val))
		cas_restart(val);

	return retval;
}

#endif
