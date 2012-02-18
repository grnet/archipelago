#ifndef _XQ_LOCK_H
#define _XQ_LOCK_H

#define MFENCE() __sync_synchronize()
#define BARRIER() __asm__ __volatile__ ("" : "memory")
#define __pause() __asm__ __volatile__ ("pause\n");
#undef __pause
#define __pause()

struct xq_lock {
	long lock;
	unsigned long serial;
} __attribute__ ((aligned (32))); /* support up to 128bit longs */

static inline unsigned long xq_acquire(struct xq_lock *lock, unsigned long nr)
{
	unsigned long __serial;
	for (;;) {
		for (; *(volatile unsigned long *)(&lock->lock); )
			__pause();

		if (!__sync_fetch_and_sub(&lock->lock, 1))
			break;
	}

	__serial = lock->serial;
	lock->serial += nr;
	return __serial;
}

static inline void xq_release(struct xq_lock *lock)
{
	lock->lock = 0L;
}

#endif
