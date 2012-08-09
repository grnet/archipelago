#ifndef _XQ_LOCK_H
#define _XQ_LOCK_H

#define MFENCE() __sync_synchronize()
#define BARRIER() __asm__ __volatile__ ("" ::: "memory")
#define __pause() __asm__ __volatile__ ("pause\n");
#undef __pause
#define __pause()

#define Noone ((unsigned long)-1)

struct xq_lock {
	long owner;
} __attribute__ ((aligned (16))); /* support up to 128bit longs */

static inline unsigned long xq_acquire(struct xq_lock *lock, unsigned long who)
{
	for (;;) {
		for (; *(volatile unsigned long *)(&lock->owner) != Noone; )
			__pause();

		if (__sync_bool_compare_and_swap(&lock->owner, Noone, who))
			break;
	}

	return who;
}

static inline void xq_release(struct xq_lock *lock)
{
	lock->owner = Noone;
}

static inline unsigned long xq_get_owner(struct xq_lock *lock)
{
	return *(volatile unsigned long *)(&lock->owner);
}

#endif
