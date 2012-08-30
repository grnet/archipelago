#ifndef _XLOCK_H
#define _XLOCK_H

#define MFENCE() __sync_synchronize()
#define BARRIER() __asm__ __volatile__ ("" ::: "memory")
#define __pause() __asm__ __volatile__ ("pause\n");
#undef __pause
#define __pause()

#define Noone ((unsigned long)-1)

struct xlock {
	long owner;
} __attribute__ ((aligned (16))); /* support up to 128bit longs */

static inline unsigned long xlock_acquire(struct xlock *lock, unsigned long who)
{
	for (;;) {
		for (; *(volatile unsigned long *)(&lock->owner) != Noone; )
			__pause();

		if (__sync_bool_compare_and_swap(&lock->owner, Noone, who))
			break;
	}

	return who;
}

static inline unsigned long xlock_try_lock(struct xlock *lock, unsigned long who)
{
	return __sync_bool_compare_and_swap(&lock->owner, Noone, who);
}

static inline void xlock_release(struct xlock *lock)
{
	BARRIER();
	lock->owner = Noone;
}

static inline unsigned long xlock_get_owner(struct xlock *lock)
{
	return *(volatile unsigned long *)(&lock->owner);
}

#endif
