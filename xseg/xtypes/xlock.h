#ifndef _XLOCK_H
#define _XLOCK_H

#include <sys/util.h>

#define MFENCE() __sync_synchronize()
#define BARRIER() __asm__ __volatile__ ("" ::: "memory")
#define __pause() __asm__ __volatile__ ("pause\n");
#undef __pause
#define __pause()

#define Noone ((unsigned long)-1)
#define MAX_VALID_OWNER 65536 /* we are not gonna have more ports than that */

struct xlock {
	unsigned long owner;
} __attribute__ ((aligned (16))); /* support up to 128bit longs */

static inline unsigned long xlock_acquire(struct xlock *lock, unsigned long who)
{
	unsigned long owner;
	unsigned long times = 1;
	for (;;) {
		for (owner = *(volatile unsigned long *)(&lock->owner); ; owner = *(volatile unsigned long *)(&lock->owner)){
			if (owner == Noone)
				break;
			if (owner > MAX_VALID_OWNER){
				XSEGLOG("xlock %lx corrupted. Lock owner %lu",
						(unsigned long) lock, owner);
				XSEGLOG("Resetting xlock %lx to Noone", 
						(unsigned long) lock);
				lock->owner = Noone;
			}
			if (!(times & ((1<<20) -1))){
				XSEGLOG("xlock %lx spinned for %llu times"
					"\n\t who: %lu, owner: %lu",
					(unsigned long) lock, times,
					who, owner);
//				xseg_printtrace();
			}
			times++;
			__pause();
		}

		if (__sync_bool_compare_and_swap(&lock->owner, Noone, who))
			break;
	}
	if (lock->owner > MAX_VALID_OWNER){
		XSEGLOG("xlock %lx locked with INVALID lock owner %lu",
				(unsigned long) lock, lock->owner);
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
