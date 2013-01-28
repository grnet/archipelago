/*
 * Copyright 2012 GRNET S.A. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 *   1. Redistributions of source code must retain the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer.
 *   2. Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials
 *      provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY GRNET S.A. ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL GRNET S.A OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and
 * documentation are those of the authors and should not be
 * interpreted as representing official policies, either expressed
 * or implied, of GRNET S.A.
 */

#ifndef _XLOCK_H
#define _XLOCK_H

#include <sys/util.h>

#define MFENCE() __sync_synchronize()
#define BARRIER() __asm__ __volatile__ ("" ::: "memory")
#define __pause() __asm__ __volatile__ ("pause\n");
#undef __pause
#define __pause()

#define Noone ((unsigned long)-1)

#define XLOCK_SANITY_CHECKS
#define XLOCK_CONGESTION_NOTIFY

#ifdef XLOCK_SANITY_CHECKS
#define MAX_VALID_OWNER 65536 /* we are not gonna have more ports than that */
#endif /* XLOCK_SANITY_CHECKS */

#ifdef XLOCK_CONGESTION_NOTIFY
#define MIN_SHIFT 20
#define MAX_SHIFT ((sizeof(unsigned long) * 8) -1)
#endif /* XLOCK_CONGESTION_NOTIFY */

struct xlock {
	unsigned long owner;
};
//} __attribute__ ((aligned (16))); /* support up to 128bit longs */

static inline unsigned long xlock_acquire(struct xlock *lock, unsigned long who)
{
	unsigned long owner;
#ifdef XLOCK_CONGESTION_NOTIFY
	unsigned long times = 1;
	unsigned long shift = MIN_SHIFT;
#endif /* XLOCK_CONGESTION_NOTIFY */

	for (;;) {
		for (; (owner = *(volatile unsigned long *)(&lock->owner) != Noone);){
#ifdef XLOCK_SANITY_CHECKS
			if (owner > MAX_VALID_OWNER){
				XSEGLOG("xlock %lx corrupted. Lock owner %lu",
						(unsigned long) lock, owner);
				XSEGLOG("Resetting xlock %lx to Noone", 
						(unsigned long) lock);
				lock->owner = Noone;
			}
#endif /* XLOCK_SANITY_CHECKS */
#ifdef XLOCK_CONGESTION_NOTIFY
			if (!(times & ((1<<shift) -1))){
				XSEGLOG("xlock %lx spinned for %llu times"
					"\n\t who: %lu, owner: %lu",
					(unsigned long) lock, times,
					who, owner);
				if (shift < MAX_SHIFT)
					shift++;
//				xseg_printtrace();
			}
			times++;
#endif /* XLOCK_CONGESTION_NOTIFY */
			__pause();
		}

		if (__sync_bool_compare_and_swap(&lock->owner, Noone, who))
			break;
	}
#ifdef XLOCK_SANITY_CHECKS
	if (lock->owner > MAX_VALID_OWNER){
		XSEGLOG("xlock %lx locked with INVALID lock owner %lu",
				(unsigned long) lock, lock->owner);
	}
#endif /* XLOCK_SANITY_CHECKS */

	return who;
}

static inline unsigned long xlock_try_lock(struct xlock *lock, unsigned long who)
{
	return __sync_bool_compare_and_swap(&lock->owner, Noone, who);
}

static inline void xlock_release(struct xlock *lock)
{
	BARRIER();
	/*
#ifdef XLOCK_SANITY_CHECKS
	if (lock->owner > MAX_VALID_OWNER){
		XSEGLOG("xlock %lx releasing lock with INVALID lock owner %lu",
				(unsigned long) lock, lock->owner);
	}
#endif 
	*/
	/* XLOCK_SANITY_CHECKS */
	lock->owner = Noone;
}

static inline unsigned long xlock_get_owner(struct xlock *lock)
{
	return *(volatile unsigned long *)(&lock->owner);
}

#endif
