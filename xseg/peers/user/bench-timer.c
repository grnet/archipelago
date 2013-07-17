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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <pthread.h>
#include <xseg/xseg.h>
#include <peer.h>
#include <time.h>
#include <sys/util.h>
#include <signal.h>
#include <bench-xseg.h>
#include <limits.h>

#define SEC 1000000000 //1sec = 10^9 nsec
#define SEC2 (uint64_t) SEC*SEC //1sec*1sec = 10^18 nsec^2

/*
 * Get elapsed time by subtracting start time from end time.
 * Subtraction can result to a negative value, so we check for both cases
 */
static inline void timespecsub(struct timespec *end,
		struct timespec *start, struct timespec *result)
{
	if (start->tv_nsec > end->tv_nsec) {
		result->tv_nsec = SEC - start->tv_nsec + end->tv_nsec;
		result->tv_sec = end->tv_sec - start->tv_sec - 1;
	} else {
		result->tv_nsec = end->tv_nsec - start->tv_nsec;
		result->tv_sec = end->tv_sec - start->tv_sec;
	}
}

static inline void timespecadd(struct timespec *a,
		struct timespec *b, struct timespec *result)
{
	if (a->tv_nsec + b->tv_nsec >= SEC) {
		result->tv_nsec = a->tv_nsec + b->tv_nsec - SEC;
		result->tv_sec = a->tv_sec + b->tv_sec + 1;
	} else {
		result->tv_nsec = a->tv_nsec + b->tv_nsec;
		result->tv_sec = a->tv_sec + b->tv_sec;
	}
}

int init_timer(struct timer **tm, int insanity)
{
	*tm = malloc(sizeof(struct timer));
	if (!*tm) {
		perror("malloc");
		return -1;
	}

	memset(*tm, 0, sizeof(struct timer));
	(*tm)->insanity = insanity;
	return 0;
}

void timer_start(struct bench *prefs, struct timer *timer)
{
	//We need a low-latency way to get current time in nanoseconds.
	//QUESTION: Is this way the best way?
	if (GET_FLAG(INSANITY, prefs->flags) < timer->insanity)
		return;

	clock_gettime(CLOCK_BENCH, &timer->start_time);
}

void timer_stop(struct bench *prefs, struct timer *timer,
		struct timespec *start_time)
{
	struct timespec end_time;

	if (GET_FLAG(INSANITY, prefs->flags) < timer->insanity)
		return;

	/*
	 * There are timers such as rec_tm whose start_time cannot be trusted
	 * and the submission time is stored in other structs (e.g. struct
	 * peer_request).
	 * In this case, the submission time must be passed explicitly to this
	 * function using the "start" argument.
	 */
	if (!start_time)
		start_time = &timer->start_time;

	clock_gettime(CLOCK_BENCH, &end_time);

	timespecsub(&end_time, start_time, &timer->elapsed_time);

	//Add the elapsed time to the current sum for this timer.
	//For accuracy, nanoseconds' sum has to be always less that 10^9
	timespecadd(&timer->elapsed_time, &timer->sum, &timer->sum);

#if 0
	struct timespec2 elapsed_time_sq;

	//Add elapsed_time^2 to the current sum of squares for this timer
	//This is needed to calculate standard deviation.
	//As above, the sum of square of nanoseconds has to be less than 10^18
	elapsed_time_sq.tv_sec2 = elapsed_time.tv_sec*elapsed_time.tv_sec;
	elapsed_time_sq.tv_nsec2 = elapsed_time.tv_nsec*elapsed_time.tv_nsec;
	if (elapsed_time_sq.tv_nsec2 + timer->sum_sq.tv_nsec2 > SEC2) {
		timer->sum_sq.tv_nsec2 =
			(timer->sum_sq.tv_nsec2 + elapsed_time_sq.tv_nsec2) % SEC2;
		timer->sum_sq.tv_sec2 += elapsed_time_sq.tv_sec2 + 1;
	} else {
		timer->sum_sq.tv_nsec2 += elapsed_time_sq.tv_nsec2;
		timer->sum_sq.tv_sec2 += elapsed_time_sq.tv_sec2;
	}
#endif
	//TODO: check if we need to make it volatile
	timer->completed++;

	/*
	printf("Start: %lu s %lu ns\n", start_time.tv_sec, start_time.tv_nsec);
	printf("Elpsd: %lu s %lu ns\n", elapsed_time.tv_sec, elapsed_time.tv_nsec);
	printf("End:   %lu s %lu ns\n", end_time.tv_sec, end_time.tv_nsec);
	*/
}




