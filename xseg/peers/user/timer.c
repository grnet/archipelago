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

void timer_start(struct timer *timer)
{
	//We need a low-latency way to get current time in nanoseconds.
	//Is this way the best way?
	clock_gettime(CLOCK_MONOTONIC, &timer->start_time);
}

void timer_stop(struct timer *timer)
{
	struct timespec end_time;
	struct timespec start_time = timer->start_time;
	struct timespec elapsed_time;
	struct timespec2 elapsed_time_sq;

	clock_gettime(CLOCK_MONOTONIC, &end_time);

	//Get elapsed time by subtracting start time from end time.
	//Also, be very cautious with negative values
	if (start_time.tv_nsec > end_time.tv_nsec) {
		//UGLY: Is there a better way to handle carrying?
		elapsed_time.tv_nsec = (volatile long)
			LONG_MAX - start_time.tv_nsec + end_time.tv_nsec + 1;
		elapsed_time.tv_sec = end_time.tv_sec - start_time.tv_sec - 1;
	} else {
		elapsed_time.tv_nsec = end_time.tv_nsec - start_time.tv_nsec;
		elapsed_time.tv_sec = end_time.tv_sec - start_time.tv_sec;
	}

	//Add the elapsed time to the current sum for this timer
	if (LONG_MAX - elapsed_time.tv_nsec < timer->sum.tv_nsec){
		//UGLY: Is there a better way to handle overflows?
		timer->sum.tv_nsec += elapsed_time.tv_nsec;
		timer->sum.tv_sec += elapsed_time.tv_sec + 1;
	} else {
		timer->sum.tv_nsec += elapsed_time.tv_nsec;
		timer->sum.tv_sec += elapsed_time.tv_sec;
	}

	//Add elapsed_time^2 to the current sum of squares for this timer
	//Needed to calculate standard deviation.
	elapsed_time_sq.tv_sec2 = elapsed_time.tv_sec*elapsed_time.tv_sec;
	elapsed_time_sq.tv_nsec2 = elapsed_time.tv_nsec*elapsed_time.tv_nsec;
	if (UINT64_MAX - elapsed_time_sq.tv_nsec2 < timer->sum_sq.tv_nsec2) {
		//UGLY: Is there a better way to handle overflows?
		timer->sum_sq.tv_nsec2 += elapsed_time_sq.tv_nsec2;
		timer->sum_sq.tv_sec2 += elapsed_time_sq.tv_sec2 + 1;
	} else {
		timer->sum_sq.tv_nsec2 += elapsed_time_sq.tv_nsec2;
		timer->sum_sq.tv_sec2 += elapsed_time_sq.tv_sec2;
	}

	//TODO: check if we need to make it volatile
	timer->completed++;
}




