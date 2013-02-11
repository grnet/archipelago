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

#define MAX_ARG_LEN 10

struct bench {
	uint64_t ts; //Total I/O size
	uint64_t os; //Object size
	uint64_t bs; //Block size
	uint32_t iodepth; //Num of in-flight xseg reqs
	xport dst_port;
	xport src_port;
	uint8_t flags;
	struct timer *total_tm;
	struct timer *get_tm;
	struct timer *sub_tm;
	struct timer *rec_tm;
};

/*
 * Custom timespec. Made to calculate variance, where we need the square of a
 * timespec structure. This structure should be more than enough to hold the
 * square of the biggest timespec.
 */
struct timespec2 {
	unsigned long tv_sec2;
	uint64_t tv_nsec2;
};

struct timer {
	struct timespec sum;
	struct timespec2 sum_sq;
	double mean;
	double std;
	struct timespec start_time;
	unsigned long completed;
};

int custom_peerd_loop(void *arg);

void timer_start(struct timer *sample_req);
void timer_stop(struct timer *sample_tm);


