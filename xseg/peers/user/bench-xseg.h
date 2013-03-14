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

#include <bench-lfsr.h>

/*
 * If CLOCK_MONOTONIC_RAW is not defined in our system, use CLOCK_MONOTONIC
 * instead. CLOCK_MONOTONIC_RAW is preferred since we are guaranteed that the
 * clock won't skew.
 */
#ifdef CLOCK_MONOTONIC_RAW
#define CLOCK_BENCH CLOCK_MONOTONIC_RAW
#else
#define CLOCK_BENCH CLOCK_MONOTONIC
#endif


#define MAX_ARG_LEN 10

/*
 * Pattern type occupies 1st flag bit.
 * If 1, it's sequential, if 0, it's random.
 */
#define PATTERN_FLAG_POS 0
#define PATTERN_BITMASK 1
#define PATTERN_SEQ 0
#define PATTERN_RAND 1

/*
 * Verify mode occupies 2nd and 3rd flag bit.
 * If 01, it uses metadata for verification, if 11 it writes pseudorandom nums
 * in chunk's memory range and if 00, it's off.
 */
#define VERIFY_FLAG_POS 1
#define VERIFY_BITMASK 3	/* i.e. "11" in binary form */
#define VERIFY_NO 0
#define	VERIFY_META 1
#define	VERIFY_FULL 2

/* Timer insanity occupies 4th and 5th flag bit */
#define INSANITY_FLAG_POS 3
#define INSANITY_BITMASK 3	/* i.e. "11" in binary form */
#define INSANITY_SANE 0
#define INSANITY_ECCENTRIC 1
#define INSANITY_MANIC 2
#define INSANITY_PARANOID 3


/*
 * Current bench flags representation:
 * 64 7  6  5  4  3  2  1 : bits
 * ...0  0  0  0  0  0  0
 *         |____||____||_|
 *			  ^	    ^   ^
 *			  |		|   |
 *		   insanity	| pattern
 *				 verify
 */
/* Add flag bit according to its position */
#define SET_FLAG(__ftype, __flag, __val)	\
	__flag |= __val << __ftype##_FLAG_POS;

/* Apply bitmask to flags, shift result to the right to get correct value */
#define GET_FLAG(__ftype, __flag)			\
	(__flag & (__ftype##_BITMASK << __ftype##_FLAG_POS)) >> __ftype##_FLAG_POS
/*
 * The benchark ID (IDLEN) is global for the test, calculated once and is a
 * string of the following form: {"bench-" + 9-digit number + "\0"}.
 * The target string (TARGETLEN) is per object, concatenated with the string
 * above and is of the following form: {"-" +16-digit number + "\0"}.
 */
#define IDLEN 16
#define TARGETLEN (IDLEN + 17)
extern char global_id[IDLEN];

struct bench {
	uint64_t to; //Total number of objects (not for read/write)
	uint64_t ts; //Total I/O size
	uint64_t os; //Object size
	uint64_t bs; //Block size
	uint32_t iodepth; //Num of in-flight xseg reqs
	xport dst_port;
	xport src_port;
	uint32_t op;	//xseg operation
	uint64_t flags;
	struct peerd *peer;
	struct req_status *status;
	struct bench_lfsr *lfsr;
	struct timer *total_tm; //Total time for benchmark
	struct timer *get_tm;	//Time for xseg_get_request
	struct timer *sub_tm;	//Time for xseg_submit_request
	struct timer *rec_tm;	//Time for xseg_receive_request
};

struct req_status {
	uint64_t max;		/* Max requests for benchmark */
	uint64_t submitted;
	uint64_t received;
	uint64_t corrupted;	/* Requests that did not pass verification */
	uint64_t failed;
};

/*
 * Custom timespec. Made to calculate variance, where we need the square of a
 * timespec struct. This struct should be more than enough to hold the square
 * of the biggest timespec.
 */
struct timespec2 {
	unsigned long tv_sec2;
	uint64_t tv_nsec2;
};

/*
 * struct timer fields
 * ====================
 * completed: number of completed requests
 * start_time: submission time of a request
 * sum: the sum of elapsed times of every completed request
 * sum_sq: the sum of the squares of elapsed times
 * insanity: benchmarking level, higher means that the request associated with
 *           this timer is more trivial.
 */
struct timer {
	struct timespec sum;
	struct timespec2 sum_sq;
	struct timespec start_time;
	uint64_t completed;
	int insanity;
};

struct tm_result {
	unsigned int s;
	unsigned int ms;
	unsigned int us;
	unsigned int ns;
};

struct signature {
	uint64_t id;
	uint64_t object;
	uint64_t offset;
};


int bench_peerd_loop(void *arg);

void timer_start(struct bench *prefs, struct timer *sample_req);
void timer_stop(struct bench *prefs, struct timer *sample_tm,
		struct timespec *start);
int init_timer(struct timer **tm, int insanity);
uint64_t str2num(char *str);
int read_op(char *op);
int read_pattern(char *pattern);
int read_insanity(char *insanity);
int read_verify(char *insanity);
void print_res(struct bench *prefs, struct timer *tm, char *type);
void print_stats(struct bench *prefs);
void create_target(struct bench *prefs, struct xseg_request *req,
		uint64_t new);
void create_chunk(struct bench *prefs, struct xseg_request *req, uint64_t new);
int read_chunk(struct bench *prefs, struct xseg_request *req);
uint64_t determine_next(struct bench *prefs);
uint64_t calculate_offset(struct bench *prefs, uint64_t new);
void create_id(unsigned long seed);

