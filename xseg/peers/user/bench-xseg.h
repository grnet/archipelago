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

#define TM_SANE 0
#define TM_ECCENTRIC 1
#define TM_MANIC 2
#define TM_PARANOID 3

/*
 * Pattern type occupies first flag bit.
 * If 1, it's synchronous, if 0, it's random.
 */
#define PATTERN_FLAG 0
#define IO_SEQ 0 << PATTERN_FLAG
#define IO_RAND 1 << PATTERN_FLAG

/*
 * FIXME: The following are variables and definitions used to name objects and
 * seed the lfsr. They can be handled more elegantly (e.g. be a member of a
 * struct.)
 */
#define IDLEN 15
#define TARGETLEN (IDLEN + 17)
extern char global_id[IDLEN];
extern uint64_t global_seed;

struct bench {
	uint64_t to; //Total number of objects (not for read/write)
	uint64_t ts; //Total I/O size
	uint64_t os; //Object size
	uint64_t bs; //Block size
	uint64_t max_requests; //Max number of requests for a benchmark
	uint32_t iodepth; //Num of in-flight xseg reqs
	int insanity;
	xport dst_port;
	xport src_port;
	uint32_t op;	//xseg operation
	uint8_t flags;
	struct peerd *peer;
	struct lfsr *lfsr;
	struct timer *total_tm; //Total time for benchmark
	struct timer *get_tm;	//Time for xseg_get_request
	struct timer *sub_tm;	//Time for xseg_submit_request
	struct timer *rec_tm;	//Time for xseg_receive_request
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
	uint32_t completed;
	unsigned int insanity;
};

struct tm_result {
	unsigned long s;
	unsigned long ms;
	unsigned long us;
	unsigned long ns;
};

/* FILLME
struct signature {
	//target's name
	//οffset
	//hash of data (heavy)
};
*/


int custom_peerd_loop(void *arg);

void timer_start(struct bench *prefs, struct timer *sample_req);
void timer_stop(struct bench *prefs, struct timer *sample_tm,
		struct timespec *start);
int init_timer(struct timer **tm, int insanity);
uint64_t str2num(char *str);
int read_op(char *op);
int read_pattern(char *pattern);
void print_res(struct tm_result res, char *type);
void separate_by_order(struct timespec src, struct tm_result *res);
void create_target(struct bench *prefs, struct xseg_request *req,
		uint64_t new);
void create_chunk(struct bench *prefs, struct xseg_request *req,
		uint64_t new);
uint64_t determine_next(struct bench *prefs);
void create_id();
int read_insanity(char *insanity);

/**************\
 * LFSR stuff *
\**************/

struct lfsr {
	uint8_t length;
	uint64_t limit;
	uint64_t state;
	uint64_t xnormask;
};

int lfsr_init(struct lfsr *lfsr, uint64_t size, uint64_t seed);

/*
 * This loop generates each time a new pseudo-random number. However, if it's
 * bigger than what we want, we discard it and generate the next one.
 */
static inline uint64_t lfsr_next(struct lfsr *lfsr)
{
	do {
		lfsr->state = (lfsr->state >> 1) ^
			(((lfsr->state & 1UL) - 1UL) & lfsr->xnormask);
	} while (lfsr->state > lfsr->limit);

	return lfsr->state;
}

