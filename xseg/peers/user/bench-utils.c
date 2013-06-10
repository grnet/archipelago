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

#define _GNU_SOURCE
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

#include <math.h>
#include <string.h>

#define PRINT_SIG(__who, __sig)						\
	fprintf(stdout, "%s (%lu): id %lu, object %lu, offset %lu\n",	\
			#__who, (uint64_t)(__sig),			\
			((struct signature *)__sig)->id,		\
			((struct signature *)__sig)->object,		\
			((struct signature *)__sig)->offset);

struct timespec delay = {0, 4000000};

/******************************\
 * Static miscellaneous tools *
\******************************/
static inline uint64_t __get_id()
{
	return atol(global_id + 6); /* cut the "bench-" part*/
}

static inline uint64_t __get_object_from_name(char *name)
{
	return atol(name + IDLEN + 1); /* cut the "bench-908135-" part*/
}

static inline uint64_t __get_object(struct bench *prefs, uint64_t new)
{
	if (prefs->ts > 0)
		new = new / (prefs->os / prefs->bs);
	return new;
}

static inline int __snap_to_bound8(uint64_t space)
{
	return space > 8 ? 8 : space;
}

static inline double __timespec2double(struct timespec num)
{
	return (double) (num.tv_sec * pow(10, 9) + num.tv_nsec);
}

static inline void __write_sig(struct bench_lfsr *sg, uint64_t *d, uint64_t s,
		int pos)
{
	uint64_t i;
	uint64_t last_val;
	uint64_t space_left;

	/* Write random numbers (based on global_id) every 24 bytes */
	/* TODO: Should we use memcpy? */
	for (i = pos; i < (s / 8) - (3 - pos); i += 3)
		*(d + i) = lfsr_next(sg);

	/* special care for last chunk */
	last_val = lfsr_next(sg);
	space_left = s - (i * 8);
	memcpy(d + i, &last_val, __snap_to_bound8(space_left));
}

static inline int __read_sig(struct bench_lfsr *sg, uint64_t *d, uint64_t s,
		int pos)
{
	uint64_t i;
	uint64_t last_val;
	uint64_t space_left;

	/* TODO: Should we use memcmp? */
	for (i = pos; i < (s / 8) - (3 - pos); i += 3) {
		if (*(d + i) != lfsr_next(sg))
			return 1;
	}
	/* special care for last chunk */
	last_val = lfsr_next(sg);
	space_left = s - (i * 8);
	if (memcmp(d + i, &last_val, __snap_to_bound8(space_left)))
		return 1;

	return 0;
}

/*
 * Seperates a double number in seconds, msec, usec, nsec
 * Expects a number in nanoseconds (e.g. a number from timespec2double)
 */
static struct tm_result __separate_by_order(double num)
{
	struct tm_result res;

	//The format we expect is the following:
	//
	//		|-s-|-ms-|-us-|-ns|
	//num =	 123 456  789  012 . 000000000000
	res.s = num / pow(10,9);
	num = fmod(num, pow(10,9));
	res.ms = num / pow(10,6);
	num = fmod(num, pow(10,6));
	res.us = num / 1000;
	res.ns = fmod(num, 1000);

	return res;
}

static void __calculate_bw(struct bench *prefs, double iops, struct bw *bw)
{
	bw->val = iops * prefs->bs;
	strcpy(bw->unit, "B/s");

	if (bw->val < 1024)
		return;

	bw->val = bw->val / 1024;
	strcpy(bw->unit, "KB/s");

	if (bw->val < 1024)
		return;

	bw->val = bw->val / 1024;
	strcpy(bw->unit, "MB/s");

	if (bw->val < 1024)
		return;

	bw->val = bw->val / 1024;
	strcpy(bw->unit, "GB/s");
}

static double __calculate_iops(struct bench *prefs, double elapsed_ns)
{
	/* elapsed_ns is in nanoseconds, so we convert it to seconds */
	double elapsed = elapsed_ns / pow(10,9);
	return (prefs->status->received / elapsed);
}

/******************************\
 * Argument-parsing functions *
\******************************/

/*
 * Convert string to size in bytes.
 * If syntax is invalid, return 0. Values such as zero and non-integer
 * multiples of segment's page size should not be accepted.
 */
uint64_t str2num(char *str)
{
	char *unit;
	uint64_t num;

	num = strtoll(str, &unit, 10);
	if (strlen(unit) > 1) //Invalid syntax
		return 0;
	else if (strlen(unit) < 1) //Plain number in bytes
		return num;

	switch (*unit) {
		case 'g':
		case 'G':
			num *= 1024;
		case 'm':
		case 'M':
			num *= 1024;
		case 'k':
		case 'K':
			num *= 1024;
			break;
		default:
			num = 0;
	}
	return num;
}

/*
 * Converts struct timespec to double (units in nanoseconds)
 */
int read_insanity(char *insanity)
{
	if (strncmp(insanity, "sane", MAX_ARG_LEN + 1) == 0)
		return INSANITY_SANE;
	if (strncmp(insanity, "eccentric", MAX_ARG_LEN + 1) == 0)
		return INSANITY_ECCENTRIC;
	if (strncmp(insanity, "manic", MAX_ARG_LEN + 1) == 0)
		return INSANITY_MANIC;
	if (strncmp(insanity, "paranoid", MAX_ARG_LEN + 1) == 0)
		return INSANITY_PARANOID;
	return -1;
}

int read_op(char *op)
{
	if (strncmp(op, "read", MAX_ARG_LEN + 1) == 0)
		return X_READ;
	if (strncmp(op, "write", MAX_ARG_LEN + 1) == 0)
		return X_WRITE;
	if (strncmp(op, "info", MAX_ARG_LEN + 1) == 0)
		return X_INFO;
	if (strncmp(op, "delete", MAX_ARG_LEN + 1) == 0)
		return X_DELETE;
	return -1;
}

int read_verify(char *verify)
{
	if (strncmp(verify, "no", MAX_ARG_LEN + 1) == 0)
		return VERIFY_NO;
	if (strncmp(verify, "meta", MAX_ARG_LEN + 1) == 0)
		return VERIFY_META;
	if (strncmp(verify, "full", MAX_ARG_LEN + 1) == 0)
		return VERIFY_FULL;
	return -1;
}

int read_progress(char *progress)
{
	if (strncmp(progress, "no", MAX_ARG_LEN + 1) == 0)
		return PROGRESS_NO;
	if (strncmp(progress, "yes", MAX_ARG_LEN + 1) == 0)
		return PROGRESS_YES;
	return -1;
}

int read_ping(char *ping)
{
	if (strncmp(ping, "no", MAX_ARG_LEN + 1) == 0)
		return PING_MODE_OFF;
	if (strncmp(ping, "yes", MAX_ARG_LEN + 1) == 0)
		return PING_MODE_ON;
	return -1;
}

int read_pattern(char *pattern)
{
	if (strncmp(pattern, "seq", MAX_ARG_LEN + 1) == 0)
		return PATTERN_SEQ;
	if (strncmp(pattern, "rand", MAX_ARG_LEN + 1) == 0)
		return PATTERN_RAND;
	return -1;
}

/*******************\
 * Print functions *
\*******************/

void print_io_stats(struct bench *prefs, double elapsed)
{
	struct bw bw;
	double iops;

	/*
	 * We could malloc struct bw in __calculate_bw, but it's safer in cases when
	 * there is no memory left.
	 */
	iops = __calculate_iops(prefs, elapsed);
	__calculate_bw(prefs, iops, &bw);

	fprintf(stdout, "           ~~~~~~~~~~~~~~~~~~~~~~~~\n");
	if (prefs->op == X_READ || prefs->op == X_WRITE)
		fprintf(stdout, "Bandwidth:    %.3lf %s\n", bw.val, bw.unit);
	fprintf(stdout, "IOPS:         %.3lf\n", iops);
}

void print_stats(struct bench *prefs)
{
	fprintf(stdout, "\n"
			"Requests total:     %10lu\n"
			"Requests submitted: %10lu\n"
			"Requests received:  %10lu\n"
			"Requests failed:    %10lu\n",
			prefs->status->max,
			prefs->status->submitted,
			prefs->status->received,
			prefs->status->failed);
	if ((prefs->op == X_READ) && (GET_FLAG(VERIFY, prefs->flags) != VERIFY_NO))
		fprintf(stdout, "Requests corrupted: %10lu\n", prefs->status->corrupted);
	fprintf(stdout, "\n");
	fflush(stdout);
}

void print_remaining(struct bench *prefs)
{
	uint64_t remaining;

	remaining = prefs->status->max - prefs->status->received;
	if (remaining)
		fprintf(stdout, "Requests remaining: %10lu\n", remaining);
	else
		fprintf(stdout, "All requests have been served.\n");
	fflush(stdout);
}

void print_res(struct bench *prefs)
{
	struct timer *tm;
	struct tm_result res, res_rec;
	double sum, sum_rec;

	/*  */
	tm = prefs->total_tm;
	sum = __timespec2double(tm->sum);
	res = __separate_by_order(sum);

	fprintf(stdout, "\n");
	fprintf(stdout, "              Benchmark results\n");
	fprintf(stdout, "           ========================\n");
	fprintf(stdout, "             |-s-||-ms-|-us-|-ns-|\n");
	fprintf(stdout, "Total time:   %3u. %03u  %03u  %03u\n",
			res.s, res.ms, res.us, res.ns);

	if (!prefs->status->received) {
		fflush(stdout);
		return;
	}

	tm = prefs->rec_tm;
	if (GET_FLAG(INSANITY, prefs->flags) < tm->insanity)
		goto flush;

	sum_rec = __timespec2double(tm->sum);
	res_rec = __separate_by_order(sum_rec / prefs->status->received);

	fprintf(stdout, "Avg. latency: %3u. %03u  %03u  %03u\n",
			res_rec.s, res_rec.ms, res_rec.us, res_rec.ns);

flush:
	print_io_stats(prefs, sum);
	fflush(stdout);
}

void print_progress(struct bench *prefs)
{
	int lines = 6;

	if ((prefs->op == X_READ) && (GET_FLAG(VERIFY, prefs->flags) != VERIFY_NO))
		lines++;

	fprintf(stdout, "\033[%dA\033[J", lines);
	print_stats(prefs);
}

/**************************\
 * Benchmarking functions *
\**************************/

void create_id(unsigned long seed)
{
	if (seed >= pow(10, 9))
		XSEGLOG2(&lc, W, "Seed larger than 10^9, only its first 9 digits will "
				"be used\n");

	//nanoseconds can't be more than 9 digits
	snprintf(global_id, IDLEN + 1, "bench-%09lu", seed);
}

void create_target(struct bench *prefs, struct xseg_request *req,
		uint64_t new)
{
	struct xseg *xseg = prefs->peer->xseg;
	char *req_target;
	char buf[TARGETLEN + 1];

	req_target = xseg_get_target(xseg, req);

	//For read/write, the target object may not correspond to `new`, which is
	//actually the chunk number.
	new = __get_object(prefs, new);
	snprintf(buf, TARGETLEN + 1, "%s-%016lu", global_id, new);
	strncpy(req_target, buf, TARGETLEN);
	XSEGLOG2(&lc, D, "Target name of request is %s\n", buf);
}


uint64_t determine_next(struct bench *prefs)
{
	if (GET_FLAG(PATTERN, prefs->flags) == PATTERN_SEQ)
		return prefs->status->submitted;
	else
		return lfsr_next(prefs->lfsr);
}

uint64_t calculate_offset(struct bench *prefs, uint64_t new)
{
	if (prefs->ts > 0)
		return (new * prefs->bs) % prefs->os;
	else
		return 0;
}

uint64_t calculate_prog_quantum(struct bench *prefs)
{
	return round((double)prefs->status->max / 20.0);
}


/*
 * ***********************************************
 * `create_chunk` handles 3 identifiers:
 * 1. The benchmark's global_id
 * 2. The object's number
 * 3. The chunk offset in the object
 *
 * ************************************************
 * `readwrite_chunk_full` takes the above 3 identifiers and feeds them as seeds
 * in 63-bit LFSRs. The numbers generated are written consecutively in chunk's
 * memory range. For example, for a 72-byte chunk:
 *
 * || 1 | 2 | 3 | 1 | 2 | 3 | 1 | 2 | 3 ||
 *  ^   8  16  24  32  40  48  56  64   ^
 *  |                                   |
 *  |                                   |
 * start                               end
 *
 * 1,2,3 differ between each iteration
 *
 * **************************************************
 * `_create_chunk_meta` simply writes the above 3 ids in the start and end of
 * the chunk's memory range, so it should be much faster (but less safe)
 *
 * **************************************************
 * In both cases, special care is taken not to exceed the chunk's memory range.
 * Also, the bare minimum chunk to verify should be 48 bytes. This limit is set
 * by reeadwrite_chunk_meta, which expects to write in a memory at least this
 * big.
 *
 * **************************************************
 * Note: The diagram above also represents the x86_64's endianness.
 * Endianness must be taken into careful consideration when examining a memory
 * chunk.
 */
static int readwrite_chunk_full(struct xseg *xseg, struct xseg_request *req,
		uint64_t id, uint64_t object)
{
	struct bench_lfsr id_lfsr;
	struct bench_lfsr obj_lfsr;
	struct bench_lfsr off_lfsr;
	uint64_t *d = (uint64_t *)xseg_get_data(xseg, req);
	uint64_t s = req->size;

	/* Create 63-bit LFSRs */
	lfsr_init(&id_lfsr, 0x7FFFFFFFFFFFFFFF, id, 0);
	lfsr_init(&obj_lfsr, 0x7FFFFFFFFFFFFFFF, object, 0);
	lfsr_init(&off_lfsr, 0x7FFFFFFFFFFFFFFF, req->offset, 0);

	if (s < sizeof(struct signature)) {
		XSEGLOG2(&lc, E, "Too small chunk size (%lu butes). Leaving.", s);
		return 1;
	}

	/*
	 * Every write operation has its read counterpart which, if it finds any
	 * corruption, returns 1
	 */

	if (req->op == X_WRITE) {
		__write_sig(&id_lfsr, d, s, 0);
		__write_sig(&obj_lfsr, d, s, 1);
		__write_sig(&off_lfsr, d, s, 2);
	} else {
		if (__read_sig(&id_lfsr, d, s, 0))
			return 1;
		if (__read_sig(&obj_lfsr, d, s, 1))
			return 1;
		if(__read_sig(&off_lfsr, d, s, 2))
			return 1;
	}

	return 0;
}

static int readwrite_chunk_meta(struct xseg *xseg, struct xseg_request *req,
		uint64_t id, uint64_t object)
{
	char *d = xseg_get_data(xseg, req);
	uint64_t s = req->size;
	struct signature sig;
	int sig_s = sizeof(struct signature);
	int r = 0;

	sig.id = id;
	sig.object = object;
	sig.offset = req->offset;

	if (s < sig_s) {
		XSEGLOG2(&lc, E, "Too small chunk size (%lu butes). Leaving.", s);
		return 1;
	}

	//PRINT_SIG(expected, (&sig));
	/* Read/Write chunk signature both at its start and at its end */
	if (req->op == X_WRITE) {
		memcpy(d, &sig, sig_s);
		memcpy(d + s - sig_s, &sig, sig_s);
	} else {
		if (memcmp(d, &sig, sig_s))
			r = 1;
		else if (memcmp(d + s - sig_s, &sig, sig_s))
			r = 1;
	}
	//PRINT_SIG(start, d);
	//PRINT_SIG(end, (d + s - sig_s));
	return r;
}

/*
 * We want these functions to be as fast as possible in case we haven't asked
 * for verification
 * TODO: Make them prettier but keep the speed of this implementation
 */
void create_chunk(struct bench *prefs, struct xseg_request *req, uint64_t new)
{
	struct xseg *xseg = prefs->peer->xseg;
	uint64_t id;
	uint64_t object;
	int verify;

	verify = GET_FLAG(VERIFY, prefs->flags);
	switch (verify) {
		case VERIFY_NO:
			break;
		case VERIFY_META:
			id = __get_id();
			object = __get_object(prefs, new);
			readwrite_chunk_meta(xseg, req, id, object);
			break;
		case VERIFY_FULL:
			id = __get_id();
			object = __get_object(prefs, new);
			readwrite_chunk_full(xseg, req, id, object);
			break;
		default:
			XSEGLOG2(&lc, W, "Unexpected verification mode: %d\n", verify);
	}
}

int read_chunk(struct bench *prefs, struct xseg_request *req)
{
	struct xseg *xseg = prefs->peer->xseg;
	uint64_t id;
	uint64_t object;
	char *target;
	int verify;
	int r = 0;

	verify = GET_FLAG(VERIFY, prefs->flags);
	switch (verify) {
		case VERIFY_NO:
			break;
		case VERIFY_META:
			id = __get_id();
			target = xseg_get_target(xseg, req);
			object = __get_object_from_name(target);
			r = readwrite_chunk_meta(xseg, req, id, object);
			break;
		case VERIFY_FULL:
			id = __get_id();
			target = xseg_get_target(xseg, req);
			object = __get_object_from_name(target);
			r = readwrite_chunk_full(xseg, req, id, object);
			break;
		default:
			XSEGLOG2(&lc, W, "Unexpected verification mode: %d\n", verify);
	}
	return r;
}
