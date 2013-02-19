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

struct timespec delay = {0, 4000000};

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

int read_insanity(char *insanity)
{
	if (strcmp(insanity, "sane") == 0)
		return TM_SANE;
	if (strcmp(insanity, "eccentric") == 0)
		return TM_ECCENTRIC;
	if (strcmp(insanity, "manic") == 0)
		return TM_MANIC;
	if (strcmp(insanity, "paranoid") == 0)
		return TM_PARANOID;
	return -1;
}

int read_op(char *op)
{
	if (strcmp(op, "read") == 0)
		return X_READ;
	if (strcmp(op, "write") == 0)
		return X_WRITE;
	if (strcmp(op, "info") == 0)
		return X_INFO;
	if (strcmp(op, "delete") == 0)
		return X_DELETE;
	return -1;
}

int read_pattern(char *pattern)
{
	if (strcmp(pattern, "sync") == 0)
		return IO_SYNC;
	if (strcmp(pattern, "rand") == 0)
		return IO_RAND;
	return -1;
}

void print_res(struct tm_result res, char *type)
{
	printf("\n");
	printf("      %s\n", type);
	printf("================================\n");
	printf("       |-s-||-ms-|-us-|-ns-|\n");
	printf("Time:   %03lu. %03lu  %03lu  %03lu\n",
			res.s, res.ms, res.us, res.ns);
}

/*
 * Seperates a timespec struct in seconds, msec, usec, nsec
 */
void separate_by_order(struct timespec src, struct tm_result *res)
{
	res->ns = src.tv_nsec % 1000;
	src.tv_nsec /= 1000;
	res->us = src.tv_nsec % 1000;
	res->ms = src.tv_nsec / 1000;
	res->s = src.tv_sec;
}

void create_target(struct bench *prefs, struct xseg_request *req,
		uint64_t new)
{
	struct xseg *xseg = prefs->peer->xseg;
	char *req_target;

	req_target = xseg_get_target(xseg, req);

	//For read/write, the target object does not correspond to `new`, which is
	//actually the chunk number. We need to div this number with the number of
	//chunks in an object.
	//FIXME: Make it more elegant
	if (prefs->op == X_READ || prefs->op == X_WRITE)
		new = new / (prefs->os / prefs->ts);
	snprintf(req_target, TARGETLEN, "%s-%016lu", global_id, new);
	XSEGLOG2(&lc, D, "Target name of request is %s\n", req_target);
}

void create_chunk(struct bench *prefs, struct xseg_request *req, uint64_t new)
{/*
	struct xseg *xseg = prefs->peer->xseg;
	char *req_data;

	//TODO: Fill data depening on validation level
	req_data = xseg_get_data(xseg, req);
	*/
}

uint64_t determine_next(struct bench *prefs)
{
	if ((prefs->flags & PATTERN_FLAG) == IO_SYNC)
		return prefs->sub_tm->completed;
	else {
		return lfsr_next(prefs->lfsr);
	}
}

//FIXME: this looks like a hack, handle it more elegantly
void create_id()
{
	struct timespec seed;

	clock_gettime(CLOCK_MONOTONIC_RAW, &seed);

	global_seed = seed.tv_nsec;
	//nanoseconds can't be more than 9 digits
	snprintf(global_id, IDLEN, "bench-%09lu", global_seed);
	XSEGLOG2(&lc, I, "Global ID is %s\n", global_id);
}
