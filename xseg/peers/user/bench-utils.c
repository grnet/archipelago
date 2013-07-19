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

struct timespec delay = {0, 4000000};

uint64_t __get_object(struct bench *prefs, uint64_t new)
{
	if (prefs->ts > 0)
		new = new / (prefs->os / prefs->bs);
	return new;
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
	if (strncmp(progress, "req", MAX_ARG_LEN + 1) == 0)
		return PROGRESS_REQ;
	if (strncmp(progress, "io", MAX_ARG_LEN + 1) == 0)
		return PROGRESS_IO;
	if (strncmp(progress, "both", MAX_ARG_LEN + 1) == 0)
		return PROGRESS_BOTH;
	return -1;
}

/*
 * Read interval in percentage or raw mode and return its length (in requests)
 * If syntax is invalid, return 0.
 */
uint64_t read_interval(struct bench *prefs, char *str_interval)
{
	char *unit = NULL;
	uint64_t interval;

	interval = strtoll(str_interval, &unit, 10);

	/* If interval is raw number of requests */
	if (!unit[0] && interval < prefs->status->max)
		return interval;

	/* If interval is percentage of max requests */
	if (strncmp(unit, "%", MAX_ARG_LEN + 1) == 0 &&
			interval > 0 && interval < 100)
		return calculate_interval(prefs, interval);

	return 0;
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

int validate_seed(struct bench *prefs, unsigned long seed)
{
	if (seed < pow(10, prefs->objvars->seedlen))
		return 0;
	return -1;
}

uint64_t calculate_interval(struct bench *prefs, uint64_t percentage)
{
	uint64_t interval = round((double)prefs->status->max *
			(double)percentage / 100);

	if (!interval)
		interval = 1;

	return interval;
}

/**************************\
 * Benchmarking functions *
\**************************/

void create_target(struct bench *prefs, struct xseg_request *req)
{
	struct xseg *xseg = prefs->peer->xseg;
	struct object_vars *obv = prefs->objvars;
	char *req_target;

	req_target = xseg_get_target(xseg, req);

	/*
	 * For read/write, the target object may not correspond to `new`, which
	 * is actually the chunk number.
	 * Also, we use one extra byte while writting the target's name to store
	 * the null character and not overflow, but this will not be part of the
	 * target's name
	 */
	if (obv->prefix[0]) {
		snprintf(req_target, obv->namelen + 1, "%s-%0*lu-%0*lu",
				obv->prefix, obv->seedlen, obv->seed,
				obv->objnumlen, obv->objnum);
	} else {
		strncpy(req_target, obv->name, obv->namelen);
	}
	XSEGLOG2(&lc, D, "Target name of request is %s\n", req_target);
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

