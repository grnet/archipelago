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

/******************************\
 * Static miscellaneous tools *
\******************************/

static inline double __timespec2double(struct timespec num)
{
	return (double) (num.tv_sec * pow(10, 9) + num.tv_nsec);
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

	if (bw->val < 1024) {
		strcpy(bw->unit, "B/s");
		return;
	}

	bw->val = bw->val / 1024;

	if (bw->val < 1024) {
		strcpy(bw->unit, "KB/s");
		return;
	}

	bw->val = bw->val / 1024;

	if (bw->val < 1024) {
		strcpy(bw->unit, "MB/s");
		return;
	}

	bw->val = bw->val / 1024;
	strcpy(bw->unit, "GB/s");
}

static double __calculate_iops(uint64_t requests, double elapsed_ns)
{
	/* elapsed_ns is in nanoseconds, so we convert it to seconds */
	double elapsed = elapsed_ns / pow(10,9);
	return (requests / elapsed);
}

/*******************\
 * Print functions *
\*******************/

int calculate_report_lines(struct bench *prefs)
{
	int ptype = prefs->rep->type;
	int lines = 0;

	if (ptype == PTYPE_REQ || ptype == PTYPE_BOTH) {
		lines = 6;
		if ((GET_FLAG(VERIFY, prefs->flags) != VERIFY_NO) &&
				(prefs->op == X_READ))
			lines++;
	}
	if (ptype == PTYPE_IO || ptype == PTYPE_BOTH) {
		lines += 1;
		if (prefs->op == X_READ || prefs->op == X_WRITE)
			lines++;
	}

	return lines;
}

void clear_report_lines(int lines)
{
	fprintf(stdout, "\033[%dA\033[J", lines);
}

void print_divider()
{
	fprintf(stdout, "           ~~~~~~~~~~~~~~~~~~~~~~~~\n");
}

void print_io_stats(struct bench *prefs)
{
	struct timer *tm = prefs->total_tm;
	struct bw bw;
	double elapsed;
	double iops;

	if (!prefs->status->received) {
		if (prefs->op == X_READ || prefs->op == X_WRITE)
			fprintf(stdout, "Bandwidth:    NaN\n");
		fprintf(stdout, "IOPS:         NaN\n");
		return;
	}

	elapsed = __timespec2double(tm->elapsed_time);
	iops = __calculate_iops(prefs->rep->interval, elapsed);
	__calculate_bw(prefs, iops, &bw);

	if (prefs->op == X_READ || prefs->op == X_WRITE)
		fprintf(stdout, "Bandwidth:    %.3lf %s\n", bw.val, bw.unit);
	fprintf(stdout, "IOPS:         %.3lf\n", iops);
}

void print_req_stats(struct bench *prefs)
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
	if ((prefs->op == X_READ) &&
			(GET_FLAG(VERIFY, prefs->flags) != VERIFY_NO))
		fprintf(stdout, "Requests corrupted: %10lu\n",
				prefs->status->corrupted);
	fprintf(stdout, "\n");
}

void print_remaining(struct bench *prefs)
{
	uint64_t remaining;

	remaining = prefs->status->max - prefs->status->received;
	if (remaining)
		fprintf(stdout, "Requests remaining: %10lu\n", remaining);
	else
		fprintf(stdout, "All requests have been served.\n");
}

void print_total_res(struct bench *prefs)
{
	struct timer *tm = prefs->total_tm;
	struct tm_result res;
	double sum;

	sum = __timespec2double(tm->sum);
	res = __separate_by_order(sum);

	fprintf(stdout, "\n");
	fprintf(stdout, "              Benchmark results\n");
	fprintf(stdout, "           ========================\n");
	fprintf(stdout, "             |-s-||-ms-|-us-|-ns-|\n");
	fprintf(stdout, "Total time:   %3u. %03u  %03u  %03u\n",
			res.s, res.ms, res.us, res.ns);
}

void print_rec_res(struct bench *prefs)
{
	struct timer *tm = prefs->rec_tm;
	struct tm_result res;
	double sum;

	if (!prefs->status->received) {
		fprintf(stdout, "Avg. latency: NaN\n");
		return;
	}

	sum = __timespec2double(tm->sum);
	res = __separate_by_order(sum / prefs->status->received);

	fprintf(stdout, "Avg. latency: %3u. %03u  %03u  %03u\n",
			res.s, res.ms, res.us, res.ns);
}

static void __print_progress(struct bench *prefs)
{
	int ptype = prefs->rep->type;

	if (ptype == PTYPE_REQ || ptype == PTYPE_BOTH)
			print_req_stats(prefs);
	if (ptype == PTYPE_IO || ptype == PTYPE_BOTH)
			print_io_stats(prefs);
	fflush(stdout);
}

void print_dummy_progress(struct bench *prefs)
{
	__print_progress(prefs);
}

void print_progress(struct bench *prefs)
{
	timer_stop(prefs, prefs->total_tm, NULL);
	clear_report_lines(prefs->rep->lines);
	__print_progress(prefs);
	timer_start(prefs, prefs->total_tm);
}


