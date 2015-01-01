/*
Copyright (C) 2010-2014 GRNET S.A.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
#include <xseg/util.h>
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
				(prefs->op == X_READ)) {
			lines++;
        }
	}
	if (ptype == PTYPE_IO || ptype == PTYPE_BOTH) {
		lines += 1;
		if (prefs->op == X_READ || prefs->op == X_WRITE) {
			lines++;
        }
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
		if (prefs->op == X_READ || prefs->op == X_WRITE) {
			fprintf(stdout, "Bandwidth:    NaN\n");
        }
		fprintf(stdout, "IOPS:         NaN\n");
		return;
	}

	elapsed = __timespec2double(tm->elapsed_time);
	iops = __calculate_iops(prefs->rep->interval, elapsed);
	__calculate_bw(prefs, iops, &bw);

	if (prefs->op == X_READ || prefs->op == X_WRITE) {
		fprintf(stdout, "Bandwidth:    %.3lf %s\n", bw.val, bw.unit);
    }
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
			(GET_FLAG(VERIFY, prefs->flags) != VERIFY_NO)) {
		fprintf(stdout, "Requests corrupted: %10lu\n",
				prefs->status->corrupted);
    }
	fprintf(stdout, "\n");
}

void print_remaining(struct bench *prefs)
{
	uint64_t remaining;

	remaining = prefs->status->max - prefs->status->received;
	if (remaining) {
		fprintf(stdout, "Requests remaining: %10lu\n", remaining);
    } else {
		fprintf(stdout, "All requests have been served.\n");
    }
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

	if (ptype == PTYPE_REQ || ptype == PTYPE_BOTH) {
			print_req_stats(prefs);
    }
	if (ptype == PTYPE_IO || ptype == PTYPE_BOTH) {
			print_io_stats(prefs);
    }
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
