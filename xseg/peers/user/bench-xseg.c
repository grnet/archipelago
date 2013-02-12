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

void custom_peer_usage()
{
	fprintf(stderr, "Custom peer options: \n"
		"  --------------------------------------------\n"
		"    -ts       | None    | Total I/O size\n"
		"    -os       | 4M      | Object size\n"
		"    -bs       | 4k      | Block size\n"
		"    -dp       | None    | Destination port\n"
		"    --iodepth | 1       | Number of in-flight I/O requests\n"
		"\n");
}

/*
 * Convert string to size in bytes.
 * If syntax is invalid, return 0. Values such as zero and non-integer
 * multiples of segment's page size should not be accepted.
 */
static uint64_t str2num(char *str)
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

int custom_peer_init(struct peerd *peer, int argc, char *argv[])
{
	struct bench *prefs;
	char total_size[MAX_ARG_LEN + 1];
	char object_size[MAX_ARG_LEN + 1];
	char block_size[MAX_ARG_LEN + 1];
	struct xseg *xseg = peer->xseg;
	unsigned int xseg_page_size = 1 << xseg->config.page_shift;
	long dst_port = -1;

	total_size[0] = 0;
	block_size[0] = 0;
	object_size[0] = 0;

	prefs = malloc(sizeof(struct bench));
	if (!prefs) {
		perror("malloc");
		return -1;
	}

	//Begin reading the benchmark-specific arguments
	BEGIN_READ_ARGS(argc, argv);
	READ_ARG_STRING("-ts", total_size, MAX_ARG_LEN);
	READ_ARG_STRING("-os", object_size, MAX_ARG_LEN);
	READ_ARG_STRING("-bs", block_size, MAX_ARG_LEN);
	READ_ARG_ULONG("--iodepth", prefs->iodepth);
	READ_ARG_ULONG("-dp", dst_port);
	END_READ_ARGS();

	/*************************
	 * Check size parameters *
	 *************************/

	//Block size (bs): Defaults to 4K.
	//It must be a number followed by one of these characters: [k|K|m|M|g|G].
	//If not, it will be considered as size in bytes.
	//Must be integer multiple of segment's page size (typically 4k).
	if (!block_size[0])
		strcpy(block_size,"4k");

	if (!prefs->iodepth)
		prefs->iodepth = 1;

	prefs->bs = str2num(block_size);
	if (!prefs->bs) {
		XSEGLOG2(&lc, E, "Invalid syntax: %s\n", block_size);
		goto arg_fail;
	} else if (prefs->bs % xseg_page_size) {
		XSEGLOG2(&lc, E, "Misaligned block size: %s\n", block_size);
		goto arg_fail;
	}

	//Total I/O size (ts): Must be supplied by user.
	//Must have the same format as "total size"
	//Must be integer multiple of "block size"
	if (!total_size[0]) {
		XSEGLOG2(&lc, E, "Total I/O size needs to be supplied\n");
		goto arg_fail;
	}

	prefs->ts = str2num(total_size);
	if (!prefs->ts) {
		XSEGLOG2(&lc, E, "Invalid syntax: %s\n", total_size);
		goto arg_fail;
	} else if (prefs->ts % prefs->bs) {
		XSEGLOG2(&lc, E, "Misaligned total I/O size: %s\n", total_size);
		goto arg_fail;
	} else if (prefs->ts > xseg->segment_size) {
		XSEGLOG2(&lc, E, "Total I/O size exceeds segment size\n", total_size);
		goto arg_fail;
	}

	//Object size (os): Defaults to 4M.
	//Must have the same format as "total size"
	//Must be integer multiple of "block size"
	if (!object_size[0])
		strcpy(object_size,"4M");

	prefs->os = str2num(object_size);
	if (!prefs->os) {
		XSEGLOG2(&lc, E, "Invalid syntax: %s\n", object_size);
		goto arg_fail;
	} else if (prefs->os % prefs->bs) {
		XSEGLOG2(&lc, E, "Misaligned object size: %s\n", object_size);
		goto arg_fail;
	}

	/*************************
	 * Check port parameters *
	 *************************/

	if (dst_port < 0){
		XSEGLOG2(&lc, E, "Destination port needs to be supplied\n");
		goto arg_fail;
	}

	prefs->src_port = peer->portno_start; //TODO: allow user to change this
	prefs->dst_port = (xport) dst_port;

	/*********************************
	 * Create timers for all metrics *
	 *********************************/

	prefs->total_tm = malloc(sizeof(struct timer));
	prefs->get_tm = malloc(sizeof(struct timer));
	prefs->sub_tm = malloc(sizeof(struct timer));
	prefs->rec_tm = malloc(sizeof(struct timer));
	if (!prefs->total_tm || !prefs->get_tm || !prefs->sub_tm ||
			!prefs->rec_tm) {
		perror("malloc");
		return -1;
	}
	memset(prefs->total_tm, 0, sizeof(struct timer));
	memset(prefs->get_tm, 0, sizeof(struct timer));
	memset(prefs->sub_tm, 0, sizeof(struct timer));
	memset(prefs->rec_tm, 0, sizeof(struct timer));

	/**************************
	 * Customize struct peerd *
	 **************************/

	peer->peerd_loop = custom_peerd_loop;
	peer->priv = (void *) prefs;
	return 0;

arg_fail:
	free(prefs);
	custom_peer_usage();
	return -1;
}


static int send_request(struct peerd *peer, struct bench *prefs)
{
	struct xseg_request *req;
	struct xseg *xseg = peer->xseg;
	struct peer_req *pr;
	xport srcport = prefs->src_port;
	xport dstport = prefs->dst_port;
	xport p;

	int r;
	uint32_t targetlen=10; //FIXME: handle it better
	uint64_t size = prefs->bs;

	//srcport and dstport must already be provided by the user.
	//returns struct xseg_request with basic initializations
	XSEGLOG("Get request %lu\n", prefs->get_tm->completed);
	timer_start(prefs->get_tm);
	req = xseg_get_request(xseg, srcport, dstport, X_ALLOC);
	if (!req) {
		fprintf(stderr, "No request\n");
		return -1;
	}
	timer_stop(prefs->get_tm);

	XSEGLOG("Prepare request\n");
	//Allocate enough space for the data and the target's name
	r = xseg_prep_request(xseg, req, targetlen, size);
	if (r < 0) {
		fprintf(stderr, "Cannot prepare request! (%lu, %llu)\n",
			(unsigned long)targetlen, (unsigned long long)size);
		xseg_put_request(xseg, req, srcport);
		return -1;
	}

#if 0
	//TODO: allow strcpy, memcpy
	//Copy target's name to the newly allocated space
	req_target = xseg_get_target(xseg, req);
	strncpy(req_target, target, targetlen);

	//Copy data buffer to the newly allocated space
	req_data = xseg_get_data(xseg, req);
	memcpy(req_data, buf, size);
	req->offset = offset;
	req->size = size;
	req->op = X_WRITE;
#endif

	//Measure this?
	XSEGLOG("Set req data\n");
	pr = alloc_peer_req(peer);
	r = xseg_set_req_data(xseg, req, pr);


	XSEGLOG("Submit request %lu\n", prefs->sub_tm->completed);
	//Submit the request from the source port to the target port
	timer_start(prefs->sub_tm);
	p = xseg_submit(xseg, req, srcport, X_ALLOC);
	if (p == NoPort) {
		fprintf(stderr, "Cannot submit\n");
		return -1;
	}
	timer_stop(prefs->sub_tm);

	timer_start(prefs->rec_tm);
	//Send SIGIO to the process that has binded this port to inform that
	//IO is possible
	xseg_signal(xseg, p);

	return 0;
}

/*
 * This function substitutes the default generic_peerd_loop of peer.c.
 * It's plugged to struct peerd at custom peer's initialisation
 */
int custom_peerd_loop(void *arg)
{
#ifdef MT
	struct thread *t = (struct thread *) arg;
	struct peerd *peer = t->peer;
	char *id = t->arg;
#else
	struct peerd *peer = (struct peerd *) arg;
	char id[4] = {'P','e','e','r'};
#endif
	struct xseg *xseg = peer->xseg;
	struct bench *prefs = peer->priv;
	xport portno_start = peer->portno_start;
	xport portno_end = peer->portno_end;
	uint64_t threshold=1000/(1 + portno_end - portno_start);
	pid_t pid =syscall(SYS_gettid);

	XSEGLOG2(&lc, I, "%s has tid %u.\n",id, pid);
	xseg_init_local_signal(xseg, peer->portno_start);
	uint64_t loops;
	unsigned long max_completed = prefs->ts / prefs->bs;

	timer_start(prefs->total_tm);

	while (!isTerminate() && xq_count(&peer->free_reqs) == peer->nr_ops) {
#ifdef MT
		if (t->func) {
			XSEGLOG2(&lc, D, "%s executes function\n", id);
			xseg_cancel_wait(xseg, peer->portno_start);
			t->func(t->arg);
			t->func = NULL;
			t->arg = NULL;
			continue;
		}
#endif
send_request:
		while (prefs->sub_tm->completed - prefs->rec_tm->completed <
				prefs->iodepth){
			XSEGLOG2(&lc, I, "Start sending new request\n");
			send_request(peer, prefs);
		}

		//Heart of peerd_loop. This loop is common for everyone.
		for (loops = threshold; loops > 0; loops--) {
			if (check_ports(peer)) {
				if (max_completed == prefs->rec_tm->completed)
					return 0;
				else
					//If an old request has just been acked, the most sensible
					//thing to do is immediately to send a new one
					goto send_request;
			}
		}
		xseg_prepare_wait(xseg, peer->portno_start);
#ifdef ST_THREADS
		if (ta){
			st_sleep(0);
			continue;
		}
#endif
		XSEGLOG2(&lc, I, "%s goes to sleep\n",id);
		xseg_wait_signal(xseg, 10000000UL);
		xseg_cancel_wait(xseg, peer->portno_start);
		XSEGLOG2(&lc, I, "%s woke up\n", id);
	}

	XSEGLOG2(&lc, I, "peer->free_reqs = %d, peer->nr_ops = %d\n",
			xq_count(&peer->free_reqs), peer->nr_ops);
	return 0;
}

void custom_peer_finalize(struct peerd *peer)
{
	struct bench *prefs = peer->priv;
	unsigned int s, ms, us, ns;

	if (!prefs->total_tm->completed)
		timer_stop(prefs->total_tm);

	struct timespec tm = prefs->total_tm->sum;
	ns = tm.tv_nsec % 1000;
	tm.tv_nsec /= 1000;
	us = tm.tv_nsec % 1000;
	ms = tm.tv_nsec / 1000;
	s = tm.tv_sec;

	printf("\n");
	printf("          Total time spent\n");
	printf("================================\n");
	printf("      |-s-||-ms-|-us-|-ns-|\n");
	printf("Time:  %03u, %03u  %03u  %03u\n", s, ms, us, ns);
	return;
}


static void handle_received(struct peerd *peer, struct peer_req *pr)
{
	//FIXME: handle null pointer
	struct bench *prefs = peer->priv;
	struct timer *rec = prefs->rec_tm;

	timer_stop(rec);
}

int dispatch(struct peerd *peer, struct peer_req *pr, struct xseg_request *req,
		enum dispatch_reason reason)
{
	switch (reason) {
		case dispatch_accept:
			//This is wrong, benchmarking peer should not accept requests,
			//only receive them.
			complete(peer, pr);
			break;
		case dispatch_receive:
			handle_received(peer, pr);
			break;
		default:
			fail(peer, pr);
	}
	return 0;
}
