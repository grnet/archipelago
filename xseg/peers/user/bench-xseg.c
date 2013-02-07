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
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>
#include <xseg/xseg.h>
#include <peer.h>
#include <time.h>
#include <sys/util.h>

struct timespec delay = {0, 4000000};

struct bench {
	uint64_t ts; //Total I/O size
	uint64_t os; //Object size
	uint64_t bs; //Block size
	uint32_t iodepth; //Num of in-flight xseg reqs
	uint8_t flags;
};

#define MAX_ARG_LEN 10

void custom_peer_usage()
{
	fprintf(stderr, "Custom peer options: \n"
		"  --------------------------------------------\n"
		"    -ts       | None    | Total I/O size\n"
		"    -os       | 4M      | Object size\n"
		"    -bs       | 4k      | Block size\n"
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
	END_READ_ARGS();

	//Block size (bs): Defaults to 4K.
	//It must be a number followed by one of these characters: [k|K|m|M|g|G].
	//If not, it will be considered as size in bytes.
	//Must be integer multiple of segment's page size (typically 4k).
	if (!block_size[0])
		strcpy(block_size,"4k");

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

	return 0;

arg_fail:
	free(prefs);
	custom_peer_usage();
	return -1;
}

void custom_peer_finalize(struct peerd *peer)
{
	return;
}

int dispatch(struct peerd *peer, struct peer_req *pr, struct xseg_request *req,
		enum dispatch_reason reason)
{
	if (canDefer(peer))
		defer_request(peer, pr);
	else {
//		printf("completing req id: %u (remote %u)\n", (unsigned int) (pr - peer->peer_reqs), (unsigned int) pr->req->priv);
//		nanosleep(&delay,NULL);
//		print_req(peer->xseg, pr->req);
		complete(peer, pr);
	}
	return 0;
}
