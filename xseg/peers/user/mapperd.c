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

/*
 * The Mapper
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <aio.h>
#include <signal.h>
#include <limits.h>
#include <xseg/xseg.h>
#include <pthread.h>

#include <xseg/protocol.h>

#include "common.h"  /* Please fix me */

#define MAX_PATH_SIZE 255
#define MAX_FILENAME_SIZE 255

#define DEFAULT_NR_OPS 16

#define MAPPER_SANITY_CHECKS 1

/*
 * Globals, holding command-line arguments
 */
long cmdline_mportno = -1;
long cmdline_bportno = -1;
char *cmdline_xseg_spec = NULL;
long cmdline_nr_ops = DEFAULT_NR_OPS;

struct mapperd {
	struct xseg *xseg;
	struct xseg_port *mport;
	uint32_t mportno, bportno;
};

static int usage(char *argv0)
{
	fprintf(stderr,
		"Usage: %s [-p MAPPERD_PORT]"
			"[-b BLOCKD_POART] [-g XSEG_SPEC] [-n NR_OPS]\n\n"
		"where:\n"
		"\tMAPPERD_PORT: xseg port to listen for requests on\n"
		"\tBLOCKD_PORT: xseg port where blockd/filed/sosd lives\n"
		"\tXSEG_SPEC: xseg spec as 'type:name:nr_ports:nr_requests:"
			"request_size:extra_size:page_shift'\n"
		"\tNR_OPS: number of outstanding xseg requests\n",
		argv0);

	return 1;
}

static int safe_atoi(char *s)
{
	long l;
	char *endp;

	l = strtol(s, &endp, 10);
	if (s != endp && *endp == '\0')
		return l;
	else
		return -1;
}

static void parse_cmdline(int argc, char **argv)
{
	for (;;) {
		int c;

		opterr = 0;
		c = getopt(argc, argv, "+:hp:b:n:g:");
		if (c == -1)
			break;
		
		switch(c) {
			case '?':
				perr(PFE, 0, "Unknown option: -%c", optopt);
				break;
			case ':':
				perr(PFE, 0, "Option -%c requires an argument",
					optopt);
				break;
			case 'h':
				usage(argv[0]);
				exit(0);
				break;
			case 'p':
				cmdline_mportno = safe_atoi(optarg);
				break;
			case 'b':
				cmdline_bportno = safe_atoi(optarg);
				break;
			case 'n':
				cmdline_nr_ops = safe_atoi(optarg);
				break;
			case 'g':
				/* FIXME: Max length of spec? strdup, eww */
				cmdline_xseg_spec = strdup(optarg);
				if (!cmdline_xseg_spec)
					perr(PFE, 0, "out of memory");
                                break;
		}
	}

	argc -= optind;
	argv += optind;

	/* Sanity check for all arguments */
	if (cmdline_mportno < 0)
		perr(PFE, 0, "no or invalid port specified for mapperd");
	if (cmdline_bportno != -1)
		perr(PFE, 0, "This is a no-op 1-1 mapper. Cannot specify a blocker port");
		//no or invalid port specified for blockd/filed/sosd");
	if (cmdline_nr_ops < 1)
		perr(PFE, 0, "specified outstanding request count is invalid");
	if (!cmdline_xseg_spec)
		perr(PFE, 0, "xseg specification is mandatory");

	if (argc)
		perr(PFE, 0, "Non-option arguments specified on command line");
}

static struct xseg *join_or_create(char *spec)
{
	struct xseg_config config;
	struct xseg *xseg;

	(void)xseg_parse_spec(spec, &config);
	xseg = xseg_join(config.type, config.name, "posix", NULL);
	if (xseg)
		return xseg;

	(void)xseg_create(&config);
	return xseg_join(config.type, config.name, "posix", NULL);
}

static int mapperd_loop(struct mapperd *mapperd)
{
	int ret;
	struct xseg_request *xreq;
	struct xseg *xseg = mapperd->xseg;
	uint32_t mportno = mapperd->mportno;
	char *target, buf[MAX_FILENAME_SIZE];
	xport p;

	always_assert(xseg);

	for (;;) {
		ret = xseg_prepare_wait(xseg, mportno);
		always_assert(ret == 0);

		xreq = xseg_accept(xseg, mportno, 0);
		if (xreq) {
			xseg_cancel_wait(xseg, mportno);
			/*
 			 * Construct a 1-1 reply immediately, make sure it fits
 			 * Verify the initiator has allocated enough space for
 			 * the reply and the target name fits in the map reply.
 			 */
			size_t s = sizeof(struct xseg_reply_map) +
				2 * sizeof(struct xseg_reply_map_scatterlist);
			target = xseg_get_target(xseg, xreq);
			strncpy(buf, target, xreq->targetlen);
			xseg_resize_request(xseg, xreq, xreq->targetlen, s);
			target = xseg_get_target(xseg, xreq);
			strncpy(target, buf, xreq->targetlen);

			struct xseg_reply_map *mreply = (void *)xseg_get_data(xseg, xreq);
			mreply->cnt = 2;
			mreply->segs[0].offset = xreq->offset;
			mreply->segs[0].size = xreq->size/2;
			/* FIXME: strlcpy() would work nicely here */
			strncpy(mreply->segs[0].target, target, xreq->targetlen);
			mreply->segs[0].target[xreq->targetlen] = '_';
			mreply->segs[0].target[xreq->targetlen + 1] = '1';
			mreply->segs[0].target[xreq->targetlen + 2] = '\0';
			
			mreply->segs[1].offset = xreq->offset;
			mreply->segs[1].size = xreq->size/2;
			/* FIXME: strlcpy() would work nicely here */
			strncpy(mreply->segs[1].target, target, xreq->targetlen);
			mreply->segs[1].target[xreq->targetlen] = '_';
			mreply->segs[1].target[xreq->targetlen + 1] = '2';
			mreply->segs[1].target[xreq->targetlen + 2] = '\0';

			/* Respond to the initiator, signal the source port */
//			perr(PI, 0, "completed io");
			xreq->state |= XS_SERVED;
			p = xseg_respond(xseg, xreq, mportno, X_ALLOC);
			ret = xseg_signal(xseg, p);
//			always_assert(ret == 1);
		} else {
			/*
 			 * If things are OK, no timeout should ever be needed.
 			 * Otherwise, it's a mapperd or xseg bug.
 			 */
			xseg_wait_signal(xseg, 1000000UL);
		}
	}
	
	/* Shouldn't reach this point */
	always_assert(0);
	return 0;
}

/*
 * FIXME: Initialize the mapperd struct based on cmdline_* vars
 */
static int mapperd_init(struct mapperd *mapperd)
{
	int ret;

	mapperd->mportno = cmdline_mportno;
	mapperd->bportno = cmdline_bportno;

	/* FIXME: If xseg library fails, is errno set? */
	if (xseg_initialize()) {
		perr(PE, 0, "could not initialize xseg library");
		ret = -EIO;
		goto out;
	}

	if (! (mapperd->xseg = join_or_create(cmdline_xseg_spec))) {
		perr(PE, 0, "could not join or create xseg with spec '%s'\n",
			cmdline_xseg_spec);
		ret = -EIO;
		goto out_with_xseginit;
	}

	if (! (mapperd->mport = xseg_bind_port(mapperd->xseg, mapperd->mportno, NULL))) {
		perr(PE, 0, "cannot bind to xseg port %ld", (long)mapperd->mportno);
		ret = -EIO;
		goto out_with_xsegjoin;
	}

	mapperd->mportno = xseg_portno(mapperd->xseg, mapperd->mport);
	xseg_init_local_signal(mapperd->xseg, mapperd->mportno);
	perr(PI, 0, "mapperd on port %u of %u",
		mapperd->mportno, mapperd->xseg->config.nr_ports);

	ret = 0;
	goto out;

out_with_xsegjoin:
	xseg_leave(mapperd->xseg);
out_with_xseginit:
	xseg_finalize();
out:
	return ret;
}

int main(int argc, char *argv[])
{
	struct mapperd mapper;

	init_perr("mapperd");
	parse_cmdline(argc, argv);

	perr(PI, 0, "v = %ld, m = %ld, b = %ld, nr_ops = %lu\n",
		cmdline_mportno, cmdline_mportno, cmdline_bportno, cmdline_nr_ops);

	if (mapperd_init(&mapper) < 0) {
		perr(PFE, 0, "failed to initialize mapperd.");
		exit(1); /* This is just to quiesce gcc's control flow analysis */
	}

	return mapperd_loop(&mapper);
}

