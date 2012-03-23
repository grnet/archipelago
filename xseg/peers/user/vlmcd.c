/*
 * The VoLuMe Composer
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

#include "common.h"  /* Please fix me */

#define MAX_PATH_SIZE 255
#define MAX_FILENAME_SIZE 255

#define DEFAULT_NR_OPS 16

/*
 * Globals, holding command-line arguments
 */
long cmdline_vport = -1;
long cmdline_mport = -1;
long cmdline_bport = -1;
long cmdline_nr_ops = DEFAULT_NR_OPS;

/*
 * vlmcd-specific structure,
 * containing information on a pending I/O operation
 */
/* FIXME: XS_CONCLUDED equals XS_SERVING? */
/* FIXME: is it really vlmcd-specific? */
enum io_state_enum {
	ACCEPTED = 0,
	PENDING_MAPPER_REPLY = 1,
	PENDING_BLOCKD_REPLY = 2,
	CONCLUDED = 3
};

struct io {
	enum io_state_enum state;
	struct xseg_request *accepted_req;
	struct xseg_request *mapper_req;
	
	/* FIXME */
};

static int usage(char *argv0)
{
	fprintf(stderr,
		"Usage: %s [-p VLMCD_PORT] [-m MAPPERD_PORT]"
			"[-b BLOCKD_PORT] [-g XSEG_SPEC] [-n NR_OPS]\n\n"
		"where:\n"
		"\tVLMCD_PORT: xseg port to listen for requests on\n"
		"\tMAPPERD_PORT: xseg port where the mapper lives\n"
		"\tBLOCKD_PORT: xseg port where blockd/filed/sosd lives\n"
		"\tXSEG_SPEC: xseg spec as  'type:name:nr_ports:nr_requests:"
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
		c = getopt(argc, argv, "+:hp:m:b:n:");
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
				cmdline_vport = safe_atoi(optarg);
				break;
			case 'm':
				cmdline_mport = safe_atoi(optarg);
				break;
			case 'b':
				cmdline_bport = safe_atoi(optarg);
				break;
			case 'n':
				cmdline_nr_ops = safe_atoi(optarg);
				break;
		}
	}

	argc -= optind;
	argv += optind;

	/* Sanity check for all arguments */
	if (cmdline_vport < 0)
		perr(PFE, 0, "no or invalid port specified for vlmcd");
	if (cmdline_mport < 0)
		perr(PFE, 0, "no or invalid port specified for mapperd");
	if (cmdline_bport < 0)
		perr(PFE, 0, "no or invalid port specified for blockd/filed/sosd");
	if (cmdline_nr_ops < 1)
		perr(PFE, 0, "specified outstanding request count is invalid");

	if (argc)
		perr(PFE, 0, "Non-option arguments specified on command line");
}

static struct xseg *join(char *spec)
{
	struct xseg_config config;
	struct xseg *xseg;

	(void)xseg_parse_spec(spec, &config);
	xseg = xseg_join(config.type, config.name);
	if (xseg)
		return xseg;

	(void)xseg_create(&config);
	return xseg_join(config.type, config.name);
}

static int dispatch(struct io *io)
{
	/* FIXME: Arguments, sanity checks on them? */
	switch (io->state) {
	case ACCEPTED:
		/*
		 * Just accepted a new request,
		 * construct and submit a request to
		 * the mapper port.
		 */
		/* FIXME: Do I need to lock io? */
		req_mapper = FIXME;
		xseg_submit(FIXME);
		io->state = PENDING_MAPPER_REPLY;
		break;
	case PENDING_MAPPER_REPLY:
		/*
		 * Now that we know where the requested
		 * volume block maps, use the blocker to fetch it.
		 */
		xseg_free_request(req_mapper);
		req_blocker = FIXME;
		xseg_submit(FIXME);
		io->state = PENDING_BLOCKER_REPLY;
		break;
	case PENDING_BLOCKER_REPLY:
		/*
		 * Now that the block is in place,
		 * complete the original request.
		 */
		complete(io); /* FIXME: bogus */
	}

	return 0;
}

static int vlmcd_loop(FIXME)
{
	/* Create nr_ops threads */
	/* Have all threads call xseg_accept() */

	for (;;) {
		prepare_wait(xseg, portno);

		/* only accept a new request if there's room */
		io = NULL;
		if (remaining) {
			if (xseg_accept()) {
				/* allocate a new pending io structure */
				io = alloc_io();
				req->priv = io;
			}
		}

		/* has a reply arrived? */
		if (xseg_receive()) {
			io = req->priv;
		}

		/* io is the pending io currently being processed */
		if (io) {
			cancel_wait(xseg, portno);
			dispatch(io);
		} else {
			/*
 			 * FIXME: I don't want a timeout.
 			 * If things are OK, no timeout should ever be needed.
 			 * Otherwise, it's a vlmcd or xseg bug.
 			 */
			xseg_wait_signal(xseg, portno, 0);
		}
	}

	return 0;
}

static int vlmcd(FIXME)
{
	struct xseg *xseg;

	/* FIXME: If xseg library fails, is errno set? */
	if (xseg_initialize("posix")) {
		perr(PE, 0, "could not initialize xseg library");
		return -1;
	}

	if (! (xseg = join(spec))) {
		perr(PE, 0, "could not join or create xseg with spec '%s'\n",
			spec);
		return -1;
	}

	if (! (xport = xseg_bind_port(xseg, portno))) {
		perr(PE, 0, "cannot bind to xseg port %ld", portno);
		return 1;

	portno = xseg_portno(xseg, xport);
	
	perr(PI, 0, "vlmcd on port %u of %u",
		portno, xseg->config.nr_ports);
	
	return vlmcd_loop(FIXME);
}

int main(int argc, char *argv[])
{
	init_perr("vlmcd");
	parse_cmdline(argc, argv);

	perr(PI, 0, "v = %ld, m = %ld, b = %ld, nr_ops = %lu\n",
		cmdline_vport, cmdline_mport, cmdline_bport, cmdline_nr_ops);

	return 0;
#if 0
	if (nr_ops <= 0)
		nr_ops = 16;

	return filed(path, size, nr_ops, spec, portno);
#endif
}

