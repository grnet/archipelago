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

#include <xseg/protocol.h>

#include "common.h"  /* Please fix me */

#define MAX_PATH_SIZE 255
#define MAX_FILENAME_SIZE 255

#define DEFAULT_NR_OPS 128

#define VLMCD_SANITY_CHECKS 1

/*
 * Globals, holding command-line arguments
 */
long cmdline_vportno = -1;
long cmdline_mportno = -1;
long cmdline_bportno = -1;
char *cmdline_xseg_spec = NULL;
long cmdline_nr_ops = DEFAULT_NR_OPS;

/*
 * vlmcd-specific structure,
 * containing information on a pending I/O operation
 */
/* FIXME: XS_CONCLUDED equals XS_SERVING? */
/* FIXME: is it really vlmcd-specific? */
enum io_state_enum {
	ACCEPTED = 0,
	MAPPING = 1,
	SERVING = 2,
	CONCLUDED = 3
};

struct io {
	enum io_state_enum state;
	struct xseg_request *vreq;
	struct xseg_request *mreq;
	struct xseg_request **breqs;
	int breqs_len, breq_cnt;
};

struct vlmcd {
	struct xseg *xseg;
	struct xseg_port *vport;
	uint32_t vportno, mportno, bportno;

	int flying;
	long nr_ops;
	struct xq free_ops;

	struct xq free_ios;
	struct io *ios;

};

static inline struct io *__io_from_idx(struct vlmcd *vlmcd, xqindex idx)
{
	if (idx >= vlmcd->nr_ops) {
		perr(PE, 0, "Internal error: called with idx = %ld > %ld",
			(long)idx, vlmcd->nr_ops);
		return NULL;
	}

	return &vlmcd->ios[idx];
}

static inline xqindex __idx_from_io(struct vlmcd *vlmcd, struct io *io)
{
	long idx = io - vlmcd->ios;

	if (idx < 0 || idx >= vlmcd->nr_ops) {
		perr(PE, 0, "Internal error: called with io = %p, idx = %ld, "
			"nr_ops = %ld",
			(void *)io, (long)(io - vlmcd->ios), vlmcd->nr_ops);
		return Noneidx;
	}

	return idx;
}

static inline struct io *alloc_io(struct vlmcd *vlmcd)
{
	xqindex idx = xq_pop_head(&vlmcd->free_ios);
	if (idx == Noneidx)
		return NULL;
	++vlmcd->flying;
//	perr(PI, 0, "alloc'd io %p, in-flight reqs: %d", (void *)&vlmcd->ios[idx], vlmcd->flying);
	return &vlmcd->ios[idx];
}

static inline void free_io(struct vlmcd *vlmcd, struct io *io)
{
	/* FIXME: what if xq_append_head() fails? */
	xq_append_head(&vlmcd->free_ios, __idx_from_io(vlmcd, io));
	--vlmcd->flying;
}

static int complete(struct vlmcd *vlmcd, struct io *io)
{
	int ret;

	io->vreq->state |= XS_SERVED;
//	perr(PI, 0, "completed io %p", (void *)io);
	ret = xseg_respond(vlmcd->xseg, io->vreq->portno, io->vreq);
	always_assert(ret != NoSerial);
	ret = xseg_signal(vlmcd->xseg, io->vreq->portno);
	always_assert(ret == 0);

	return 0;
}

static int usage(char *argv0)
{
	fprintf(stderr,
		"Usage: %s [-p VLMCD_PORT] [-m MAPPERD_PORT]"
			"[-b BLOCKD_POART] [-g XSEG_SPEC] [-n NR_OPS]\n\n"
		"where:\n"
		"\tVLMCD_PORT: xseg port to listen for requests on\n"
		"\tMAPPERD_PORT: xseg port where the mapper lives\n"
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
		c = getopt(argc, argv, "+:hp:m:b:n:g:");
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
				cmdline_vportno = safe_atoi(optarg);
				break;
			case 'm':
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
	if (cmdline_vportno < 0)
		perr(PFE, 0, "no or invalid port specified for vlmcd");
	if (cmdline_mportno < 0)
		perr(PFE, 0, "no or invalid port specified for mapperd");
	if (cmdline_bportno < 0)
		perr(PFE, 0, "no or invalid port specified for blockd/filed/sosd");
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

/*
 * FIXME: What happens if this function fails?
 * FIXME: How does this function fail? Do we return values from <errno.h>
 * FIXME: Error reporting: Who prints errors, who prints errno?
 */
static int dispatch(struct vlmcd *vlmcd, struct io *io, struct xseg_request *xreq)
{
	struct xseg *xseg;
	uint32_t vportno;
	int i, ret;
	uint64_t pos;

	always_assert(vlmcd);
	always_assert(io);
	xseg = vlmcd->xseg;
	always_assert(xseg);
	vportno = vlmcd->vportno;

	/* FIXME: Arguments, sanity checks on them? */
	switch (io->state) {
	case ACCEPTED:
		/*
		 * Step 1: Issue a request to the mapper.
		 */
		/* FIXME: xseglog(), strerror(), etc */
		/* FIXME: xreq->target a pointer?! why not a field, like * xreq->op? */
		always_assert(io->vreq == xreq);
		io->vreq->serviced = 0;
		io->mreq = xseg_get_request(xseg, vportno);
		always_assert(io->mreq);
		/*
		 * FIXME:
		 * We only care about the length of the target name
		 * and hope the mapper reply fits in the remaining datalen
		 * bytes.
		 */
		ret = xseg_prep_request(io->mreq, io->vreq->targetlen,
			io->mreq->bufferlen - io->vreq->targetlen);
		always_assert(ret == 0);

		struct xseg_request *m = io->mreq;
		strncpy(m->target, io->vreq->target, m->targetlen);
		m->size = io->vreq->size;
		m->offset = io->vreq->offset;
		m->flags = 0;
		m->priv = __idx_from_io(vlmcd, io); /* use the io's idx for tracking */
		switch (io->vreq->op) {
			case X_READ:  m->op = X_MAPR; break;
			case X_WRITE: m->op = X_MAPW; break;
			case X_INFO:  m->op = X_INFO; break;
			default:
				perr(PFE, 0, "Internal error? io->vreq->op = "
					"%d\n", io->vreq->op);
		}
		if (m->op == X_INFO) {
			ret = xseg_submit(xseg, vlmcd->bportno, io->mreq);
			always_assert(ret != NoSerial);
			always_assert(xseg_signal(xseg, vlmcd->bportno) == 0);
		}
		else {
			ret = xseg_submit(xseg, vlmcd->mportno, io->mreq);
			always_assert(ret != NoSerial);
			always_assert(xseg_signal(xseg, vlmcd->mportno) == 0);
		}

		io->state = MAPPING;
		break;
	case MAPPING:
		/*
		 * Step 2. Issue block requests, one per segment
		 * in the reply from the mapper.
		 */
		/* FIXME */
		/* For every mapped segment, issue a request to blockd */
		/* FIXME: what if we run out of xseg requests? */
		always_assert(xreq == io->mreq);
		always_assert(!(xreq->state & XS_FAILED) && xreq->state & XS_SERVED); /* FIXME: This is too harsh */
		if (xreq->op == X_INFO) {
			*(off_t *)io->vreq->data = *(off_t *)io->mreq->data;
			io->vreq->state |= XS_SERVED;

			ret = xseg_respond(vlmcd->xseg, io->vreq->portno, io->vreq);
			always_assert(ret != NoSerial);
			ret = xseg_signal(vlmcd->xseg, io->vreq->portno);
			always_assert(ret == 0);
			io->state = CONCLUDED;
			always_assert(xseg_put_request(xseg, vportno, io->mreq) != NoSerial);
			free_io(vlmcd, io);
		} else {
			struct xseg_reply_map *mreply = (void *)io->mreq->data;
			always_assert(mreply->cnt > 0);
			//perr(PE, 0, "%llu %llu %llu mreply->target = %d\n", mreply->cnt, mreply->segs[0].size, mreply->segs[0].offset, mreply->segs[0].target[0]);

			io->breqs_len = mreply->cnt;
			io->breqs = calloc(io->breqs_len, sizeof(struct xseg_request *));
			always_assert(io->breqs);
			for (i = 0, pos = 0; i < mreply->cnt; i++) {
				uint64_t datalen, offset, targetlen;
				struct xseg_request *breq;

				datalen = mreply->segs[i].size;
				offset = mreply->segs[i].offset;
				targetlen = strlen(mreply->segs[i].target);

				breq = xseg_get_request(xseg, vportno);
				always_assert(breq);
				always_assert(datalen + targetlen <= breq->bufferlen);

				ret = xseg_prep_request(breq, targetlen, datalen);
				breq->datalen = datalen;
				breq->offset = offset;
				breq->size = datalen;
				breq->op = io->vreq->op;
				breq->priv = __idx_from_io(vlmcd, io); /* use the io's idx for tracking */
				strncpy(breq->target, mreply->segs[i].target, targetlen);
				/*
				 * Get the blocker to place data directly into vreq's
				 * buffer. FIXME: Manipulate ->data by hand?
				 */
				breq->data = io->vreq->data + pos;
				pos += datalen;

				ret = xseg_submit(xseg, vlmcd->bportno, breq);
				always_assert(ret != NoSerial);
				/* possible race? */
				io->breqs[i] = breq;
				always_assert(xseg_signal(xseg, vlmcd->bportno) == 0);
			}
			io->breq_cnt = i;
			ret = xseg_put_request(xseg, vportno, io->mreq);
			always_assert(ret == 0);

			io->state = SERVING;
		}
		break;
	case SERVING:
		/*
		 * One of the breqs has been completed.
		 * Update io and vreq counters, complete vreq when
		 * all of the data have arrived.
		 */
#if VLMCD_SANITY_CHECKS
		for (i = 0; i < io->breqs_len; i++)
			if (io->breqs[i] == xreq)
				break;
		if (i >= io->breqs_len) {
			perr(PE, 0, "Called for xreq = %p, not belonging to io %p",
				(void *)xreq, (void *)io);
			always_assert(0);
			/* FIXME: how do I handle this? */
		}
#endif
		struct xseg_request *breq = xreq;
		always_assert(!(breq->state & XS_FAILED) && breq->state & XS_SERVED);
		always_assert(breq->serviced == breq->size);
		io->vreq->serviced += breq->serviced;
		ret = xseg_put_request(xseg, vportno, breq);
		always_assert(ret == 0);
		
		if (--io->breq_cnt == 0) {
			always_assert(io->vreq->serviced == io->vreq->datalen);
			complete(vlmcd, io);
			io->state = CONCLUDED;
			free_io(vlmcd, io);
		}
		break;
	case CONCLUDED:
		perr(PFE, 0, "Internal error, called for CONCLUDED");
		break;
	default:
		perr(PFE, 0, "Internal error, io->state = %d\n", io->state);
	}

	return 0;
}

static int vlmcd_loop(struct vlmcd *vlmcd)
{
	int ret;
	struct io *io;
	struct xseg_request *xreq;
	struct xseg *xseg = vlmcd->xseg;
	uint32_t vportno = vlmcd->vportno;

	always_assert(xseg);

	for (;;) {
		ret = xseg_prepare_wait(xseg, vportno);
		always_assert(ret == 0);

		io = NULL;
		/*
		 * Accept requests from xseg if under the nr_ops limit,
		 * and check if any replies have been received.
		 *
		 * Use ->priv for tracking, retrieve the relevant io struct
		 * we reply upon our peers to not have touched -> priv
		 */
		if (vlmcd->flying < vlmcd->nr_ops &&
                    (xreq = xseg_accept(xseg, vportno))) {
			io = alloc_io(vlmcd);
			io->vreq = xreq;
			io->state = ACCEPTED;
		} else {
			xreq = xseg_receive(xseg, vportno);
			if (xreq) {
				io = __io_from_idx(vlmcd, xreq->priv);
				always_assert(io);
				always_assert(io->state != CONCLUDED);
			}
		}

		/* io is the pending io currently being processed */
		if (io) {
			/* FIXME: WHY cancel_wait() anyway? */
			ret = xseg_cancel_wait(xseg, vportno);
			always_assert(ret == 0);
			dispatch(vlmcd, io, xreq);
		} else {
			/*
 			 * If things are OK, no timeout should ever be needed.
 			 * Otherwise, it's a vlmcd or xseg bug.
			 * FIXME: sigtimedwait() with zero-valued timeout?
			 * FAIL.
 			 */
			xseg_wait_signal(xseg, 100000UL);
		}
	}

	return 0;
}

/*
 * FIXME: Initialize the vlmcd struct based on cmdline_* vars
 */
static int vlmcd_init(struct vlmcd *vlmcd)
{
	int ret;

	vlmcd->vportno = cmdline_vportno;
	vlmcd->mportno = cmdline_mportno;
	vlmcd->bportno = cmdline_bportno;

	vlmcd->flying = 0;
	vlmcd->nr_ops = cmdline_nr_ops;
	vlmcd->ios = calloc(vlmcd->nr_ops, sizeof(struct io));
	if (!vlmcd->ios) {
		perr(PE, 0, "could not allocate memory [ios]");
		ret = -ENOMEM;
		goto out;
	}

	/* FIXME: meaning of arguments to xq_alloc_seq()? */
	if (!xq_alloc_seq(&vlmcd->free_ios, cmdline_nr_ops, cmdline_nr_ops)) {
		perr(PE, 0, "could not allocate memory [free_ios]");
		ret = -ENOMEM;
		goto out_with_ios;
	}

	/* FIXME: If xseg library fails, is errno set? */
	if (xseg_initialize()) {
		perr(PE, 0, "could not initialize xseg library");
		ret = -EIO;
		goto out_with_freeios;
	}

	if (! (vlmcd->xseg = join_or_create(cmdline_xseg_spec))) {
		perr(PE, 0, "could not join or create xseg with spec '%s'\n",
			cmdline_xseg_spec);
		ret = -EIO;
		goto out_with_xseginit;
	}

	if (! (vlmcd->vport = xseg_bind_port(vlmcd->xseg, vlmcd->vportno))) {
		perr(PE, 0, "cannot bind to xseg port %ld", (long)vlmcd->vportno);
		ret = -EIO;
		goto out_with_xsegjoin;
	}

	vlmcd->vportno = xseg_portno(vlmcd->xseg, vlmcd->vport);
	
	perr(PI, 0, "vlmcd on port %u of %u",
		vlmcd->vportno, vlmcd->xseg->config.nr_ports);

	ret = 0;
	goto out;

out_with_xsegjoin:
	xseg_leave(vlmcd->xseg);
out_with_xseginit:
	always_assert(xseg_finalize() == 0);
out_with_freeios:
	xq_free(&vlmcd->free_ios);
out_with_ios:
	free(vlmcd->ios);
out:
	return ret;
}

int main(int argc, char *argv[])
{
	struct vlmcd vlmc;

	init_perr("vlmcd");
	parse_cmdline(argc, argv);

	perr(PI, 0, "v = %ld, m = %ld, b = %ld, nr_ops = %lu\n",
		cmdline_vportno, cmdline_mportno, cmdline_bportno, cmdline_nr_ops);

	if (vlmcd_init(&vlmc) < 0)
		perr(PFE, 0, "failed to initialize vlmcd");

	return vlmcd_loop(&vlmc);
}
