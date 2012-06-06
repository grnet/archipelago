#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <xseg/xseg.h>
#include <util_libs/user/sos/sos.h>
#include <sys/time.h>

#include <signal.h>
#include <sys/syscall.h>

/* maybe add this to store struct */
#define objsize (4*1024*1024)
#define MAX_VOL_NAME 242

static int usage(void)
{
	printf("Usage: ./sosd <path_to_disk_image> [options]\n"
		"Options: [-p portno]\n"
		"         [-g type:name:nr_ports:nr_requests:request_size:extra_size:page_shift]\n"
		"         [-n nr_parallel_ops]\n");
	return 1;
}

struct io {
	struct xseg_request *req;
	ssize_t retval;
	struct sos_request sos_req;
	char objname[MAX_VOL_NAME +1 + 12 + 1];
	struct timeval start;
};

struct store {
	struct xseg *xseg;
	struct xseg_port *xport;
	uint32_t portno;
	int fd;
	uint64_t size;
	struct io *ios;
	struct xq free_ops;
	char *free_bufs;
	struct xq resubmit_ops;
	char *resubmit_bufs;
	long nr_ops;
	sos_handle_t sos;
	pid_t pid;
	sigset_t signal_set;
};

static unsigned int verbose;

static void sigaction_handler(int sig, siginfo_t *siginfo, void *arg)
{
	return;
}

static void signal_self(struct store *store)
{
	union sigval sigval = {0};
	pid_t me = store->pid;
	if (sigqueue(me, SIGIO, sigval) < 0)
		perror("sigqueue");
}

static int wait_signal(struct store *store)
{
	int r;
	siginfo_t siginfo;
	struct timespec ts;
	uint32_t usec_timeout = 5000;

	ts.tv_sec = usec_timeout / 1000000;
	ts.tv_nsec = 1000 * (usec_timeout - ts.tv_sec * 1000000);

	r = sigtimedwait(&store->signal_set, &siginfo, &ts);
	if (r < 0)
		return r;

	return siginfo.si_signo;

}

static struct io *alloc_io(struct store *store)
{
	xqindex idx = xq_pop_head(&store->free_ops);
	if (idx == None)
		return NULL;
	return store->ios + idx;
}

static inline void free_io(struct store *store, struct io *io)
{
	xqindex idx = io - store->ios;
	io->req = NULL;
	xq_append_head(&store->free_ops, idx);
	/* not the right place. sosd_loop couldn't sleep because of that
	 * needed for flush support. maybe this should go to complete function
	 *
	signal_self(store);
	*/
}

static void resubmit_io(struct store *store, struct io *io)
{
	xqindex idx = io - store->ios;
	xq_append_tail(&store->resubmit_ops, idx);
}

static struct io* get_resubmitted_io(struct store *store)
{
	xqindex idx = xq_pop_head(&store->resubmit_ops);
	if (idx == None)
		return NULL;
	return store->ios + idx;
}

static void log_io(char *msg, struct io *io)
{
	char target[64], data[64];
	/* null terminate name in case of req->target is less than 63 characters,
	 * and next character after name (aka first byte of next buffer) is not
	 * null
	 */
	unsigned int end = (io->req->targetlen> 63) ? 63 : io->req->targetlen;
	if (verbose) {
		strncpy(target, io->req->target, end);
		target[end] = 0;
		strncpy(data, io->req->data, 63);
		data[63] = 0;
		printf("%s: sos req id:%u, op:%u %llu:%lu serviced: %lu, retval: %lu, reqstate: %u\n"
				"target[%u]:'%s', data[%llu]:\n%s------------------\n\n",
				msg,
				(unsigned int)io->sos_req.id,
				(unsigned int)io->req->op,
				(unsigned long long)io->sos_req.offset,
				(unsigned long)io->sos_req.size,
				(unsigned long)io->req->serviced,
				(unsigned long)io->retval,
				(unsigned int)io->req->state,
				(unsigned int)io->req->targetlen, target,
				(unsigned long long)io->req->datalen, data);
	}
}

static void complete(struct store *store, struct io *io)
{
	struct xseg_request *req = io->req;
	/*
	struct timeval end;
	unsigned long us;
	gettimeofday(&end, NULL);
	timersub(&end, &io->start, &end);
	us = end.tv_sec*1000000 +end.tv_usec;
	printf("sosd: Request %lu completed after %lu us\n", io->sos_req.id, us);
	*/

	req->state |= XS_SERVED;
	log_io("complete", io);
	xseg_respond(store->xseg, req->portno, req);
	xseg_signal(store->xseg, req->portno);
	free_io(store, io);
}

static void fail(struct store *store, struct io *io)
{
	struct xseg_request *req = io->req;
	req->state |= XS_FAILED;
	log_io("fail", io);
	xseg_respond(store->xseg, req->portno, req);
	xseg_signal(store->xseg, req->portno);
	free_io(store, io);
}

static void pending(struct store *store, struct io *io)
{
	io->req->state = XS_PENDING;
}

static void handle_unknown(struct store *store, struct io *io)
{
	struct xseg_request *req = io->req;
	snprintf(req->data, req->datalen, "unknown request op");
	fail(store, io);
}

static int32_t get_sos_op(uint32_t xseg_op)
{
	switch (xseg_op) {
	case X_READ:
		return S_READ;
	case X_WRITE:
		return S_WRITE;
	default:
		return S_NONE;
	}
}

static uint32_t get_sos_flags(uint32_t xseg_flags)
{
	uint32_t flags = 0;
	if (xseg_flags & XF_FLUSH) {
		flags |= SF_FLUSH;
	}
	if (xseg_flags & XF_FUA) {
		flags |= SF_FUA;
	}
	return flags;
}

static int calculate_sosreq(struct xseg_request *xseg_req, struct sos_request *sos_req)
{
	unsigned int suffix;
	int r;
	char *buf;

	/* get object name from offset in volume */
	buf = sos_req->target;
	suffix = (unsigned int) ((xseg_req->offset+xseg_req->serviced) / (uint64_t)objsize) ;
//	printf("suffix: %u\n", suffix);
	if (xseg_req->targetlen> MAX_VOL_NAME){
		printf("xseg_req targetlen > MAX_VOL_NAME\n");
		return -1;
	}
	strncpy(buf, xseg_req->target, xseg_req->targetlen);
	buf[xseg_req->targetlen] = '_';
	r = snprintf(buf+xseg_req->targetlen+1, 13, "%012u", suffix);
	if (r >= 13)
		return -1;

	//sos_req->target = buf;
	sos_req->targetlen = xseg_req->targetlen+1+12;

	/* offset should be set to offset in object */
	sos_req->offset = (xseg_req->offset + xseg_req->serviced) % objsize;
	/* sos_req offset + sos_req size  < objsize always
	 * request data up to the end of object.
	 */
	sos_req->size = (xseg_req->datalen - xseg_req->serviced) ;  /* should this be xseg_req->size ? */
	if (sos_req->size > objsize - sos_req->offset)
		sos_req->size = objsize - sos_req->offset;
	/* this should have been checked before this call */
	if (xseg_req->serviced < xseg_req->datalen)
		sos_req->data = xseg_req->data + xseg_req->serviced;
	else
		return -1;
//	printf("name: %s, size: %lu, offset: %lu, data:%s\n", sos_req->target, 
//			sos_req->size, sos_req->offset, sos_req->data);
	return 0;
}

static void prepare_sosreq(struct store *store, struct io *io)
{
	struct xseg_request *xseg_req = io->req;
	struct sos_request *sos_req = &io->sos_req;
	sos_req->flags = get_sos_flags(xseg_req->flags);
	sos_req->state = S_PENDING;
	sos_req->retval = 0;
	sos_req->op = get_sos_op(xseg_req->op);
	sos_req->priv = store;
	sos_req->target = io->objname;
}

static inline void prepare_io(struct store *store, struct io *io)
{
	prepare_sosreq(store, io);
	/* Assign io id to sos_req id. This can be done as an initialization of
	 * ios, to avoid reseting it every time */
	io->sos_req.id = io - store->ios;
}


static void handle_resubmit(struct store *store, struct io *io);

static void complete_rw(struct store *store, struct io *io)
{
	int r;
	struct xseg_request *req = io->req;
	struct sos_request *sos_req = &io->sos_req;
	if (req->state == XS_ACCEPTED) {
		/* should not happen */
		fail(store, io);
		return;
	}
	if (io->retval > 0)
		req->serviced += io->retval;
	else if (io->retval == 0) {
		/* reached end of object. zero out rest of data
		 * requested from this object
		 */ 
		memset(sos_req->data, 0, sos_req->size);
		req->serviced += sos_req->size;
	}
	else if (io->retval == -2) {
		/* object not found. return zeros instead */
		memset(sos_req->data, 0, sos_req->size);
		req->serviced += sos_req->size;
	}
	else {
		/* io->retval < 0 */
		fail(store, io);
		return;
	}
	/* request completed ? */
	if (req->serviced >= req->datalen) {
		complete(store, io);
		return;
	}

	if (req != io->req)
		printf("0.%p vs %p!\n", (void *)req, (void *)io->req);
	if (!req->size) {
		/* should not happen */
		fail(store, io);
		return;
	}

	switch (req->op) {
	case X_READ:
	case X_WRITE:
		log_io("resubmitting", io);
		resubmit_io(store, io);
		signal_self(store);
		break;
	default:
		snprintf(req->data, req->datalen,
			 "wtf, corrupt op %u?\n", req->op);
		fail(store, io);
		return;
	}
}

static void handle_read_write(struct store *store, struct io *io)
{
	int r;
	struct xseg_request *req = io->req;
	struct sos_request *sos_req = &io->sos_req;
	struct io *resubmit_io;

	if (req != io->req)
		printf("0.%p vs %p!\n", (void *)req, (void *)io->req);

	prepare_io(store, io);
	if (!req->size) {
		if (req->flags & XF_FLUSH) {
#if 0
			/* note that with FLUSH/size == 0 
			 * there will probably be a (uint64_t)-1 offset */

			/* size must be zero */
			sos_req->size = 0;
			/* all these should be irrelevant on a flush request */
			sos_req->target = 0;
			sos_req->targetlen= 0;
			sos_req->data = 0;
			sos_req->offset = 0;
			/* philipgian:
			 * make sure all pending requests are completed and then
			 * perform flush request to flush them to disk.
			 */
			while (xq_size(&store->free_ops) != store->nr_ops){
				wait_signal(store);
				/* handle any possible resubmissions */
				resubmit_io = get_resubmitted_io(store);
				while (resubmit_io){
					handle_resubmit(store, resubmit_io);
					resubmit_io = get_resubmitted_io(store);
				}
			}
			r = sos_submit(store->sos, sos_req);
			if (r < 0) 
				fail(store,io);
			else {
				complete(store, io);
			}
			return;
		} else {
			complete(store, io);
			return;
		}
#else
			complete(store, io);
			return;
		}
#endif
	}
	r = calculate_sosreq(req, sos_req);	
	if (r < 0 ) {
		fail(store, io);
		return;
	}

	switch (req->op) {
	case X_READ:
	case X_WRITE:
		//log_io("submit", io);
		pending(store, io);
		r = sos_submit(store->sos, sos_req);
		break;
	default:
		snprintf(req->data, req->datalen,
			 "wtf, corrupt op %u?\n", req->op);
		fail(store, io);
		return;
	}

	if (r) {
		strerror_r(errno, req->data, req->datalen);
		fail(store, io);
		return;
	}
}

static void handle_returned(struct store *store, struct io *io)
{
	io->retval = io->sos_req.retval;
	switch (io->req->op){
		case X_READ:
		case X_WRITE:
			complete_rw(store, io);
			break;
		default:
			if (io->sos_req.state & S_FAILED)
				fail(store, io);
			else
				complete(store, io);
	}	
}

/* this is safe for now, as long as callback is only called once.
 * if callback gets called, then sos_request has been completed and no race
 * conditions occur.
 */
static int sos_cb(struct sos_request *sos_req, unsigned long event)
{
	struct store *store = (struct store *) sos_req->priv;
	struct io *io = (struct io*) store->ios + sos_req->id;

	if (event == S_NOTIFY_FAIL){
		sos_req->state = S_FAILED;
	}
	else if (event == S_NOTIFY_ACK) {
		sos_req->state = S_ACKED;
	}
	else if (event == S_NOTIFY_COMMIT){
		sos_req->state = S_COMMITED;
	}
	handle_returned(store, io);
	return 1;
}

static void handle_info(struct store *store, struct io *io)
{
	struct xseg_request *req = io->req;

	*((uint64_t *) req->data) = store->size;
	req->serviced = req->datalen = sizeof(store->size);
	io->retval = req->datalen;

	complete(store, io);
}

static void dispatch(struct store *store, struct io *io)
{
	switch (io->req->op) {
	case X_READ:
	case X_WRITE:
		handle_read_write(store, io); break;
	case X_INFO:
		handle_info(store, io); break;
	case X_SYNC:
	default:
		handle_unknown(store, io);
	}
}

static void handle_resubmit(struct store *store, struct io *io)
{
	dispatch(store, io);
}

static void handle_accepted(struct store *store, struct io *io)
{
	struct xseg_request *req = io->req;
	req->serviced = 0;
	req->state = XS_ACCEPTED;
	io->retval = 0;
	//log_io("accepted", io);
	gettimeofday(&io->start, NULL);
	dispatch(store, io);
}

static int sosd_loop(struct store *store)
{
	struct xseg *xseg = store->xseg;
	uint32_t portno = store->portno;
	struct io *io, *resubmit_io;
	struct xseg_request *accepted;

	for (;;) {
		accepted = NULL;
		xseg_prepare_wait(xseg, portno);
		io = alloc_io(store);
		if (io) {
			accepted = xseg_accept(xseg, portno);
			if (accepted) {
				xseg_cancel_wait(xseg, portno);
				io->req = accepted;
				handle_accepted(store, io);
			} else
				free_io(store, io);
		}
		resubmit_io = get_resubmitted_io(store);
		if (resubmit_io){
			xseg_cancel_wait(xseg, portno);
			handle_resubmit(store, resubmit_io);
		}
		if (!accepted && !resubmit_io) 
			xseg_wait_signal(xseg, 10000);
	}

	return 0;
}

static struct xseg *join(char *spec)
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

static int sosd(char *path, unsigned long size, uint32_t nr_ops,
		  char *spec, long portno)
{
	struct store *store;

	store = malloc(sizeof(struct store));
	if (!store) {
		perror("malloc");
		return -1;
	}

	store->sos = sos_init(sos_cb);
	if (!store->sos) {
		fprintf(stderr, "SOS init failed\n");
		return -1;
	}

	/*
	r = daemon(1, 1);
	if (r < 0)
		return r;
		*/

	store->pid = syscall(SYS_gettid);

	// just a temp solution. 
	// Make all images 20GB. Maybe use an image header object for a more
	// permantent solution.
	store->size=20*1024*1024;

	if (sigemptyset(&store->signal_set))
		perror("sigemptyset");

	if (sigaddset(&store->signal_set, SIGIO))
		perror("sigaddset");


	store->nr_ops = nr_ops;
	store->free_bufs = calloc(nr_ops, sizeof(xqindex));
	if (!store->free_bufs)
		goto malloc_fail;

	store->resubmit_bufs = calloc(nr_ops, sizeof(xqindex));
	if (!store->resubmit_bufs)
		goto malloc_fail;

	store->ios = calloc(nr_ops, sizeof(struct io));
	if (!store->ios) {
malloc_fail:
		perror("malloc");
		return -1;
	}

	xq_init_seq(&store->free_ops, nr_ops, nr_ops, store->free_bufs);
	xq_init_empty(&store->resubmit_ops, nr_ops, store->resubmit_bufs);


	if (xseg_initialize()) {
		printf("cannot initialize library\n");
		return -1;
	}
	store->xseg = join(spec);
	if (!store->xseg)
		return -1;

	store->xport = xseg_bind_port(store->xseg, portno);
 	if (!store->xport) {
		printf("cannot bind to port %ld\n", portno);
		return -1;
	}

	store->portno = xseg_portno(store->xseg, store->xport);
	printf("sosd on port %u/%u\n",
		store->portno, store->xseg->config.nr_ports);
	
	return sosd_loop(store);
}

int main(int argc, char **argv)
{
	char *path, *spec = "";
	unsigned long size;
	int i;
	long portno;
	uint32_t nr_ops;
	unsigned int debug_level = 0;

	if (argc < 2)
		return usage();

	path = argv[1];
	size = 0;
	portno = -1;
	nr_ops = 0;

	for (i = 2; i < argc; i++) {
		if (!strcmp(argv[i], "-g") && i + 1 < argc) {
			spec = argv[i+1];
			i += 1;
			continue;
		}

		if (!strcmp(argv[i], "-p") && i + 1 < argc) {
			portno = strtoul(argv[i+1], NULL, 10);
			i += 1;
			continue;
		}

		if (!strcmp(argv[i], "-p") && i + 1 < argc) {
			nr_ops = strtoul(argv[i+1], NULL, 10);
			i += 1;
			continue;
		}
		if (!strcmp(argv[i], "-v") ) {
			debug_level++;
			continue;
		}
	}

	sos_set_debug_level(debug_level);
	verbose = debug_level;

	if (nr_ops <= 0)
		nr_ops = 16;

	return sosd(path, size, nr_ops, spec, portno);
}

