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

#include <xseg/xseg.h>

#define TARGET_NAMELEN 128

static int usage(void)
{
	printf("Usage: ./blockd <path_to_disk_image> [options]\n"
		"Options: [-p portno]\n"
		"         [-s image size in bytes]\n"
		"         [-g type:name:nr_ports:nr_requests:request_size:extra_size:page_shift]\n"
		"         [-n nr_parallel_ops]\n"
		"         [-v]\n");
	return 1;
}

struct io {
	struct aiocb cb;
	struct xseg_request *req;
	ssize_t retval;
};

struct store {
	struct xseg *xseg;
	struct xseg_port *xport;
	uint32_t portno;
	int fd;
	char name[TARGET_NAMELEN];
	uint32_t namesize;
	uint64_t size;
	struct io *ios;
	struct xq free_ops;
	char *free_bufs;
	struct xq pending_ops;
	char *pending_bufs;
	long nr_ops;
	struct sigevent sigevent;
};

static unsigned verbose;
static unsigned long sigaction_count;

static void sigaction_handler(int sig, siginfo_t *siginfo, void *arg)
{
	sigaction_count ++;
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
}

static inline void pending_io(struct store *store, struct io *io)
{
	xqindex idx = io - store->ios;
	xq_append_tail(&store->pending_ops, idx);
}

static inline struct io *get_pending_io(struct store *store)
{
	xqindex idx = xq_pop_head(&store->pending_ops);
	if (idx == None)
		return NULL;
	return store->ios + idx;
}

static void log_io(char *msg, struct io *io)
{
	char name[64], data[64];
	/* null terminate name in case of req->name is less than 63 characters,
	 * and next character after name (aka first byte of next buffer) is not
	 * null
	 */
	unsigned int end = (io->req->namesize > 63) ? 63 : io->req->namesize;
	strncpy(name, io->req->name, end);
	name[end] = 0;
	strncpy(data, io->req->data, 63);
	data[63] = 0;
	printf("%s: fd:%u, op:%u %llu:%lu retval: %lu, reqstate: %u\n"
		"name[%u]:'%s', data[%llu]:\n%s------------------\n\n",
		msg,
		(unsigned int)io->cb.aio_fildes,
		(unsigned int)io->req->op,
		(unsigned long long)io->cb.aio_offset,
		(unsigned long)io->cb.aio_nbytes,
		(unsigned long)io->retval,
		(unsigned int)io->req->state,
		(unsigned int)io->req->namesize, name,
		(unsigned long long)io->req->datasize, data);
}

static void complete(struct store *store, struct io *io)
{
	struct xseg_request *req = io->req;
	req->state |= XS_SERVED;
	if (verbose)
		log_io("complete", io);
	xseg_respond(store->xseg, req->portno, req);
	xseg_signal(store->xseg, req->portno);
	free_io(store, io);
}

static void fail(struct store *store, struct io *io)
{
	struct xseg_request *req = io->req;
	req->state |= XS_FAILED;
	if (verbose)
		log_io("fail", io);
	xseg_respond(store->xseg, req->portno, req);
	xseg_signal(store->xseg, req->portno);
	free_io(store, io);
}

static void pending(struct store *store, struct io *io)
{
	if (verbose)
		log_io("pending", io);
	io->req->state = XS_PENDING;
	pending_io(store, io);
}

static void handle_unknown(struct store *store, struct io *io)
{
	struct xseg_request *req = io->req;
	snprintf(req->data, req->datasize, "unknown request op");
	fail(store, io);
}

static inline void prepare_io(struct store *store, struct io *io)
{
	io->cb.aio_fildes = store->fd;
	io->cb.aio_sigevent = store->sigevent;
	/* cb->aio_sigevent.sigev_value.sival_int = fd; */
}

static void handle_read_write(struct store *store, struct io *io)
{
	int r;
	struct xseg_request *req = io->req;
	struct aiocb *cb = &io->cb;

	if (req->state != XS_ACCEPTED) {
		if (io->retval > 0)
			req->serviced += io->retval;
		else
			req->datasize = req->serviced;

		if (req->serviced >= req->datasize) {
			complete(store, io);
			return;
		}
	}

	if (req != io->req)
		printf("0.%p vs %p!\n", (void *)req, (void *)io->req);
	if (!req->size) {
		if (req->flags & (XF_FLUSH | XF_FUA)) {
			/* for now, no FLUSH/FUA support.
			 * note that with FLUSH/size == 0 
			 * there will probably be a (uint64_t)-1 offset */
			complete(store, io);
			return;
		} else {
			complete(store, io);
			return;
		}
	}

	prepare_io(store, io);
	cb->aio_buf = req->data + req->serviced;
	cb->aio_nbytes = req->datasize - req->serviced;
	cb->aio_offset = req->offset + req->serviced;

	switch (req->op) {
	case X_READ:
		r = aio_read(cb);
		break;
	case X_WRITE:
		r = aio_write(cb);
		break;
	default:
		snprintf(req->data, req->datasize,
			 "wtf, corrupt op %u?\n", req->op);
		fail(store, io);
		return;
	}

	if (r) {
		strerror_r(errno, req->data, req->datasize);
		fail(store, io);
		return;
	}

	pending(store, io);
}

static void handle_info(struct store *store, struct io *io)
{
	struct xseg_request *req = io->req;
	struct stat stat;
	int r;
	off_t size;

	if (req->namesize != store->namesize ||
		strncmp(req->name, store->name, store->namesize)) {

		fail(store, io);
		return;
	}

	r = fstat(store->fd, &stat);
	if (r < 0) {
		perror("fstat");
		fail(store, io);
		return;
	}

	size = stat.st_size;
	*((uint64_t *) req->data) = store->size;

	req->serviced = req->datasize = sizeof(store->size);
	io->retval = io->cb.aio_offset = io->cb.aio_nbytes = req->datasize;

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

static void handle_pending(struct store *store, struct io *io)
{
	int r = aio_error(&io->cb);
	if (r == EINPROGRESS) {
		pending(store, io);
		return;
	}

	io->retval = aio_return(&io->cb);
	if (r) {
		fail(store, io);
		return;
	}

	dispatch(store, io);
}

static void handle_accepted(struct store *store, struct io *io)
{
	struct xseg_request *req = io->req;
	req->serviced = 0;
	req->state = XS_ACCEPTED;
	io->retval = 0;
	dispatch(store, io);
}

static int blockd_loop(struct store *store)
{
	struct xseg *xseg = store->xseg;
	uint32_t portno = store->portno;
	struct io *io;
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

		io = get_pending_io(store);
		if (io) {
			xseg_cancel_wait(xseg, portno);
			handle_pending(store, io);
		}

		if (!io && !accepted) 
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

static int blockd(char *path, off_t size, uint32_t nr_ops,
		  char *spec, long portno)
{
	struct stat stat;
	struct sigaction sa;
	struct store *store;
	int r;

	store = malloc(sizeof(struct store));
	if (!store) {
		perror("malloc");
		return -1;
	}

	strncpy(store->name, path, TARGET_NAMELEN);
	store->name[TARGET_NAMELEN - 1] = '\0';
	store->namesize = strlen(store->name);

	store->fd = open(path, O_RDWR);
	while (store->fd < 0) {
		if (errno == ENOENT && size)
			store->fd = open(path, O_RDWR | O_CREAT, 0600);
			if (store->fd >= 0)
				break;
		perror(path);
		return store->fd;
	}
	
	if (size == 0) {
		r = fstat(store->fd, &stat);
		if (r < 0) {
			perror(path);
			return r;
		}
		size = (uint64_t) stat.st_size;
		if (size == 0) {
			fprintf(stderr, "size cannot be zero\n");
			return -1;
		}
	}

	lseek(store->fd, size-1, SEEK_SET);
	if (write(store->fd, &r, 1) != 1) {
		perror("write");
		return -1;
	}

	store->size = size;

	/*
	r = daemon(1, 1);
	if (r < 0)
		return r;
		*/

	store->sigevent.sigev_notify = SIGEV_SIGNAL;
	store->sigevent.sigev_signo = SIGIO;
	sa.sa_sigaction = sigaction_handler;
	sa.sa_flags = SA_SIGINFO;
	if (sigemptyset(&sa.sa_mask))
		perror("sigemptyset");

	if (sigaction(SIGIO, &sa, NULL)) {
		perror("sigaction");
		return -1;
	}

	store->nr_ops = nr_ops;
	store->free_bufs = calloc(nr_ops, sizeof(xqindex));
	if (!store->free_bufs)
		goto malloc_fail;

	store->pending_bufs = calloc(nr_ops, sizeof(xqindex));
	if (!store->pending_bufs)
		goto malloc_fail;

	store->ios = calloc(nr_ops, sizeof(struct io));
	if (!store->ios) {
malloc_fail:
		perror("malloc");
		return -1;
	}

	xq_init_seq(&store->free_ops, nr_ops, nr_ops, store->free_bufs);
	xq_init_empty(&store->pending_ops, nr_ops, store->pending_bufs);

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
	printf("blockd on port %u/%u\n",
		store->portno, store->xseg->config.nr_ports);

	return blockd_loop(store);
}

int main(int argc, char **argv)
{
	char *path, *spec = "";
	uint64_t size;
	int i;
	long portno;
	uint32_t nr_ops;

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

		if (!strcmp(argv[i], "-s") && i + 1 < argc) {
			size = strtoull(argv[i+1], NULL, 10);
			i += 1;
			continue;
		}

		if (!strcmp(argv[i], "-p") && i + 1 < argc) {
			portno = strtoul(argv[i+1], NULL, 10);
			i += 1;
			continue;
		}

		if (!strcmp(argv[i], "-n") && i + 1 < argc) {
			nr_ops = strtoul(argv[i+1], NULL, 10);
			i += 1;
			continue;
		}

		if (!strcmp(argv[i], "-v")) {
			verbose = 1;
			continue;
		}
	}

	if (nr_ops <= 0)
		nr_ops = 16;

	return blockd(path, size, nr_ops, spec, portno);
}

