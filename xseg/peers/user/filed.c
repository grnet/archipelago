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

#define MAX_PATH_SIZE 255
#define MAX_FILENAME_SIZE 255

static int usage(void)
{
	printf("Usage: ./filed <path_to_directory> [options]\n"
		"Options: [-p portno]\n"
		"         [-g type:name:nr_ports:nr_requests:request_size:extra_size:page_shift]\n"
		"         [-n nr_parallel_ops]\n"
		"         [-v]\n");
	return 1;
}

struct fsync_io {
	unsigned long cacheidx;
	int fd;
	uint64_t time;
};

struct io {
	struct store *store;
	struct xseg_request *req;
	ssize_t retval;
	long fdcacheidx;
	pthread_cond_t cond;
	pthread_mutex_t lock;
};

#define READY (1 << 1)

struct fdcache_node {
	volatile int fd;
	volatile unsigned int ref;
	volatile unsigned long time;
	volatile unsigned int flags;
	pthread_cond_t cond;
	char target[MAX_FILENAME_SIZE + 1];
};

struct store {
	struct xseg *xseg;
	struct xseg_port *xport;
	uint32_t portno;
	uint64_t size;
	struct io *ios;
	struct xq free_ops;
	char *free_bufs;
	long nr_ops;
	struct sigevent sigevent;
	int dirfd;
	uint32_t path_len;
	uint64_t handled_reqs;
	unsigned long maxfds;
	struct fdcache_node *fdcache;
	pthread_t *iothread;
	pthread_mutex_t cache_lock;
	char path[MAX_PATH_SIZE + 1];
};

static unsigned verbose;

static unsigned long sigaction_count;

static void sigaction_handler(int sig, siginfo_t *siginfo, void *arg)
{
	sigaction_count++;
}

static void log_io(char *msg, struct io *io)
{
	char target[64], data[64];
	/* null terminate name in case of req->target is less than 63 characters,
	 * and next character after name (aka first byte of next buffer) is not
	 * null
	 */
	unsigned int end = (io->req->targetlen> 63) ? 63 : io->req->targetlen;
	strncpy(target, io->req->target, end);
	target[end] = 0;
	strncpy(data, io->req->data, 63);
	data[63] = 0;

	fprintf(stderr,
		"%s: fd:%u, op:%u offset: %llu size: %lu retval: %lu, reqstate: %u\n"
		"target[%u]: '%s', data[%llu]:\n%s------------------\n\n",
		msg,
		(unsigned int)io->fdcacheidx, //this is cacheidx not fd
		(unsigned int)io->req->op,
		(unsigned long long)io->req->offset,
		(unsigned long)io->req->size,
		(unsigned long)io->retval,
		(unsigned int)io->req->state,
		(unsigned int)io->req->targetlen, target,
		(unsigned long long)io->req->datalen, data);
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


static void complete(struct store *store, struct io *io)
{
	struct xseg_request *req = io->req;
	req->state |= XS_SERVED;
	if (verbose)
		log_io("complete", io);
	xseg_respond(store->xseg, req->portno, req);
	xseg_signal(store->xseg, req->portno);
	__sync_fetch_and_sub(&store->fdcache[io->fdcacheidx].ref, 1);
}

static void fail(struct store *store, struct io *io)
{
	struct xseg_request *req = io->req;
	req->state |= XS_FAILED;
	if (verbose)
		log_io("fail", io);
	xseg_respond(store->xseg, req->portno, req);
	xseg_signal(store->xseg, req->portno);
	if (io->fdcacheidx >= 0) {
		__sync_fetch_and_sub(&store->fdcache[io->fdcacheidx].ref, 1);
	}
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

static inline void prepare_io(struct store *store, struct io *io)
{
}


static int dir_open(	struct store *store, struct io *io,
			char *target, uint32_t targetlen, int mode	)
{
	int fd = -1, r;
	struct fdcache_node *ce = NULL;
	long i, lru;
	uint64_t min;
	io->fdcacheidx = -1;
	if (targetlen> MAX_FILENAME_SIZE)
		goto out_err;

start:
	/* check cache */
	pthread_mutex_lock(&store->cache_lock);
start_locked:
	lru = -1;
	min = UINT64_MAX;
	for (i = 0; i < store->maxfds; i++) {
		if (store->fdcache[i].ref == 0 && min > store->fdcache[i].time 
				&& (store->fdcache[i].flags & READY)) {
			min = store->fdcache[i].time;
			lru = i;

		}
		if (!strncmp(store->fdcache[i].target, target, targetlen)) {
			if (store->fdcache[i].target[targetlen] == 0) {
				ce = &store->fdcache[i];
				/* if any other io thread is currently opening
				 * the file, block until it succeeds or fails
				 */
				if (!(ce->flags & READY)) {
					pthread_cond_wait(&ce->cond, &store->cache_lock);
					/* when ready, restart lookup */
					goto start_locked;
				}
				/* if successfully opened */
				if (ce->fd > 0) {
					fd = store->fdcache[i].fd;
					io->fdcacheidx = i;
					goto out;
				}
				/* else open failed for the other io thread, so
				 * it should fail for everyone waiting on this
				 * file.
				 */
				else {
					fd = -1;
					io->fdcacheidx = -1;
					goto out_err_unlock;
				}
			}
		}
	}
	if (lru < 0){
		/* all cache entries are currently being used */
		pthread_mutex_unlock(&store->cache_lock);
		goto start;
	}
	if (store->fdcache[lru].ref){
		fd = -1;
		printf("lru(%ld) ref not 0 (%u)\n", lru, store->fdcache[lru].ref);
		goto out_err_unlock;
	}
	/* make room for new file */
	ce = &store->fdcache[lru];
	/* set name here and state to not ready, for any other requests on the
	 * same target that may follow
	 */
	strncpy(ce->target, target, targetlen);
	ce->target[targetlen] = 0;
	ce->flags &= ~READY;
	pthread_mutex_unlock(&store->cache_lock);

	if (ce->fd >0){
		if (close(ce->fd) < 0){
			perror("close");
		}
	}
	fd = openat(store->dirfd, ce->target, O_RDWR);	
	if (fd < 0) {
		if (errno == ENOENT){
			fd = openat(store->dirfd, ce->target, 
					O_RDWR | O_CREAT, 0600);
			if (fd >= 0)
				goto new_entry;
		}
		perror(store->path);
		/* insert in cache a negative fd to indicate opening error to
		 * any other ios waiting for the file to open
		 */
	}	
	/* insert in cache */
new_entry:
	pthread_mutex_lock(&store->cache_lock);
	ce->fd = fd;
	ce->ref = 0;
	ce->flags = READY;
	pthread_cond_broadcast(&ce->cond);
	if (fd > 0) {
		io->fdcacheidx = lru;
	}
	else {
		io->fdcacheidx = -1;
		goto out_err_unlock;
	}

out:
	store->handled_reqs++;
	ce->time = store->handled_reqs;
	__sync_fetch_and_add(&ce->ref, 1);
	pthread_mutex_unlock(&store->cache_lock);
out_err:
	return fd;

out_err_unlock:
	pthread_mutex_unlock(&store->cache_lock);
	goto out_err;
}

static void handle_read_write(struct store *store, struct io *io)
{
	int r, fd, mode;
	struct xseg_request *req = io->req;

	if (req->op == X_WRITE)
		mode = 1;
	else
		mode = 0;
	fd = dir_open(store, io, req->target, req->targetlen, mode);
	if (fd < 0){
		perror("dir_open");
		fail(store, io);
		return;
	}

	if (req != io->req)
		printf("0.%p vs %p!\n", (void *)req, (void *)io->req);
	if (!req->size) {
		if (req->flags & (XF_FLUSH | XF_FUA)) {
			/* No FLUSH/FUA support yet (O_SYNC ?).
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

	switch (req->op) {
	case X_READ:
		while (req->serviced < req->datalen) {
			r = pread(fd, req->data + req->serviced, 
					req->datalen - req->serviced,
				       	req->offset + req->serviced);
			if (r < 0) {
				req->datalen = req->serviced;
				perror("pread");
			}
			else if (r == 0) {
				/* reached end of file. zero out the rest data buffer */
				memset(req->data + req->serviced, 0, req->datalen - req->serviced);
				req->serviced = req->datalen;
			}
			else {
				req->serviced += r;
			}
		}
		break;
	case X_WRITE:
		while (req->serviced < req->datalen) {
			r = pwrite(fd, req->data + req->serviced, 
					req->datalen - req->serviced,
				       	req->offset + req->serviced);
			if (r < 0) {
				req->datalen = req->serviced;
			}
			else if (r == 0) {
				/* reached end of file. zero out the rest data buffer */
				memset(req->data + req->serviced, 0, req->datalen - req->serviced);
				req->serviced = req->datalen;
			}
			else {
				req->serviced += r;
			}
		}
		r = fsync(fd);
		if (r< 0) {
			perror("fsync");
			/* if fsync fails, then no bytes serviced correctly */
			req->serviced = 0;
		}
		break;
	default:
		snprintf(req->data, req->datalen,
			 "wtf, corrupt op %u?\n", req->op);
		fail(store, io);
		return;
	}

	if (req->serviced > 0 ) {
		complete(store, io);
	}
	else {
		strerror_r(errno, req->data, req->datalen);
		fail(store, io);
	}
	return;
}

static void handle_info(struct store *store, struct io *io)
{
	struct xseg_request *req = io->req;
	struct stat stat;
	int fd, r;
	off_t size;

	fd = dir_open(store, io, req->target, req->targetlen, 0);
	if (fd < 0) {
		fail(store, io);
		return;
	}
	r = fstat(fd, &stat);
	if (r < 0) {
		perror("fstat");
		fail(store, io);
		return;
	}
	size = stat.st_size;
	*((off_t *) req->data) = size;
	req->datalen = sizeof(size);

	complete(store, io);
}

static void dispatch(struct store *store, struct io *io)
{
	if (verbose)
		printf("io: 0x%p, req: 0x%p, op %u\n",
			(void *)io, (void *)io->req, io->req->op);
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

static void handle_accepted(struct store *store, struct io *io)
{
	struct xseg_request *req = io->req;
	req->serviced = 0;
	req->state = XS_ACCEPTED;
	io->retval = 0;
	dispatch(store, io);
}

static struct io* wake_up_next_iothread(struct store *store)
{
	struct io *io = alloc_io(store);

	if (io){	
		pthread_mutex_lock(&io->lock);
		pthread_cond_signal(&io->cond);
		pthread_mutex_unlock(&io->lock);
	}
	return io;
}

void *io_loop(void *arg)
{
	struct io *io = (struct io *) arg;
	struct store *store = io->store;
	struct xseg *xseg = store->xseg;
	uint32_t portno = store->portno;
	struct xseg_request *accepted;

	for (;;) {
		accepted = NULL;
		accepted = xseg_accept(xseg, portno);
		if (accepted) {
			io->req = accepted;
			wake_up_next_iothread(store);
			handle_accepted(store, io);
		}
		else {
			pthread_mutex_lock(&io->lock);
			free_io(store, io);
			pthread_cond_wait(&io->cond, &io->lock);
			pthread_mutex_unlock(&io->lock);
		}
	}

	return NULL;
}

static struct xseg *join(char *spec)
{
	struct xseg_config config;
	struct xseg *xseg;

	(void)xseg_parse_spec(spec, &config);
	xseg = xseg_join(config.type, config.name, "posix", NULL);
	if (xseg)
		return xseg;

	fprintf(stderr, "Failed to join xseg, creating it...\n");
	(void)xseg_create(&config);
	return xseg_join(config.type, config.name, "posix", NULL);
}

static int filed_loop(struct store *store)
{
	struct xseg *xseg = store->xseg;
	uint32_t portno = store->portno;
	struct io *io;

	for (;;) {
		io = wake_up_next_iothread(store);
		xseg_prepare_wait(xseg, portno);
		xseg_wait_signal(xseg, 10000);
	}
	return 0;
}

static int filed(	char *path, unsigned long size, uint32_t nr_ops,
			char *spec, long portno	)
{
	struct stat stat;
	struct sigaction sa;
	struct store *store;
	int r, mode, i;
	void *status;

	store = malloc(sizeof(struct store));
	if (!store) {
		perror("malloc");
		return -1;
	}


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
	store->maxfds = 2 * nr_ops;

	store->fdcache = calloc(store->maxfds, sizeof(struct fdcache_node));
	if(!store->fdcache)
		goto malloc_fail;

	store->free_bufs = calloc(store->nr_ops, sizeof(xqindex));
	if(!store->free_bufs)
		goto malloc_fail;

	store->iothread = calloc(store->nr_ops, sizeof(pthread_t));
	if(!store->iothread)
		goto malloc_fail;

	store->ios = calloc(nr_ops, sizeof(struct io));
	if (!store->ios) {
malloc_fail:
		perror("malloc");
		return -1;
	}

	for (i = 0; i < nr_ops; i++) {
		store->ios[i].store = store;
		pthread_cond_init(&store->ios[i].cond, NULL);
		pthread_mutex_init(&store->ios[i].lock, NULL);
	}

	xq_init_seq(&store->free_ops, store->nr_ops, store->nr_ops, store->free_bufs);

	store->handled_reqs = 0;
	strncpy(store->path, path, MAX_PATH_SIZE);
	store->path[MAX_PATH_SIZE] = 0;

	store->path_len = strlen(store->path);
	if (store->path[store->path_len -1] != '/'){
		store->path[store->path_len] = '/';
		store->path[++store->path_len]= 0;
	}
	store->dirfd = open(store->path, O_RDWR);
	if (!(store->dirfd < 0 && errno == EISDIR)){
		fprintf(stderr, "%s is not a directory\n", store->path);
		return -1;
	}

	store->dirfd = open(store->path, O_RDONLY);
	if (store->dirfd < 0){
		perror("Directory open");
		return -1;
	}
/*
	mode = 1;
	int fd = dir_open(store, ".__tmp", 6, 1);
	if (fd < 0){
		perror("Directory check");
		return -1;
	}
*/
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
	printf("filed on port %u/%u\n",
		store->portno, store->xseg->config.nr_ports);

	for (i = 0; i < nr_ops; i++) {
		pthread_cond_init(&store->fdcache[i].cond, NULL);
		store->fdcache[i].flags = READY;
	}
	for (i = 0; i < nr_ops; i++) {
		//TODO error check + cond variable to stop io from starting
		//unless all threads are created successfully
		pthread_create(store->iothread + i, NULL, io_loop, (void *) (store->ios + i));
	}
	pthread_mutex_init(&store->cache_lock, NULL);
	return filed_loop(store);
}

int main(int argc, char **argv)
{
	char *path, *spec = "";
	unsigned long size;
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

	return filed(path, size, nr_ops, spec, portno);
}

