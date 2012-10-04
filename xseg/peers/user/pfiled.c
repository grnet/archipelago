/*
 * The Pithos File Blocker Peer (pfiled)
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
#include <pthread.h>
#include <sys/sendfile.h>

#include <xseg/xseg.h>
#include <xseg/protocol.h>

#include "common.h"			/* FIXME: */

#define MAX_PATH_SIZE		1024
#define MAX_FILENAME_SIZE 	255

/* default concurrency level (number of threads) */
#define DEFAULT_NR_OPS		 16

/* Pithos hash for the zero block
 * FIXME: Should it be hardcoded?
 */
#define ZERO_BLOCK \
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85"

/*
 * Globals, holding command-line arguments
 */
long cmdline_portno = -1;
char *cmdline_xseg_spec = NULL;
char *cmdline_path = NULL;
char *cmdline_vpath = NULL;
long cmdline_nr_ops = DEFAULT_NR_OPS;
long cmdline_verbose = 0;

static int usage(char *argv0)
{
	fprintf(stderr,
		"Usage: %s <PATH> <VPATH> [-p PORT] [-g XSEG_SPEC] [-n NR_OPS] [-v]\n\n"
		"where:\n"
		"\tPATH: path to pithos data blocks\n"
		"\tVPATH: path to modified volume blocks\n"
		"\tPORT: xseg port to listen for requests on\n"
		"\tXSEG_SPEC: xseg spec as 'type:name:nr_ports:nr_requests:"
			"request_size:extra_size:page_shift'\n"
		"\tNR_OPS: number of outstanding xseg requests\n"
		"\t-v: verbose mode\n",
		argv0);

	return 1;
}

/* fdcache_node flags */
#define READY (1 << 1)

/* fdcache node info */
struct fdcache_node {
	volatile int fd;
	volatile unsigned int ref;
	volatile unsigned long time;
	volatile unsigned int flags;
	pthread_cond_t cond;
	char target[MAX_FILENAME_SIZE + 1];
};

/* pfiled context */
struct pfiled {
	struct xseg *xseg;
	struct xseg_port *xport;
	uint32_t portno;
	uint64_t size;
	struct io *ios;
	struct xq free_ops;
	char *free_bufs;
	long nr_ops;
	struct sigevent sigevent;
	uint32_t path_len;
	uint32_t vpath_len;
	uint64_t handled_reqs;
	long maxfds;
	struct fdcache_node *fdcache;
	pthread_t *iothread;
	pthread_mutex_t cache_lock;
	char path[MAX_PATH_SIZE + 1];
	char vpath[MAX_PATH_SIZE + 1];
};

/*
 * pfiled specific structure 
 * containing information on a pending I/O operation
 */
struct io {
	struct pfiled *pfiled;
	struct xseg_request *req;
	uint32_t state;
	ssize_t retval;
	long fdcacheidx;
	pthread_cond_t cond;
	pthread_mutex_t lock;
};


static unsigned long sigaction_count;

static void sigaction_handler(int sig, siginfo_t *siginfo, void *arg)
{
	sigaction_count++;
}

static void log_io(char *msg, struct io *io)
{
	char target[65], data[65];
	/* null terminate name in case of req->target is less than 63 characters,
	 * and next character after name (aka first byte of next buffer) is not
	 * null
	 */
	unsigned int end = (io->req->targetlen> 64) ? 64 : io->req->targetlen;
	unsigned int dend = (io->req->datalen > 64) ? 64 : io->req->datalen;
	char *req_target = xseg_get_target(io->pfiled->xseg, io->req);
	char *req_data = xseg_get_data(io->pfiled->xseg, io->req);
	strncpy(target, req_target, end);
	target[end] = 0;
	strncpy(data, req_data, 64);
	data[dend] = 0;

	fprintf(stderr,
		"%s: fd:%u, op:%u offset: %llu size: %lu retval: %lu, reqstate: %u, serviced: %u\n"
		"target[%u]: '%s', data[%llu]:\n%s------------------\n\n",
		msg,
		(unsigned int)io->fdcacheidx, /* this is cacheidx not fd */
		(unsigned int)io->req->op,
		(unsigned long long)io->req->offset,
		(unsigned long)io->req->size,
		(unsigned long)io->retval,
		(unsigned int)io->req->state,
		(unsigned long)io->req->serviced,
		(unsigned int)io->req->targetlen, target,
		(unsigned long long)io->req->datalen, data);
}

static struct io *alloc_io(struct pfiled *pfiled)
{
	xqindex idx = xq_pop_head(&pfiled->free_ops, 1);
	if (idx == Noneidx)
		return NULL;
	return pfiled->ios + idx;
}

static inline void free_io(struct pfiled *pfiled, struct io *io)
{
	xqindex idx = io - pfiled->ios;
	io->req = NULL;
	xq_append_head(&pfiled->free_ops, idx, 1);
}

static void complete(struct pfiled *pfiled, struct io *io)
{
	struct xseg_request *req = io->req;
	req->state |= XS_SERVED;
	if (cmdline_verbose)
		log_io("complete", io);
	xport p = xseg_respond(pfiled->xseg, req, pfiled->portno, X_ALLOC);
	xseg_signal(pfiled->xseg, p);
	__sync_fetch_and_sub(&pfiled->fdcache[io->fdcacheidx].ref, 1);
}

static void fail(struct pfiled *pfiled, struct io *io)
{
	struct xseg_request *req = io->req;
	req->state |= XS_FAILED;
	if (cmdline_verbose)
		log_io("fail", io);
	xport p = xseg_respond(pfiled->xseg, req, pfiled->portno, X_ALLOC);
	xseg_signal(pfiled->xseg, p);
	if (io->fdcacheidx >= 0) {
		__sync_fetch_and_sub(&pfiled->fdcache[io->fdcacheidx].ref, 1);
	}
}

static void handle_unknown(struct pfiled *pfiled, struct io *io)
{
	struct xseg_request *req = io->req;
	char *data = xseg_get_data(pfiled->xseg, req);
	snprintf(data, req->datalen, "unknown request op");
	fail(pfiled, io);
}

static int create_path(char *buf, char *path, char *target, uint32_t targetlen, int mkdirs)
{
	int i;
	struct stat st;
	uint32_t pathlen = strlen(path);

	strncpy(buf, path, pathlen);

	for (i = 0; i < 9; i+= 3) {
		buf[pathlen + i] = target[i - (i/3)];
		buf[pathlen + i +1] = target[i + 1 - (i/3)];
		buf[pathlen + i + 2] = '/';
		if (mkdirs == 1) {
			buf[pathlen + i + 3] = '\0';
			if (stat(buf, &st) < 0) 
				if (mkdir(buf, 0600) < 0) {
					perror(buf);
					return errno;
				}
		}
	}

	strncpy(&buf[pathlen + 9], target, targetlen);
	buf[pathlen + 9 + targetlen] = '\0';

	return 0;
}

static int dir_open(struct pfiled *pfiled, struct io *io,
			char *target, uint32_t targetlen, int mode)
{
	int fd = -1;
	struct fdcache_node *ce = NULL;
	long i, lru;
	char tmp[pfiled->path_len + targetlen + 10];
	uint64_t min;
	io->fdcacheidx = -1;
	if (targetlen> MAX_FILENAME_SIZE)
		goto out_err;

start:
	/* check cache */
	pthread_mutex_lock(&pfiled->cache_lock);
start_locked:
	lru = -1;
	min = UINT64_MAX;
	for (i = 0; i < pfiled->maxfds; i++) {
		if (pfiled->fdcache[i].ref == 0 && min > pfiled->fdcache[i].time 
				&& (pfiled->fdcache[i].flags & READY)) {
			min = pfiled->fdcache[i].time;
			lru = i;

		}

		if (!strncmp(pfiled->fdcache[i].target, target, targetlen)) {
			if (pfiled->fdcache[i].target[targetlen] == 0) {
				ce = &pfiled->fdcache[i];
				/* if any other io thread is currently opening
				 * the file, block until it succeeds or fails
				 */
				if (!(ce->flags & READY)) {
					pthread_cond_wait(&ce->cond, &pfiled->cache_lock);
					/* when ready, restart lookup */
					goto start_locked;
				}
				/* if successfully opened */
				if (ce->fd > 0) {
					fd = pfiled->fdcache[i].fd;
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
		pthread_mutex_unlock(&pfiled->cache_lock);
		goto start;
	}
	if (pfiled->fdcache[lru].ref){
		fd = -1;
		printf("lru(%ld) ref not 0 (%u)\n", lru, pfiled->fdcache[lru].ref);
		goto out_err_unlock;
	}
	/* make room for new file */
	ce = &pfiled->fdcache[lru];
	/* set name here and state to not ready, for any other requests on the
	 * same target that may follow
	 */
	strncpy(ce->target, target, targetlen);
	ce->target[targetlen] = 0;
	ce->flags &= ~READY;
	pthread_mutex_unlock(&pfiled->cache_lock);

	if (ce->fd >0){
		if (close(ce->fd) < 0){
			perror("close");
		}
	}

	/* try opening it from pithos blocker dir */
	if (create_path(tmp, pfiled->path, target, targetlen, 0) < 0) {
		fd = -1;
		goto new_entry;
	}
	
	fd = open(tmp, O_RDWR);
	if (fd < 0) {
		/* try opening it from the tmp dir */
		if (create_path(tmp, pfiled->vpath, target, targetlen, 0) < 0)
			goto new_entry;

		fd = open(tmp, O_RDWR);
		if (fd < 0)  {
			if (create_path(tmp, pfiled->vpath, target, targetlen, 1) < 0) {
				fd = -1;
				goto new_entry;
			}
	
			fd = open(tmp, O_RDWR | O_CREAT, 0600);		
			if (fd < 0)
				perror(tmp);
		}
	}

	/* insert in cache a negative fd to indicate opening error to
	 * any other ios waiting for the file to open
	 */

	/* insert in cache */
new_entry:
	pthread_mutex_lock(&pfiled->cache_lock);
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
	pfiled->handled_reqs++;
	ce->time = pfiled->handled_reqs;
	__sync_fetch_and_add(&ce->ref, 1);
	pthread_mutex_unlock(&pfiled->cache_lock);
out_err:
	return fd;

out_err_unlock:
	pthread_mutex_unlock(&pfiled->cache_lock);
	goto out_err;
}

static void handle_read_write(struct pfiled *pfiled, struct io *io)
{
	int r, fd;
	struct xseg_request *req = io->req;
	char *target = xseg_get_target(pfiled->xseg, req);
	char *data = xseg_get_data(pfiled->xseg, req);

	fd = dir_open(pfiled, io, target, req->targetlen, 0);
	if (fd < 0){
		perror("dir_open");
		fail(pfiled, io);
		return;
	}

	if (req != io->req)
		printf("0.%p vs %p!\n", (void *)req, (void *)io->req);
	if (!req->size) {
		if (req->flags & (XF_FLUSH | XF_FUA)) {
			/* No FLUSH/FUA support yet (O_SYNC ?).
			 * note that with FLUSH/size == 0 
			 * there will probably be a (uint64_t)-1 offset */
			complete(pfiled, io);
			return;
		} else {
			complete(pfiled, io);
			return;
		}
	}

	switch (req->op) {
	case X_READ:
		while (req->serviced < req->datalen) {
			r = pread(fd, data + req->serviced, 
					req->datalen - req->serviced,
				       	req->offset + req->serviced);
			if (r < 0) {
				req->datalen = req->serviced;
				perror("pread");
			}
			else if (r == 0) {
				/* reached end of file. zero out the rest data buffer */
				memset(data + req->serviced, 0, req->datalen - req->serviced);
				req->serviced = req->datalen;
			}
			else {
				req->serviced += r;
			}
		}
		break;
	case X_WRITE:
		while (req->serviced < req->datalen) {
			r = pwrite(fd, data + req->serviced, 
					req->datalen - req->serviced,
				       	req->offset + req->serviced);
			if (r < 0) {
				req->datalen = req->serviced;
			}
			else if (r == 0) {
				fprintf(stderr, "write returned 0\n");
				memset(data + req->serviced, 0, req->datalen - req->serviced);
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
		snprintf(data, req->datalen,
			 "wtf, corrupt op %u?\n", req->op);
		fail(pfiled, io);
		return;
	}

	if (req->serviced > 0 ) {
		complete(pfiled, io);
	}
	else {
		strerror_r(errno, data, req->datalen);
		fail(pfiled, io);
	}
	return;
}

static void handle_info(struct pfiled *pfiled, struct io *io)
{
	struct xseg_request *req = io->req;
	struct stat stat;
	int fd, r;
	uint64_t size;
	char *target = xseg_get_target(pfiled->xseg, req);
	char *data = xseg_get_data(pfiled->xseg, req);
	struct xseg_reply_info *xinfo  = (struct xseg_reply_info *)data;

	fd = dir_open(pfiled, io, target, req->targetlen, 0);
	if (fd < 0) {
		fail(pfiled, io);
		return;
	}

	r = fstat(fd, &stat);
	if (r < 0) {
		perror("fstat");
		fail(pfiled, io);
		return;
	}

	size = (uint64_t)stat.st_size;
	xinfo->size = size;

	complete(pfiled, io);
}

static void handle_copy(struct pfiled *pfiled, struct io *io)
{
	struct xseg_request *req = io->req;
	char *target = xseg_get_target(pfiled->xseg, req);
	char *data = xseg_get_data(pfiled->xseg, req);
	struct xseg_request_copy *xcopy = (struct xseg_request_copy *)data;
	struct stat st;
	char *buf = malloc(256);
	int n, src, dst;

	dst = dir_open(pfiled, io, target, req->targetlen, 1);
	if (dst < 0) {
		fprintf(stderr, "fail in dst\n");
		fail(pfiled, io);
		return;
	}

	if (create_path(buf, pfiled->path, xcopy->target, xcopy->targetlen, 0) < 0)  {
		fail(pfiled, io);
		return;
	}

	src = open(buf, O_RDWR);
	if (src < 0) {
		XSEGLOG("fail in src %s\n", buf);
		perror("open src");
		fail(pfiled, io);
		return;
	}

	fstat(src, &st);
	n = sendfile(dst, src, 0, st.st_size);
	if (n != st.st_size) {
		fprintf(stderr, "fail in copy\n");
		fail(pfiled, io);
		goto out;
	}

	if (n < 0) {
		fprintf(stderr, "fail in cp\n");
		fail(pfiled, io);
		goto out;
	}

	complete(pfiled, io);

out:
	close(src);
}

static void handle_delete(struct pfiled *pfiled, struct io *io)
{
	struct xseg_request *req = io->req;
	char *buf = malloc(255);
	int fd;
	char *target = xseg_get_target(pfiled->xseg, req);
	
	fd = dir_open(pfiled, io, target, req->targetlen, 0);
	if (fd < 0) {
		fprintf(stderr, "fail in dir_open\n");
		fail(pfiled, io);
		return;
	}

	/* 'invalidate' cache entry */
	if (io->fdcacheidx >= 0) {
		pfiled->fdcache[io->fdcacheidx].fd = -1;
	}

	close(fd);

	if (create_path(buf, pfiled->vpath, target, req->targetlen, 0) < 0) {
		fail(pfiled, io);
		return;
	}
	unlink(buf);

	complete(pfiled, io);

	return;
}

static void dispatch(struct pfiled *pfiled, struct io *io)
{
	if (cmdline_verbose) { 
		fprintf(stderr, "io: 0x%p, req: 0x%p, op %u\n",
			(void *)io, (void *)io->req, io->req->op);
	}

	switch (io->req->op) {
	case X_READ:
	case X_WRITE:
		handle_read_write(pfiled, io); break;
	case X_INFO:
		handle_info(pfiled, io); break;
	case X_COPY:
		handle_copy(pfiled, io); break;
	case X_DELETE:
		handle_delete(pfiled, io); break;
//	case X_SNAPSHOT:
	case X_SYNC:
	default:
		handle_unknown(pfiled, io);
	}
}

static void handle_accepted(struct pfiled *pfiled, struct io *io)
{
	struct xseg_request *req = io->req;
	req->serviced = 0;
	io->state = XS_ACCEPTED;
	io->retval = 0;
	dispatch(pfiled, io);
}

static struct io* wake_up_next_iothread(struct pfiled *pfiled)
{
	struct io *io = alloc_io(pfiled);

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
	struct pfiled *pfiled = io->pfiled;
	struct xseg *xseg = pfiled->xseg;
	uint32_t portno = pfiled->portno;
	struct xseg_request *accepted;

	for (;;) {
		accepted = NULL;
		accepted = xseg_accept(xseg, portno);
		if (accepted) {
			io->req = accepted;
			wake_up_next_iothread(pfiled);
			handle_accepted(pfiled, io);
		}
		else {
			pthread_mutex_lock(&io->lock);
			free_io(pfiled, io);
			pthread_cond_wait(&io->cond, &io->lock);
			pthread_mutex_unlock(&io->lock);
		}
	}

	return NULL;
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

static int pfiled_loop(struct pfiled *pfiled)
{
	struct xseg *xseg = pfiled->xseg;
	uint32_t portno = pfiled->portno;
	/* GCC + pthreads glitch? */
	struct io *io;

	for (;;) {
		io = wake_up_next_iothread(pfiled);
		xseg_prepare_wait(xseg, portno);
		xseg_wait_signal(xseg, 1000000UL);
	}

	return 0;
}

static int pfiled_init(struct pfiled *pfiled)
{
	struct sigaction sa;
	int ret;
	int i;

	pfiled->sigevent.sigev_notify = SIGEV_SIGNAL;
	pfiled->sigevent.sigev_signo = SIGIO;
	sa.sa_sigaction = sigaction_handler;
	sa.sa_flags = SA_SIGINFO;

	if ((ret = sigemptyset(&sa.sa_mask))) {
		perr(PE, 0, "[sigemptyset]");
		goto out;
	}

	if ((ret = sigaction(SIGIO, &sa, NULL))) {
		perr(PE, 0, "[sigaction]");
		/* FIXME: Since this is an init routine, if it fails the program will
		 * exit and clean its own stuff (mem, sigs etc). We only have to cleanup
		 * anything xseg-related
		 */
		goto out;
	}

	pfiled->nr_ops = cmdline_nr_ops;
	pfiled->maxfds = 2 * cmdline_nr_ops;

	pfiled->fdcache = calloc(pfiled->maxfds, sizeof(struct fdcache_node));
	if(!pfiled->fdcache) {
		ret = -ENOMEM;
		perr(PE, 0, "could not allocate memory [fdcache]");
		goto out;
	}
		

	pfiled->free_bufs = calloc(pfiled->nr_ops, sizeof(xqindex));
	if(!pfiled->free_bufs) {
		ret = -ENOMEM;
		perr(PE, 0, "could not allocate memory [free_bufs]");
		goto out;
	}

	pfiled->iothread = calloc(pfiled->nr_ops, sizeof(pthread_t));
	if(!pfiled->iothread) {
		ret = -ENOMEM;
		perr(PE, 0, "could not allocate memory [iothreads]");
		goto out;
	}

	pfiled->ios = calloc(pfiled->nr_ops, sizeof(struct io));
	if (!pfiled->ios) {
		ret = -ENOMEM;
		perr(PE, 0, "could not allocate memory [ios]");
		goto out;
	}

	for (i = 0; i < pfiled->nr_ops; i++) {
		pfiled->ios[i].pfiled = pfiled;
		pthread_cond_init(&pfiled->ios[i].cond, NULL);
		pthread_mutex_init(&pfiled->ios[i].lock, NULL);
	}

	xq_init_seq(&pfiled->free_ops, pfiled->nr_ops, pfiled->nr_ops,
				pfiled->free_bufs);
	
	pfiled->handled_reqs = 0;

	strncpy(pfiled->path, cmdline_path, MAX_PATH_SIZE);
	pfiled->path[MAX_PATH_SIZE] = 0;

	strncpy(pfiled->vpath, cmdline_vpath, MAX_PATH_SIZE);
	pfiled->vpath[MAX_PATH_SIZE] = 0;

	pfiled->path_len = strlen(pfiled->path);
	if (pfiled->path[pfiled->path_len -1] != '/'){
		pfiled->path[pfiled->path_len] = '/';
		pfiled->path[++pfiled->path_len]= 0;
	}

	pfiled->vpath_len = strlen(pfiled->vpath);
	if (pfiled->vpath[pfiled->vpath_len -1] != '/'){
		pfiled->vpath[pfiled->vpath_len] = '/';
		pfiled->vpath[++pfiled->vpath_len]= 0;
	}

	if (xseg_initialize()) {
		ret = - ENOMEM;
		perr(PE, 0, "could not initialize xseg library");
		goto out;
	}

	pfiled->xseg = join_or_create(cmdline_xseg_spec);
	if (!pfiled->xseg) {
		ret = -EIO;
		perr(PE, 0, "could not join xseg with spec '%s'\n", 
			cmdline_xseg_spec);
		goto out_with_xseginit;
	}

	pfiled->xport = xseg_bind_port(pfiled->xseg, cmdline_portno, NULL);
	if (!pfiled->xport) {
		ret = -EIO;
		perr(PE, 0, "could not bind to xseg port %ld", cmdline_portno);
		goto out_with_xsegjoin;
	}

	pfiled->portno = xseg_portno(pfiled->xseg, pfiled->xport);
	perr(PI, 0, "filed on port %u/%u\n",
		pfiled->portno, pfiled->xseg->config.nr_ports);

	if (xseg_init_local_signal(pfiled->xseg, pfiled->portno) < 0){
		printf("cannot int local signals\n");
		return -1;
	}

	for (i = 0; i < pfiled->nr_ops; i++) {
		pthread_cond_init(&pfiled->fdcache[i].cond, NULL);
		pfiled->fdcache[i].flags = READY;
	}
	for (i = 0; i < pfiled->nr_ops; i++) {
		/* 
		 * TODO: error check + cond variable to stop io from starting
		 * unless all threads are created successfully
		 */
		pthread_create(pfiled->iothread + i, NULL, io_loop, (void *) (pfiled->ios + i));
	}
	pthread_mutex_init(&pfiled->cache_lock, NULL);

	goto out;

out_with_xsegjoin:
	xseg_leave(pfiled->xseg);
out_with_xseginit:
	xseg_finalize();
out:
	return ret;
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
	char *argv0 = argv[0];

	for (;;) {
		int c;

		opterr = 0;
		c = getopt(argc, argv, "hp:n:g:v");
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
				usage(argv0);
				exit(0);
				break;
			case 'p':
				cmdline_portno = safe_atoi(optarg);
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
			case 'v':
				cmdline_verbose = 1;
				break;
		}
	}

	argc -= optind;
	argv += optind;

	/* Sanity check for all arguments */
	if (cmdline_portno < 0) {
		usage(argv0);
		perr(PFE, 0, "no or invalid port specified");
	}
	if (cmdline_nr_ops < 1) {
		usage(argv0);
		perr(PFE, 0, "specified outstanding request count is invalid");
	}
	if (!cmdline_xseg_spec) {
		usage(argv0);
		perr(PFE, 0, "xseg specification is mandatory");
	}

	if (argc < 2) {
		usage(argv0);
		perr(PFE, 0, "path and vpath specification is mandatory");
	}

	cmdline_path = strdup(argv[0]);
	if (!cmdline_path)
		perr(PFE, 0, "out of memory");

	cmdline_vpath = strdup(argv[1]);
	if (!cmdline_vpath)
		perr(PFE, 0, "out of memory");
}

int main(int argc, char **argv)
{
	struct pfiled pfiled;

	init_perr("pfiled");
	parse_cmdline(argc, argv);

	perr(PI, 0, "p = %ld, nr_ops = %lu\n", cmdline_portno, cmdline_nr_ops);

	if (pfiled_init(&pfiled) < 0)
		perr(PFE, 0, "failed to initialize pfiled");

	return pfiled_loop(&pfiled);
}
