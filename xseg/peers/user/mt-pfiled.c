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
#include <syscall.h>
#include <sys/sendfile.h>
#include <peer.h>

#include <xseg/xseg.h>
#include <xseg/protocol.h>

#define LOCK_SUFFIX		"_lock"
#define MAX_PATH_SIZE		1024
#define MAX_FILENAME_SIZE 	(XSEG_MAX_TARGETLEN + 5) //strlen(LOCK_SUFFIX)
#define MAX_PREFIX_LEN		10

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

void usage(char *argv0)
{
	fprintf(stderr,
			"Usage: %s [-p PORT] [-g XSEG_SPEC] [-n NR_OPS] [-v] "
			"--pithos PATH --archip VPATH --prefix PREFIX\n\n"
			"where:\n"
			"\tPATH: path to pithos data blocks\n"
			"\tVPATH: path to modified volume blocks\n"
			"\tPREFIX: Common prefix of Archipelagos objects to be"
			"striped during filesystem hierarchy creation\n"
			"\tPORT: xseg port to listen for requests on\n"
			"\tXSEG_SPEC: xseg spec as 'type:name:nr_ports:nr_requests:"
			"request_size:extra_size:page_shift'\n"
			"\tNR_OPS: number of outstanding xseg requests\n"
			"\t-v: verbose mode\n",
			argv0);

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
	uint32_t path_len;
	uint32_t vpath_len;
	uint32_t prefix_len;
	uint64_t handled_reqs;
	long maxfds;
	struct fdcache_node *fdcache;
	pthread_mutex_t cache_lock;
	char path[MAX_PATH_SIZE + 1];
	char vpath[MAX_PATH_SIZE + 1];
	char prefix[MAX_PREFIX_LEN];
};

/*
 * pfiled specific structure 
 * containing information on a pending I/O operation
 */
struct fio {
	uint32_t state;
	long fdcacheidx;
};

struct pfiled * __get_pfiled(struct peerd *peer)
{
	return (struct pfiled *) peer->priv;
}

struct fio * __get_fio(struct peer_req *pr)
{
	return (struct fio*) pr->priv;
}

static void close_cache_entry(struct peerd *peer, struct peer_req *pr)
{
	struct pfiled *pfiled = __get_pfiled(peer);
	struct fio *fio = __get_fio(pr);
	int fd = -1;
	if (fio->fdcacheidx >= 0) {
		if (!__sync_sub_and_fetch(&pfiled->fdcache[fio->fdcacheidx].ref, 1) && !(pfiled->fdcache[fio->fdcacheidx].flags & READY)) {
			pthread_mutex_lock(&pfiled->cache_lock);
			if (!pfiled->fdcache[fio->fdcacheidx].ref){
				/* invalidate cache entry */
				fd = pfiled->fdcache[fio->fdcacheidx].fd;
				pfiled->fdcache[fio->fdcacheidx].fd = -1;
				pfiled->fdcache[fio->fdcacheidx].target[0] = 0;
				pfiled->fdcache[fio->fdcacheidx].flags |= READY;
			}
			pthread_mutex_unlock(&pfiled->cache_lock);
			if (fd > 0)
				close(fd);

		}
	}
}

static void pfiled_complete(struct peerd *peer, struct peer_req *pr)
{
	close_cache_entry(peer, pr);
	complete(peer, pr);
}

static void pfiled_fail(struct peerd *peer, struct peer_req *pr)
{
	close_cache_entry(peer, pr);
	fail(peer, pr);
}

static void handle_unknown(struct peerd *peer, struct peer_req *pr)
{
	XSEGLOG2(&lc, W, "unknown request op");
	pfiled_fail(peer, pr);
}

static int create_path(char *buf, char *path, char *target, uint32_t targetlen,
		uint32_t prefixlen, int mkdirs)
{
	int i;
	struct stat st;
	uint32_t pathlen = strlen(path);

	strncpy(buf, path, pathlen);

	for (i = 0; i < 9; i+= 3) {
		buf[pathlen + i] = target[prefixlen + i - (i/3)];
		buf[pathlen + i +1] = target[prefixlen + i + 1 - (i/3)];
		buf[pathlen + i + 2] = '/';
		if (mkdirs == 1) {
			buf[pathlen + i + 3] = '\0';
retry:
			if (stat(buf, &st) < 0) 
				if (mkdir(buf, 0700) < 0) {
					if (errno == EEXIST)
						goto retry;
					perror(buf);
					return errno;
				}
		}
	}

	strncpy(&buf[pathlen + 9], target, targetlen);
	buf[pathlen + 9 + targetlen] = '\0';

	return 0;
}

static int dir_open(struct pfiled *pfiled, struct fio *io,
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
		XSEGLOG2(&lc, E, "lru(%ld) ref not 0 (%u)\n", lru, pfiled->fdcache[lru].ref);
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
			XSEGLOG2(&lc, W, "Cannot close %s", ce->target);
		}
	}

	/* try opening it from pithos blocker dir */
	if (create_path(tmp, pfiled->path, target, targetlen, 0, 0) < 0) {
		fd = -1;
		goto new_entry;
	}

	fd = open(tmp, O_RDWR);
	if (fd < 0) {
		/* try opening it from the tmp dir */
		if (create_path(tmp, pfiled->vpath, target, targetlen,
						pfiled->prefix_len,  0) < 0)
			goto new_entry;

		fd = open(tmp, O_RDWR);
		if (fd < 0)  {
			if (create_path(tmp, pfiled->vpath, target, targetlen,
						pfiled->prefix_len, 1) < 0) {
				fd = -1;
				goto new_entry;
			}

			fd = open(tmp, O_RDWR | O_CREAT, 0600);		
			if (fd < 0)
				XSEGLOG2(&lc, E, "Cannot open %s", tmp);
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

static void handle_read_write(struct peerd *peer, struct peer_req *pr)
{
	struct pfiled *pfiled = __get_pfiled(peer);
	struct fio *fio = __get_fio(pr);
	struct xseg_request *req = pr->req;
	int r, fd;
	char *target = xseg_get_target(peer->xseg, req);
	char *data = xseg_get_data(peer->xseg, req);

	fd = dir_open(pfiled, fio, target, req->targetlen, 0);
	if (fd < 0){
		XSEGLOG2(&lc, E, "Dir open failed");
		pfiled_fail(peer, pr);
		return;
	}

	if (!req->size) {
		if (req->flags & (XF_FLUSH | XF_FUA)) {
			/* No FLUSH/FUA support yet (O_SYNC ?).
			 * note that with FLUSH/size == 0 
			 * there will probably be a (uint64_t)-1 offset */
			pfiled_complete(peer, pr);
			return;
		} else {
			pfiled_complete(peer, pr);
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
					XSEGLOG2(&lc, E, "Cannot read");
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
				else {
					req->serviced += r;
				}
			}
			r = fsync(fd);
			if (r< 0) {
				XSEGLOG2(&lc, E, "Fsync failed.");
				/* if fsync fails, then no bytes serviced correctly */
				req->serviced = 0;
			}
			break;
		default:
			XSEGLOG2(&lc, E, "wtf, corrupt op %u?\n", req->op);
			pfiled_fail(peer, pr);
			return;
	}

	if (req->serviced > 0 ) {
		pfiled_complete(peer, pr);
	}
	else {
		pfiled_fail(peer, pr);
	}
	return;
}

static void handle_info(struct peerd *peer, struct peer_req *pr)
{
	struct pfiled *pfiled = __get_pfiled(peer);
	struct fio *fio = __get_fio(pr);
	struct xseg_request *req = pr->req;
	struct stat stat;
	int fd, r;
	uint64_t size;
	char *target = xseg_get_target(peer->xseg, req);
	char *data = xseg_get_data(peer->xseg, req);
	struct xseg_reply_info *xinfo  = (struct xseg_reply_info *)data;

	fd = dir_open(pfiled, fio, target, req->targetlen, 0);
	if (fd < 0) {
		XSEGLOG2(&lc, E, "Dir open failed");
		pfiled_fail(peer, pr);
		return;
	}

	r = fstat(fd, &stat);
	if (r < 0) {
		XSEGLOG2(&lc, E, "fail in stat");
		pfiled_fail(peer, pr);
		return;
	}

	size = (uint64_t)stat.st_size;
	xinfo->size = size;

	pfiled_complete(peer, pr);
}

static void handle_copy(struct peerd *peer, struct peer_req *pr)
{
	struct pfiled *pfiled = __get_pfiled(peer);
	struct fio *fio = __get_fio(pr);
	struct xseg_request *req = pr->req;
	
	char *target = xseg_get_target(peer->xseg, req);
	char *data = xseg_get_data(peer->xseg, req);
	struct xseg_request_copy *xcopy = (struct xseg_request_copy *)data;
	struct stat st;
	char *buf = malloc(MAX_PATH_SIZE + MAX_FILENAME_SIZE);
	int n, src = -1, dst = -1, r = -1;

	if (!buf){
		XSEGLOG2(&lc, E, "Out of memory");
		pfiled_fail(peer, pr);
		return;
	}

	dst = dir_open(pfiled, fio, target, req->targetlen, 1);
	if (dst < 0) {
		XSEGLOG2(&lc, E, "Fail in dst");
		r = dst;
		goto out;
	}

	if (create_path(buf, pfiled->path, xcopy->target,
					xcopy->targetlen, 0, 0) < 0)  {
		XSEGLOG2(&lc, E, "Create path failed");
		r = -1;
		goto out;
	}

	src = open(buf, O_RDWR);
	if (src < 0) {
		XSEGLOG2(&lc, E, "fail in src %s", buf);
		r = src;
		goto out;
	}

	r = fstat(src, &st);
	if (r < 0){
		XSEGLOG2(&lc, E, "fail in stat for src %s", buf);
		goto out;
	}

	n = sendfile(dst, src, 0, st.st_size);
	if (n != st.st_size) {
		XSEGLOG2(&lc, E, "Copy failed for %s", buf);
		r = -1;
		goto out;
	}
	r = 0;

out:
	if (src > 0)
		close(src);
	free(buf);
	if (r < 0)
		pfiled_fail(peer, pr);
	else
		pfiled_complete(peer, pr);
	return;
}

static void handle_delete(struct peerd *peer, struct peer_req *pr)
{
	struct pfiled *pfiled = __get_pfiled(peer);
	struct fio *fio = __get_fio(pr);
	struct xseg_request *req = pr->req;
	
	char *buf = malloc(MAX_PATH_SIZE + MAX_FILENAME_SIZE);
	int fd, r;
	char *target = xseg_get_target(peer->xseg, req);
	if (!buf){
		XSEGLOG2(&lc, E, "Out of memory");
		pfiled_fail(peer, pr);
		return;
	}
	fd = dir_open(pfiled, fio, target, req->targetlen, 0);
	if (fd < 0) {
		XSEGLOG2(&lc, E, "Dir open failed");
		r = fd;
		goto out;
	}

	/* mark cache entry as invalid 
	 * give a chance to pending operations on this file to end.
	 * file will close when all operations are done 
	 */
	if (fio->fdcacheidx >= 0) {
		pthread_mutex_lock(&pfiled->cache_lock);
		pfiled->fdcache[fio->fdcacheidx].flags &= ~READY;
		pthread_mutex_unlock(&pfiled->cache_lock);
	}

	r = create_path(buf, pfiled->vpath, target, req->targetlen,
				pfiled->prefix_len, 0);
	if (r< 0) {
		XSEGLOG2(&lc, E, "Create path failed");
		goto out;
	}
	r = unlink(buf);
out:
	free(buf);
	if (r < 0)
		pfiled_fail(peer, pr);
	else
		pfiled_complete(peer, pr);
	return;
}

static void handle_open(struct peerd *peer, struct peer_req *pr)
{
	struct pfiled *pfiled = __get_pfiled(peer);
//	struct fio *fio = __get_fio(pr);
	struct xseg_request *req = pr->req;
	char *buf = malloc(MAX_FILENAME_SIZE);
	char *pathname = malloc(MAX_PATH_SIZE + MAX_FILENAME_SIZE);
	int fd = -1;
	char *target = xseg_get_target(peer->xseg, req);

	if (!buf || !pathname) {
		XSEGLOG2(&lc, E, "Out of memory");
		pfiled_fail(peer, pr);
		return;
	}

	strncpy(buf, target, req->targetlen);
	strncpy(buf+req->targetlen, LOCK_SUFFIX, strlen(LOCK_SUFFIX));

	XSEGLOG2(&lc, I, "Trying to acquire lock %s", buf);

	if (create_path(pathname, pfiled->vpath, buf, 
			req->targetlen + strlen(LOCK_SUFFIX),
			pfiled->prefix_len, 1) < 0) {
		XSEGLOG2(&lc, E, "Create path failed for %s", buf);
		goto out;
	}

	//nfs v >= 3
	while ((fd = open(pathname, O_CREAT | O_EXCL, S_IRWXU | S_IRUSR)) < 0){
		//actual error
		if (errno != EEXIST){
			XSEGLOG2(&lc, W, "Error opening %s", pathname);
			goto out;
		}
		if (req->flags & XF_NOSYNC)
			goto out;
		sleep(1);
	}
	close(fd);
out:
	free(buf);
	free(pathname);
	if (fd < 0){
		XSEGLOG2(&lc, I, "Failed to acquire lock %s", buf);
		pfiled_fail(peer, pr);
	}
	else{
		XSEGLOG2(&lc, I, "Acquired lock %s", buf);
		pfiled_complete(peer, pr);
	}
	return;
}

static void handle_close(struct peerd *peer, struct peer_req *pr)
{
	struct pfiled *pfiled = __get_pfiled(peer);
//	struct fio *fio = __get_fio(pr);
	struct xseg_request *req = pr->req;
	char *buf = malloc(MAX_FILENAME_SIZE);
	char *pathname = malloc(MAX_PATH_SIZE + MAX_FILENAME_SIZE);
	char *target = xseg_get_target(peer->xseg, req);
	int r;

	if (!buf || !pathname) {
		XSEGLOG2(&lc, E, "Out of memory");
		fail(peer, pr);
		return;
	}

	strncpy(buf, target, req->targetlen);
	strncpy(buf+req->targetlen, LOCK_SUFFIX, strlen(LOCK_SUFFIX));

	r = create_path(pathname, pfiled->vpath, buf,
			req->targetlen + strlen(LOCK_SUFFIX),
			pfiled->prefix_len, 0);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Create path failed for %s", buf);
		goto out;
	}
	r = unlink(pathname);

out:
	free(buf);
	free(pathname);
	if (r < 0)
		fail(peer, pr);
	else
		complete(peer, pr);
	return;
}

int dispatch(struct peerd *peer, struct peer_req *pr, struct xseg_request *req,
		                enum dispatch_reason reason)
{
	struct fio *fio = __get_fio(pr);
	if (reason == dispatch_accept){
		fio->fdcacheidx = -1;
		fio->state = XS_ACCEPTED;
	}
	
	switch (req->op) {
		case X_READ:
		case X_WRITE:
			handle_read_write(peer, pr); break;
		case X_INFO:
			handle_info(peer, pr); break;
		case X_COPY:
			handle_copy(peer, pr); break;
		case X_DELETE:
			handle_delete(peer, pr); break;
		case X_OPEN:
			handle_open(peer, pr); break;
		case X_CLOSE:
			handle_close(peer, pr); break;
			//	case X_SNAPSHOT:
		case X_SYNC:
		default:
			handle_unknown(peer, pr);
	}
	return 0;
}

int custom_peer_init(struct peerd *peer, int argc, char *argv[])
{
	int ret = 0;
	int i;
	struct pfiled *pfiled = malloc(sizeof(struct pfiled));
	if (!pfiled){
		XSEGLOG2(&lc, E, "Out of memory");
		ret = -ENOMEM;
		goto out;
	}
	peer->priv = pfiled;

	pfiled->maxfds = 2 * peer->nr_ops;
	pfiled->fdcache = calloc(pfiled->maxfds, sizeof(struct fdcache_node));
	if(!pfiled->fdcache) {
		XSEGLOG2(&lc, E, "Out of memory");
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < peer->nr_ops; i++) {
		peer->peer_reqs[i].priv = malloc(sizeof(struct fio));
		if (!peer->peer_reqs->priv){
			XSEGLOG2(&lc, E, "Out of memory");
			ret = -ENOMEM;
			goto out;
		}
	}

	pfiled->vpath[0] = 0;
	pfiled->path[0] = 0;
	pfiled->handled_reqs = 0;
	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "--pithos") && (i+1) < argc){
			strncpy(pfiled->path, argv[i+1], MAX_PATH_SIZE);
			pfiled->path[MAX_PATH_SIZE] = 0;
			i += 1;
			continue;
		}
		if (!strcmp(argv[i], "--archip") && (i+1) < argc){
			strncpy(pfiled->vpath, argv[i+1], MAX_PATH_SIZE);
			pfiled->vpath[MAX_PATH_SIZE] = 0;
			i += 1;
			continue;
		}
		if (!strcmp(argv[i], "--prefix") && (i+1) < argc){
			strncpy(pfiled->prefix, argv[i+1], MAX_PREFIX_LEN);
			pfiled->prefix[MAX_PREFIX_LEN] = 0;
			i += 1;
			continue;
		}
	}

	pfiled->prefix_len = strlen(pfiled->prefix);

	pfiled->path_len = strlen(pfiled->path);
	if (!pfiled->path_len){
		XSEGLOG2(&lc, E, "Pithos path was not provided");
		return -1;
	}
	if (pfiled->path[pfiled->path_len -1] != '/'){
		pfiled->path[pfiled->path_len] = '/';
		pfiled->path[++pfiled->path_len]= 0;
	}

	pfiled->vpath_len = strlen(pfiled->vpath);
	if (!pfiled->vpath_len){
		XSEGLOG2(&lc, E, "Archipelagos path was not provided");
		return -1;
	}
	if (pfiled->vpath[pfiled->vpath_len -1] != '/'){
		pfiled->vpath[pfiled->vpath_len] = '/';
		pfiled->vpath[++pfiled->vpath_len]= 0;
	}

	for (i = 0; i < peer->nr_ops; i++) {
		pthread_cond_init(&pfiled->fdcache[i].cond, NULL);
		pfiled->fdcache[i].flags = READY;
	}
	pthread_mutex_init(&pfiled->cache_lock, NULL);

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
