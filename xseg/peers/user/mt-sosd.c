#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <xseg/xseg.h>
#include <peer.h>
#include <rados/librados.h>
#include <xseg/protocol.h>
#include <pthread.h>

#define LOCK_SUFFIX "_lock"
#define LOCK_SUFFIX_LEN 5

#define MAX_POOL_NAME 64
#define MAX_OBJ_NAME (XSEG_MAX_TARGETLEN + LOCK_SUFFIX_LEN + 1)
#define RADOS_LOCK_NAME "RadosLock"
//#define RADOS_LOCK_COOKIE "Cookie"
#define RADOS_LOCK_COOKIE "foo"

void custom_peer_usage()
{
	fprintf(stderr, "Custom peer options:\n"
		"--pool: Rados pool to connect\n"
		"\n");
}

enum rados_state {
	ACCEPTED = 0,
	PENDING = 1,
	READING = 2,
	WRITING = 3
};

struct radosd {
	rados_t cluster;
	rados_ioctx_t ioctx;
	char pool[MAX_POOL_NAME + 1];
};

struct rados_io{
	char obj_name[MAX_OBJ_NAME + 1];
	enum rados_state state;
	uint64_t size;
	char *src_name, *buf;
	uint64_t read;
	uint64_t watch_handle;
	pthread_t tid;
	pthread_cond_t cond;
	pthread_mutex_t m;
};

void rados_ack_cb(rados_completion_t c, void *arg)
{
	struct peer_req *pr = (struct peer_req*) arg;
	struct peerd *peer = pr->peer;
	int ret = rados_aio_get_return_value(c);
	pr->retval = ret;
	rados_aio_release(c);
	dispatch(peer, pr, pr->req, dispatch_internal);
}

void rados_commit_cb(rados_completion_t c, void *arg)
{
	struct peer_req *pr = (struct peer_req*) arg;
	struct peerd *peer = pr->peer;
	int ret = rados_aio_get_return_value(c);
	pr->retval = ret;
	rados_aio_release(c);
	dispatch(peer, pr, pr->req, dispatch_internal);
}

static int do_aio_generic(struct peerd *peer, struct peer_req *pr, uint32_t op,
		char *target, char *buf, uint64_t size, uint64_t offset)
{
	struct radosd *rados = (struct radosd *) peer->priv;
	struct rados_io *rio = (struct rados_io *) pr->priv;
	int r;

	rados_completion_t rados_compl;
	switch (op) {
		case X_READ:
			r = rados_aio_create_completion(pr, rados_ack_cb, NULL, &rados_compl);
			if (r < 0)
				return -1;
			r = rados_aio_read(rados->ioctx, target, rados_compl,
					buf, size, offset);
			break;
		case X_WRITE:
			r = rados_aio_create_completion(pr, NULL, rados_commit_cb, &rados_compl);
			if (r < 0)
				return -1;
			r = rados_aio_write(rados->ioctx, target, rados_compl,
					buf, size, offset);
			break;
		case X_DELETE:
			r = rados_aio_create_completion(pr, rados_ack_cb, NULL, &rados_compl);
			if (r < 0)
				return -1;
			r = rados_aio_remove(rados->ioctx, target, rados_compl);
			break;
		case X_INFO:
			r = rados_aio_create_completion(pr, rados_ack_cb, NULL, &rados_compl);
			if (r < 0)
				return -1;
			r = rados_aio_stat(rados->ioctx, target, rados_compl, &rio->size, NULL); 
			break;
		default:
			return -1;
			break;
	}
	if (r < 0) {
		rados_aio_release(rados_compl);
	}
	return r;
}

static int do_aio_read(struct peerd *peer, struct peer_req *pr)
{
	struct xseg_request *req = pr->req;
	struct rados_io *rio = (struct rados_io *) pr->priv;
	char *data = xseg_get_data(peer->xseg, pr->req);

	return do_aio_generic(peer, pr, X_READ, rio->obj_name,
			data + req->serviced,
			req->size - req->serviced,
			req->offset + req->serviced);
}

static int do_aio_write(struct peerd *peer, struct peer_req *pr)
{
	struct xseg_request *req = pr->req;
	struct rados_io *rio = (struct rados_io *) pr->priv;
	char *data = xseg_get_data(peer->xseg, pr->req);

	return do_aio_generic(peer, pr, X_WRITE, rio->obj_name,
			data + req->serviced,
			req->size - req->serviced,
			req->offset + req->serviced);
}

int handle_delete(struct peerd *peer, struct peer_req *pr)
{
	int r;
	//struct radosd *rados = (struct radosd *) peer->priv;
	struct rados_io *rio = (struct rados_io *) pr->priv;

	if (rio->state == ACCEPTED) {
		XSEGLOG2(&lc, I, "Deleting %s", rio->obj_name);
		rio->state = PENDING;
		r = do_aio_generic(peer, pr, X_DELETE, rio->obj_name, NULL, 0, 0);
		if (r < 0) {
			XSEGLOG2(&lc, E, "Deletion of %s failed", rio->obj_name);
			fail(peer, pr);
		}
	}
	else {
		if (pr->retval < 0){
			XSEGLOG2(&lc, E, "Deletion of %s failed", rio->obj_name);
			fail(peer, pr);
		}
		else {
			XSEGLOG2(&lc, I, "Deletion of %s completed", rio->obj_name);
			complete(peer, pr);
		}
	}
	return 0;
}

int handle_info(struct peerd *peer, struct peer_req *pr)
{
	int r;
	struct xseg_request *req = pr->req;
	//struct radosd *rados = (struct radosd *) peer->priv;
	struct rados_io *rio = (struct rados_io *) pr->priv;
	char *req_data = xseg_get_data(peer->xseg, req);
	struct xseg_reply_info *xinfo = (struct xseg_reply_info *)req_data;

	if (rio->state == ACCEPTED) {
		XSEGLOG2(&lc, I, "Getting info of %s", rio->obj_name);
		rio->state = PENDING;
		r = do_aio_generic(peer, pr, X_INFO, rio->obj_name, NULL, 0, 0);
		if (r < 0) {
			XSEGLOG2(&lc, E, "Getting info of %s failed", rio->obj_name);	
			fail(peer, pr);
		}
	}
	else {
		if (pr->retval < 0){
			xinfo->size = 0;
			XSEGLOG2(&lc, E, "Getting info of %s failed", rio->obj_name);	
			fail(peer, pr);
		}
		else {
			xinfo->size = rio->size;
			pr->retval = sizeof(uint64_t);
			XSEGLOG2(&lc, I, "Getting info of %s completed", rio->obj_name);	
			complete(peer, pr);
		}
	}
	return 0;
}

int handle_read(struct peerd *peer, struct peer_req *pr)
{
	struct rados_io *rio = (struct rados_io *) (pr->priv);
	struct xseg_request *req = pr->req;
	char *data;
	if (rio->state == ACCEPTED) {
		if (!req->size) {
			complete(peer, pr);
			return 0;
		}
		rio->state = READING;
		XSEGLOG2(&lc, I, "Reading %s", rio->obj_name);
		if (do_aio_read(peer, pr) < 0) {
			XSEGLOG2(&lc, I, "Reading of %s failed on do_aio_read",
						rio->obj_name);
			fail(peer, pr);
		}
	}
	else if (rio->state == READING) {
		XSEGLOG2(&lc, I, "Reading of %s callback", rio->obj_name);
		data = xseg_get_data(peer->xseg, pr->req);
		if (pr->retval > 0)
			req->serviced += pr->retval;
		else if (pr->retval == 0) {
			XSEGLOG2(&lc, I, "Reading of %s reached end of file at "
				"%llu bytes. Zeroing out rest", rio->obj_name,
				(unsigned long long) req->serviced);
			/* reached end of object. zero out rest of data
			 * requested from this object
			 */
			memset(data + req->serviced, 0, req->datalen - req->serviced);
			req->serviced = req->datalen;
		}
		else if (pr->retval == -2) {
			XSEGLOG2(&lc, I, "Reading of %s return -2. "
					"Zeroing out data", rio->obj_name);
			/* object not found. return zeros instead */
			memset(data, 0, req->datalen);
			req->serviced = req->datalen;
		}
		else {
			XSEGLOG2(&lc, E, "Reading of %s failed", rio->obj_name);
			/* pr->retval < 0 && pr->retval != -2 */
			fail(peer, pr);
			return 0;
		}
		if (req->serviced >= req->datalen) {
			XSEGLOG2(&lc, I, "Reading of %s completed", rio->obj_name);
			complete(peer, pr);
			return 0;
		}

		if (!req->size) {
			/* should not happen */
			fail(peer, pr);
			return 0;
		}
		/* resubmit */
		XSEGLOG2(&lc, I, "Resubmitting read of %s", rio->obj_name);
		if (do_aio_read(peer, pr) < 0) {
			XSEGLOG2(&lc, E, "Reading of %s failed on do_aio_read",
					rio->obj_name);
			fail(peer, pr);
		}
	}
	else {
		/* should not reach this */
		printf("read request reached this\n");
		fail(peer, pr);
	}
	return 0;
}

int handle_write(struct peerd *peer, struct peer_req *pr)
{
	struct rados_io *rio = (struct rados_io *) (pr->priv);
	struct xseg_request *req = pr->req;
	if (rio->state == ACCEPTED) {
		if (!req->size) {
			// for future use
			if (req->flags & XF_FLUSH) {
				complete(peer, pr);
				return 0;
			}
			else {
				complete(peer, pr);
				return 0;
			}
		}
		//should we ensure req->op = X_READ ?
		rio->state = WRITING;
		XSEGLOG2(&lc, I, "Writing %s", rio->obj_name);
		if (do_aio_write(peer, pr) < 0) {
			XSEGLOG2(&lc, E, "Writing of %s failed on do_aio_write",
					rio->obj_name);
			fail(peer, pr);
		}
	}
	else if (rio->state == WRITING) {
		/* rados writes return 0 if write succeeded or < 0 if failed
		 * no resubmission occurs
		 */
		XSEGLOG2(&lc, I, "Writing of %s callback", rio->obj_name);
		if (pr->retval == 0) {
			XSEGLOG2(&lc, I, "Writing of %s completed", rio->obj_name);
			req->serviced = req->datalen;
			complete(peer, pr);
			return 0;
		}
		else {
			XSEGLOG2(&lc, E, "Writing of %s failed", rio->obj_name);
			fail(peer, pr);
			return 0;
		}
	}
	else {
		/* should not reach this */
		printf("write request reached this\n");
		fail(peer, pr);
	}
	return 0;
}

int handle_copy(struct peerd *peer, struct peer_req *pr)
{
	//struct radosd *rados = (struct radosd *) peer->priv;
	struct xseg_request *req = pr->req;
	struct rados_io *rio = (struct rados_io *) pr->priv;
	int r;
	struct xseg_request_copy *xcopy = (struct xseg_request_copy *)xseg_get_data(peer->xseg, req);

	if (rio->state == ACCEPTED){
		XSEGLOG2(&lc, I, "Copy of object %s to object %s started",
				rio->src_name, rio->obj_name);
		if (!req->size) {
			complete(peer, pr); //or fail?
			return 0;
		}

		rio->src_name = malloc(MAX_OBJ_NAME + 1);
		if (!rio->src_name){
			fail(peer, pr);
			return -1;
		}
		//NULL terminate or fail if targetlen > MAX_OBJ_NAME ?
		unsigned int end = (xcopy->targetlen > MAX_OBJ_NAME) ? MAX_OBJ_NAME : xcopy->targetlen;
		strncpy(rio->src_name, xcopy->target, end);
		rio->src_name[end] = 0;

		rio->buf = malloc(req->size);
		if (!rio->buf) {
			r = -1;
			goto out_src;
		}

		rio->state = READING;
		rio->read = 0;
		XSEGLOG2(&lc, I, "Reading %s", rio->src_name);
		if (do_aio_generic(peer, pr, X_READ, rio->src_name, rio->buf + rio->read,
			req->size - rio->read, req->offset + rio->read) < 0) {
			XSEGLOG2(&lc, I, "Reading of %s failed on do_aio_read", rio->obj_name);
			fail(peer, pr);
			r = -1;
			goto out_buf;
		}
	}
	else if (rio->state == READING){
		XSEGLOG2(&lc, I, "Reading of %s callback", rio->obj_name);
		if (pr->retval > 0)
			rio->read += pr->retval;
		else if (pr->retval == 0) {
			XSEGLOG2(&lc, I, "Reading of %s reached end of file at "
				"%llu bytes. Zeroing out rest",	rio->obj_name,
				(unsigned long long) req->serviced);
			memset(rio->buf + rio->read, 0, req->size - rio->read);
			rio->read = req->size ;
		}
		else {
			XSEGLOG2(&lc, E, "Reading of %s failed", rio->src_name);
			r = -1;
			goto out_buf;
		}

		if (rio->read >= req->size) {
			XSEGLOG2(&lc, I, "Reading of %s completed", rio->obj_name);
			//do_aio_write
			rio->state = WRITING;
			XSEGLOG2(&lc, I, "Writing %s", rio->obj_name);
			if (do_aio_generic(peer, pr, X_WRITE, rio->obj_name,
					rio->buf, req->size, req->offset) < 0) {
				XSEGLOG2(&lc, E, "Writing of %s failed on do_aio_write", rio->obj_name);
				r = -1;
				goto out_buf;
			}
			return 0;
		}

		XSEGLOG2(&lc, I, "Resubmitting read of %s", rio->obj_name);
		if (do_aio_generic(peer, pr, X_READ, rio->src_name, rio->buf + rio->read,
			req->size - rio->read, req->offset + rio->read) < 0) {
			XSEGLOG2(&lc, E, "Reading of %s failed on do_aio_read",
					rio->obj_name);
			r = -1;
			goto out_buf;
		}
	}
	else if (rio->state == WRITING){
		XSEGLOG2(&lc, I, "Writing of %s callback", rio->obj_name);
		if (pr->retval == 0) {
			XSEGLOG2(&lc, I, "Writing of %s completed", rio->obj_name);
			XSEGLOG2(&lc, I, "Copy of object %s to object %s completed", rio->src_name, rio->obj_name);
			req->serviced = req->size;
			r = 0;
			goto out_buf;
		}
		else {
			XSEGLOG2(&lc, E, "Writing of %s failed", rio->obj_name);
			XSEGLOG2(&lc, E, "Copy of object %s to object %s failed", rio->src_name, rio->obj_name);
			r = -1;
			goto out_buf;
		}
	}
	else {
		XSEGLOG2(&lc, E, "Unknown state");
	}
	return 0;


out_buf:
	free(rio->buf);
out_src:
	free(rio->src_name);

	rio->buf = NULL;
	rio->src_name = NULL;
	rio->read = 0;

	if (r < 0)
		fail(peer ,pr);
	else
		complete(peer, pr);
	return 0;
}

int spawnthread(struct peerd *peer, struct peer_req *pr,
			void *(*func)(void *arg))
{
	//struct radosd *rados = (struct radosd *) peer->priv;
	struct rados_io *rio = (struct rados_io *) (pr->priv);

	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	return (pthread_create(&rio->tid, &attr, func, (void *) pr));
}

void watch_cb(uint8_t opcode, uint64_t ver, void *arg)
{
	//assert pr valid
	struct peer_req *pr = (struct peer_req *)arg;
	//struct radosd *rados = (struct radosd *) pr->peer->priv;
	struct rados_io *rio = (struct rados_io *) (pr->priv);

	if (pr->req->op == X_OPEN){
		XSEGLOG2(&lc, I, "watch cb signaling rio of %s", rio->obj_name);
		pthread_cond_signal(&rio->cond);
	}
	else
		XSEGLOG2(&lc, E, "Invalid req op in watch_cb");
}

void * lock_op(void *arg)
{
	struct peer_req *pr = (struct peer_req *)arg;
	struct radosd *rados = (struct radosd *) pr->peer->priv;
	struct rados_io *rio = (struct rados_io *) (pr->priv);
	uint32_t len = strlen(rio->obj_name);
	strncpy(rio->obj_name + len, LOCK_SUFFIX, LOCK_SUFFIX_LEN);
	rio->obj_name[len + LOCK_SUFFIX_LEN] = 0;

	XSEGLOG2(&lc, I, "Starting lock op for %s", rio->obj_name);
	if (!(pr->req->flags & XF_NOSYNC)){
		if (rados_watch(rados->ioctx, rio->obj_name, 0,
				&rio->watch_handle, watch_cb, pr) < 0){
			XSEGLOG2(&lc, E, "Rados watch failed for %s",
					rio->obj_name);
			fail(pr->peer, pr);
			return NULL;
		}
	}

	while(rados_lock(rados->ioctx, rio->obj_name, RADOS_LOCK_NAME,
		C_LOCK_EXCLUSIVE, RADOS_LOCK_COOKIE, "", "", NULL, 0) < 0){
		if (pr->req->flags & XF_NOSYNC){
			XSEGLOG2(&lc, E, "Rados lock failed for %s",
					rio->obj_name);
			fail(pr->peer, pr);
			return NULL;
		}
		else{
			XSEGLOG2(&lc, D, "rados lock for %s sleeping",
					rio->obj_name);
			pthread_mutex_lock(&rio->m);
			pthread_cond_wait(&rio->cond, &rio->m);
			pthread_mutex_unlock(&rio->m);
			XSEGLOG2(&lc, D, "rados lock for %s woke up",
					rio->obj_name);
		}
	}
	if (!(pr->req->flags & XF_NOSYNC)){
		if (rados_unwatch(rados->ioctx, rio->obj_name,
					rio->watch_handle) < 0){
			XSEGLOG2(&lc, E, "Rados unwatch failed");
		}
	}
	XSEGLOG2(&lc, I, "Successfull lock op for %s", rio->obj_name);
	complete(pr->peer, pr);
	return NULL;
}

void * unlock_op(void *arg)
{
	struct peer_req *pr = (struct peer_req *)arg;
	struct radosd *rados = (struct radosd *) pr->peer->priv;
	struct rados_io *rio = (struct rados_io *) (pr->priv);
	uint32_t len = strlen(rio->obj_name);
	strncpy(rio->obj_name + len, LOCK_SUFFIX, LOCK_SUFFIX_LEN);
	rio->obj_name[len + LOCK_SUFFIX_LEN] = 0;
	int r;
	XSEGLOG2(&lc, I, "Starting unlock op for %s", rio->obj_name);
	if (pr->req->flags & XF_FORCE)
		r = rados_break_lock(rados->ioctx, rio->obj_name, RADOS_LOCK_NAME,
			RADOS_LOCK_COOKIE);
	else
		r = rados_unlock(rados->ioctx, rio->obj_name, RADOS_LOCK_NAME,
			RADOS_LOCK_COOKIE);
	if (r < 0){
		XSEGLOG2(&lc, E, "Rados unlock failed for %s (r: %d)", rio->obj_name, r);
		fail(pr->peer, pr);
	}
	else {
		if (rados_notify(rados->ioctx, rio->obj_name, 
					0, NULL, 0) < 0) {
			XSEGLOG2(&lc, E, "rados notify failed");
		}
		XSEGLOG2(&lc, I, "Successfull unlock op for %s", rio->obj_name);
		complete(pr->peer, pr);
	}
	return NULL;
}

int handle_open(struct peerd *peer, struct peer_req *pr)
{
	int r = spawnthread(peer, pr, lock_op);
	if (r < 0)
		fail(pr->peer, pr);
	return 0;
}


int handle_close(struct peerd *peer, struct peer_req *pr)
{
	int r = spawnthread(peer, pr, unlock_op);
	if (r < 0)
		fail(pr->peer, pr);
	return 0;
}

int custom_peer_init(struct peerd *peer, int argc, char *argv[])
{
	int i, j;
	struct radosd *rados = malloc(sizeof(struct radosd));
	struct rados_io *rio;
	if (!rados) {
		perror("malloc");
		return -1;
	}
	rados->pool[0] = 0;
	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "--pool") && (i+1) < argc){
			strncpy(rados->pool, argv[i+1], MAX_POOL_NAME);
			rados->pool[MAX_POOL_NAME] = 0;
			i += 1;
			continue;
		}
	}
	if (!rados->pool[0]){
		XSEGLOG2(&lc, E , "Pool must be provided");
		free(rados);
		return -1;
	}

	if (rados_create(&rados->cluster, NULL) < 0) {
		XSEGLOG2(&lc, E, "Rados create failed!");
		return -1;
	}
	if (rados_conf_read_file(rados->cluster, NULL) < 0){
		XSEGLOG2(&lc, E, "Error reading rados conf files!");
		return -1;
	}
	if (rados_connect(rados->cluster) < 0) {
		XSEGLOG2(&lc, E, "Rados connect failed!");
		rados_shutdown(rados->cluster);
		free(rados);
		return 0;
	}
	if (rados_pool_lookup(rados->cluster, rados->pool) < 0) {
		XSEGLOG2(&lc, I, "Pool does not exists. I will try to create it");
		if (rados_pool_create(rados->cluster, rados->pool) < 0){
			XSEGLOG2(&lc, E, "Couldn't create pool %s", rados->pool);
			rados_shutdown(rados->cluster);
			free(rados);
			return -1;
		}
		XSEGLOG2(&lc, I, "Pool created.");
	}
	if (rados_ioctx_create(rados->cluster, rados->pool, &(rados->ioctx)) < 0){
		XSEGLOG2(&lc, E, "ioctx create problem.");
		rados_shutdown(rados->cluster);
		free(rados);
		return -1;
	}
	peer->priv = (void *) rados;
	for (i = 0; i < peer->nr_ops; i++) {
		rio = malloc(sizeof(struct rados_io));
		if (!rio) {
			//ugly
			//is this really necessary?
			for (j = 0; j < i; j++) {
				free(peer->peer_reqs[j].priv);
			}
			free(rados);
			perror("malloc");
			return -1;
		}
		rio->buf = 0;
		rio->read = 0;
		rio->size = 0;
		rio->src_name = 0;
		rio->watch_handle = 0;
		pthread_cond_init(&rio->cond, NULL);
		pthread_mutex_init(&rio->m, NULL);
		peer->peer_reqs[i].priv = (void *) rio;
	}
	return 0;
}

// nothing to do here for now
int custom_arg_parse(int argc, const char *argv[])
{
	return 0;
}

void custom_peer_finalize(struct peerd *peer)
{
	return;
}

int dispatch(struct peerd *peer, struct peer_req *pr, struct xseg_request *req,
		enum dispatch_reason reason)
{
	struct rados_io *rio = (struct rados_io *) (pr->priv);
	char *target = xseg_get_target(peer->xseg, pr->req);
	unsigned int end = (pr->req->targetlen > MAX_OBJ_NAME) ? MAX_OBJ_NAME : pr->req->targetlen;
	strncpy(rio->obj_name, target, end);
	rio->obj_name[end] = 0;
	//log_pr("dispatch", pr);
	if (reason == dispatch_accept)
		rio->state = ACCEPTED;

	switch (pr->req->op){
		case X_READ:
			handle_read(peer, pr); break;
		case X_WRITE: 
			handle_write(peer, pr); break;
		case X_DELETE:
			if (canDefer(peer))
				defer_request(peer, pr);
			else
				handle_delete(peer, pr);
			break;
		case X_INFO:
			if (canDefer(peer))
				defer_request(peer, pr);
			else
				handle_info(peer, pr);
			break;
		case X_COPY:
			if (canDefer(peer))
				defer_request(peer, pr);
			else
				handle_copy(peer, pr);
			break;
		case X_OPEN:
			handle_open(peer, pr); break;
		case X_CLOSE:
			handle_close(peer, pr); break;

		default:
			fail(peer, pr);
	}
	return 0;
}
