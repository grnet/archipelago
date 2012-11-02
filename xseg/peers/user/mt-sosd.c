#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <xseg/xseg.h>
#include <peer.h>
#include <rados/librados.h>
#include <xseg/protocol.h>

#define MAX_POOL_NAME 64
#define MAX_OBJ_NAME 256

enum rados_state {
	ACCEPTED = 0,
	PENDING = 1
};

struct radosd {
	rados_t cluster;
	rados_ioctx_t ioctx;
	char pool[MAX_POOL_NAME + 1];
};

struct rados_io{
	char obj_name[MAX_OBJ_NAME + 1];
	enum rados_state state;
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

int do_aio_read(struct peerd *peer, struct peer_req *pr)
{
	struct radosd *rados = (struct radosd *) peer->priv;
	struct xseg_request *req = pr->req;
	struct rados_io *rio = (struct rados_io *) pr->priv;
	char *data = xseg_get_data(peer->xseg, pr->req);
	int r;

	rados_completion_t rados_compl;
	r = rados_aio_create_completion(pr, rados_ack_cb, NULL, &rados_compl);
	if (r < 0) 
		return -1;
	r = rados_aio_read(rados->ioctx, rio->obj_name, rados_compl, 
			data + req->serviced,
			req->size - req->serviced,
			req->offset + req->serviced);
	if (r < 0) {
		rados_aio_release(rados_compl);
		return -1;
	}
	return 0;
}

int do_aio_write(struct peerd *peer, struct peer_req *pr)
{
	struct radosd *rados = (struct radosd *) peer->priv;
	struct xseg_request *req = pr->req;
	struct rados_io *rio = (struct rados_io *) pr->priv;
	char *data = xseg_get_data(peer->xseg, pr->req);
	int r;

	rados_completion_t rados_compl;
	r = rados_aio_create_completion(pr, NULL, rados_commit_cb, &rados_compl);
	if (r < 0) 
		return -1;
	r = rados_aio_write(rados->ioctx, rio->obj_name, rados_compl, 
			data + req->serviced,
			req->size - req->serviced,
			req->offset + req->serviced);
	if (r < 0) {
		rados_aio_release(rados_compl);
		return -1;
	}
	return 0;
}

int handle_delete(struct peerd *peer, struct peer_req *pr)
{
	int r;
	struct radosd *rados = (struct radosd *) peer->priv;
	struct rados_io *rio = (struct rados_io *) pr->priv;
	
	XSEGLOG2(&lc, I, "Deleting %s", rio->obj_name);
	r = rados_remove(rados->ioctx, rio->obj_name);
	if (r < 0) {
		pr->retval = r;
		XSEGLOG2(&lc, E, "Deletion of %s failed", rio->obj_name);
		fail(peer, pr);
	}
	else {
		pr->retval = 0;
		XSEGLOG2(&lc, E, "Deletion of %s completed", rio->obj_name);
		complete(peer, pr);
	}

	return 0;

/*
	int r;
	if (rio->state == ACCEPTED) {
		XSEGLOG2(&lc, I, "Deleting %s", rio->obj_name);
		rados_completion_t rados_compl;
		r = rados_aio_create_completion(pr, rados_ack_cb, NULL, &rados_compl);
		if (r < 0){ 
			XSEGLOG2(&lc, E, "Deletion of %s failed", rio->obj_name);
			fail(peer, pr);
			return 0;
		}
		r = rados_aio_remove(rados->ioctx, rio->obj_name, rados_compl); 
		if (r < 0) {
			rados_aio_release(rados_compl);
			XSEGLOG2(&lc, E, "Deletion of %s failed", rio->obj_name);
			fail(peer, pr);
			return 0;
		}
		rio->state = PENDING;
	}
	else {
		if (pr->retval < 0){
			XSEGLOG2(&lc, E, "Deletion of %s failed", rio->obj_name);
			fail(peer, pr);
		} 
		else {
			XSEGLOG2(&lc, E, "Deletion of %s completed", rio->obj_name);
			complete(peer, pr);
		}
	}
	return 0;
*/
}

int handle_info(struct peerd *peer, struct peer_req *pr)
{
	uint64_t size;
	time_t pmtime;
	int r;
	struct xseg_request *req = pr->req;
	struct radosd *rados = (struct radosd *) peer->priv;
	struct rados_io *rio = (struct rados_io *) pr->priv;
	char *req_data = xseg_get_data(peer->xseg, req);
	struct xseg_reply_info *xinfo = req_data;

	XSEGLOG2(&lc, I, "Getting info of %s", rio->obj_name);	
	r = rados_stat(rados->ioctx, rio->obj_name, &size, &pmtime);
	if (r < 0) {
		pr->retval = r;
		XSEGLOG2(&lc, I, "Getting info of %s failed", rio->obj_name);	
		fail(peer, pr);
	}
	else {
		xinfo->size = size;
		pr->retval = sizeof(uint64_t);
		XSEGLOG2(&lc, I, "Getting info of %s completed", rio->obj_name);	
		complete(peer,pr);
	}
	return 0;
}

//FIXME req->state no longer apply
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
		//should we ensure req->op = X_READ ?
		rio->state = PENDING;
		XSEGLOG2(&lc, I, "Reading %s", rio->obj_name);
		if (do_aio_read(peer, pr) < 0) {
			XSEGLOG2(&lc, I, "Reading of %s failed on do_aio_read", rio->obj_name);
			fail(peer, pr);
		}
	}
	else if (rio->state == PENDING) {
		XSEGLOG2(&lc, I, "Reading of %s callback", rio->obj_name);
		data = xseg_get_data(peer->xseg, pr->req);
		if (pr->retval > 0) 
			req->serviced += pr->retval;
		else if (pr->retval == 0) {
			XSEGLOG2(&lc, I, "Reading of %s reached end of file at %llu bytes. Zeroing out rest", 
						rio->obj_name, (unsigned long long) req->serviced);
			/* reached end of object. zero out rest of data
			 * requested from this object
			 */
			memset(data + req->serviced, 0, req->datalen - req->serviced);
			req->serviced = req->datalen ;
		}
		else if (pr->retval == -2) {
			XSEGLOG2(&lc, I, "Reading of %s return -2. Zeroing out data", rio->obj_name);
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
		//TODO assert req->op == X_READ
		
		/* resubmit */
		XSEGLOG2(&lc, I, "Resubmitting read of %s", rio->obj_name);
		if (do_aio_read(peer, pr) < 0) {
			XSEGLOG2(&lc, E, "Reading of %s failed on do_aio_read", rio->obj_name);
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
		rio->state = PENDING;
		XSEGLOG2(&lc, I, "Writing %s", rio->obj_name);
		if (do_aio_write(peer, pr) < 0) {
			XSEGLOG2(&lc, E, "Writing of %s failed on do_aio_write", rio->obj_name);
			fail(peer, pr);
		}
	}
	else if (rio->state == PENDING) {
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
	struct radosd *rados = (struct radosd *) peer->priv;
	struct xseg_request *req = pr->req;
	struct rados_io *rio = (struct rados_io *) pr->priv;
	int r, sum;
	char *buf, src_name[MAX_OBJ_NAME + 1];
	struct xseg_request_copy *xcopy = xseg_get_data(peer->xseg, req);
	unsigned int end = (xcopy->targetlen > MAX_OBJ_NAME) ? MAX_OBJ_NAME : xcopy->targetlen;

	strncpy(src_name, xcopy->target, end);
	src_name[end] = 0;

	req->serviced = 0;
	buf = malloc(req->size);
	if (!buf) {
		fail(peer, pr);
		return -1;
	}
	XSEGLOG2(&lc, I, "Copy of object %s to object %s started", src_name, rio->obj_name);
	sum = 0;
	do {
		r = rados_read(rados->ioctx, src_name, buf, req->size, 0);
		if (r < 0){
			XSEGLOG2(&lc, E, "Read of object %s failed", src_name);
			goto out_fail;
		}
		else if (r == 0) {
			memset(buf+r, 0, req->size - r);
			sum = req->size;
		} else 
			sum += r;
	} while (sum < req->size);
	XSEGLOG2(&lc, D, "Read of object %s Completed", src_name);

	r = rados_write_full(rados->ioctx, rio->obj_name, buf, req->size);
	if (r < 0){
		XSEGLOG2(&lc, E, "Write of object %s failed", rio->obj_name);
		goto out_fail;
	}
	
	free(buf);
	req->serviced = req->size;
	XSEGLOG2(&lc, I, "Copy of object %s to object %s completed", src_name, rio->obj_name);
	complete(peer, pr);
	return 0;

out_fail:
	free(buf);
	pr->retval = -1;
	XSEGLOG2(&lc, E, "Copy of object %s to object %s failed", src_name, rio->obj_name);
	fail(peer, pr);
	return 0;



/*
	struct radosd *rados = (struct radosd *) peer->priv;
	struct xseg_request *req = pr->req;
	struct rados_io *rio = (struct rados_io *) pr->priv;
	int r, sum;
	char *buf, *src_name;
	struct xseg_request_copy *xcopy = xseg_get_data(peer->xseg, req);

	if (rio->state == ACCEPTED){
		XSEGLOG2(&lc, I, "Copy of object %s to object %s started", src_name, rio->obj_name);
		if (!req->size) {
			complete(peer, pr); //or fail?
			return 0;
		}
		src_name = malloc(MAX_OBJ_NAME + 1);
		if (!src_name){
			fail(peer, pr);
			return -1;
		}
		unsigned int end = (xcopy->targetlen > MAX_OBJ_NAME) ? MAX_OBJ_NAME : xcopy->targetlen;
		strncpy(src_name, xcopy->target, end);
		src_name[end] = 0;
		req->serviced = 0;
		buf = malloc(req->size);
		if (!buf) {
			fail(peer, pr);
			return -1;
		}
		rio->state = READING;
		XSEGLOG2(&lc, I, "Reading %s", rio->obj_name);
		if (do_aio_read(peer, pr, src_name, buf) < 0) {
			XSEGLOG2(&lc, I, "Reading of %s failed on do_aio_read", rio->obj_name);
			fail(peer, pr);
			return 0;
		}
	}
	else if (rio->state == READING){
		XSEGLOG2(&lc, I, "Reading of %s callback", rio->obj_name);
		if (pr->retval > 0) 
			status->read += pr->retval;
		else if (pr->retval == 0) {
			XSEGLOG2(&lc, I, "Reading of %s reached end of file at %llu bytes. Zeroing out rest", 
						rio->obj_name, (unsigned long long) req->serviced);
			memset(buf + status->read, 0, req->size - status->read);
			status->read = req->size ;
		}
		else {
			XSEGLOG2(&lc, E, "Reading of %s failed", rio->obj_name);
			fail(peer, pr);
			return 0;
		}
		if (status->read >= req->size) {
			XSEGLOG2(&lc, I, "Reading of %s completed", rio->obj_name);
			//do_aio_write
			rio->state = WRITING;
			XSEGLOG2(&lc, I, "Writing %s", rio->obj_name);
			if (do_aio_write(peer, pr, rio->obj_name, status->buf) < 0) {
				XSEGLOG2(&lc, E, "Writing of %s failed on do_aio_write", rio->obj_name);
				fail(peer, pr);
			}
			return 0;
		}

		if (!req->size) {
			fail(peer, pr);
			return 0;
		}
		XSEGLOG2(&lc, I, "Resubmitting read of %s", rio->obj_name);
		if (do_aio_read(peer, pr, src_name, status->buf+status->read ) < 0) {
			XSEGLOG2(&lc, E, "Reading of %s failed on do_aio_read", rio->obj_name);
			fail(peer, pr);
		}
	}
	else if (rio->state == WRITING){
		XSEGLOG2(&lc, I, "Writing of %s callback", rio->obj_name);
		free(buf);
		if (pr->retval == 0) {
			XSEGLOG2(&lc, I, "Copy of object %s to object %s completed", src_name, rio->obj_name);
			XSEGLOG2(&lc, I, "Writing of %s completed", rio->obj_name);
			req->serviced = req->size;
			complete(peer, pr);
			return 0;
		}
		else {
			XSEGLOG2(&lc, E, "Writing of %s failed", rio->obj_name);
			XSEGLOG2(&lc, E, "Copy of object %s to object %s failed", src_name, rio->obj_name);
			fail(peer, pr);
			return 0;
		}
	}
	else {
		XSEGLOG2(&lc, E, "Unknown state");
	}
	*/
}

int handle_open(struct peerd *peer, struct peer_req *pr)
{
	/* FIXME to be implemented */
	complete(peer, pr);
	return 0;
}


int handle_close(struct peerd *peer, struct peer_req *pr)
{
	/* FIXME to be implemented */
	complete(peer, pr);
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
		free(rados);
		return -1;
	}

	if (rados_create(&rados->cluster, NULL) < 0) {
		printf("Rados create failed!\n");
		return -1;
	}
	if (rados_conf_read_file(rados->cluster, NULL) < 0){
		printf("Error reading rados conf files!\n");
		return -1;
	}
	if (rados_connect(rados->cluster) < 0) {
		printf("Rados connect failed!\n");
		rados_shutdown(rados->cluster);
		free(rados);
		return 0;
	}
	if (rados_pool_lookup(rados->cluster, rados->pool) < 0) {
		printf( "Pool does not exists. I will try to create it\n");
		if (rados_pool_create(rados->cluster, rados->pool) < 0){
			printf("Couldn't create pool!\n");
			rados_shutdown(rados->cluster);
			free(rados);
			return -1;
		}
		printf("Pool created.\n");
	}
	if (rados_ioctx_create(rados->cluster, rados->pool, &(rados->ioctx)) < 0) {
		printf("ioctx create problem.\n");
		rados_shutdown(rados->cluster);
		free(rados);
		return -1;
	}
	peer->priv = (void *) rados;
	for (i = 0; i < peer->nr_ops; i++) {
		rio = malloc(sizeof(struct rados_io));
		if (!rio) {
			//ugly
			for (j = 0; j < i; j++) {
				free(peer->peer_reqs[j].priv);
			}
			free(rados);
			perror("malloc");
			return -1;
		}
		peer->peer_reqs[i].priv = (void *) rio;
	}
	return 0;
}

// nothing to do here for now
int custom_arg_parse(int argc, const char *argv[])
{
	return 0;
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
