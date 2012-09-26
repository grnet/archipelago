#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <xseg/xseg.h>
#include <mpeer.h>
#include <rados/librados.h>

#define MAX_POOL_NAME 64
#define MAX_OBJ_NAME 256

struct radosd {
	rados_t cluster;
	rados_ioctx_t ioctx;
	char pool[MAX_POOL_NAME];
};

struct rados_io{
	char obj_name[MAX_OBJ_NAME];
};

void rados_ack_cb(rados_completion_t c, void *arg)
{
	struct peer_req *pr = (struct peer_req*) arg;
	struct peerd *peer = pr->peer;
	int ret = rados_aio_get_return_value(c);
	pr->retval = ret;
	rados_aio_release(c);
	dispatch(peer, pr, pr->req);
}

void rados_commit_cb(rados_completion_t c, void *arg)
{
	struct peer_req *pr = (struct peer_req*) arg;
	struct peerd *peer = pr->peer;
	int ret = rados_aio_get_return_value(c);
	pr->retval = ret;
	rados_aio_release(c);
	dispatch(peer, pr, pr->req);
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
	
	//log_pr("delete start", pr);
	r = rados_remove(rados->ioctx, rio->obj_name);
	if (r < 0) {
		pr->retval = r;
		fail(peer, pr);
	}
	else {
		pr->retval = 0;
		complete(peer, pr);
	}
	return 0;
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

	log_pr("info start", pr);
	
	r = rados_stat(rados->ioctx, rio->obj_name, &size, &pmtime);
	if (r < 0) {
		pr->retval = r;
		fail(peer, pr);
	}
	else {
		*((uint64_t *) req_data) = size;
		pr->retval = sizeof(uint64_t);
		complete(peer,pr);
	}
	return 0;
}

int handle_read(struct peerd *peer, struct peer_req *pr)
{
	struct xseg_request *req = pr->req;
	char *data;
	if (req->state == XS_ACCEPTED) {
		if (!req->size) {
			complete(peer, pr);
			return 0;
		}
		//should we ensure req->op = X_READ ?
		pending(peer, pr);
		log_pr("read", pr);
		if (do_aio_read(peer, pr) < 0) {
			fail(peer, pr);
		}
	}
	else if (req->state == XS_PENDING) {
		data = xseg_get_data(peer->xseg, pr->req);
		if (pr->retval > 0) 
			req->serviced += pr->retval;
		else if (pr->retval == 0) {
			/* reached end of object. zero out rest of data
			 * requested from this object
			 */
			memset(data, 0, req->datalen - req->serviced);
			req->serviced = req->datalen ;
		}
		else if (pr->retval == -2) {
			/* object not found. return zeros instead */
			memset(data, 0, req->datalen);
			req->serviced = req->datalen;
		}
		else {
			/* pr->retval < 0 && pr->retval != -2 */
			fail(peer, pr);
			return 0;
		}
		if (req->serviced >= req->datalen) {
			log_pr("read complete", pr);
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
		log_pr("read resubmit", pr);
		if (do_aio_read(peer, pr) < 0) {
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
	struct xseg_request *req = pr->req;
	if (req->state == XS_ACCEPTED) {
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
		pending(peer, pr);
		//log_pr("write", pr);
		if (do_aio_write(peer, pr) < 0) {
			fail(peer, pr);
		}
	}
	else if (req->state == XS_PENDING) {
		/* rados writes return 0 if write succeeded or < 0 if failed
		 * no resubmission occurs
		 */
		//log_pr("write complete", pr);
		if (pr->retval == 0) {
			req->serviced = req->datalen;
			complete(peer, pr);
			return 0;
		}
		else {
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


int custom_peer_init(struct peerd *peer, int argc, char *argv[])
{
	int i, j;
	struct radosd *rados = malloc(sizeof(struct radosd));
	struct rados_io *rio;
	if (!rados) {
		perror("malloc");
		return -1;
	}
	//TODO this should be a parameter. maybe -r (from rados)?
	strncpy(rados->pool, "xseg", MAX_POOL_NAME);
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

int dispatch(struct peerd *peer, struct peer_req *pr, struct xseg_request *req)
{
	struct rados_io *rio = (struct rados_io *) (pr->priv);
	char *target = xseg_get_target(peer->xseg, pr->req);
	unsigned int end = (pr->req->targetlen > MAX_OBJ_NAME -1 )? MAX_OBJ_NAME - 1 : pr->req->targetlen;
	strncpy(rio->obj_name, target, end);
	rio->obj_name[end] = 0;
	//log_pr("dispatch", pr);
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
	default:
		fail(peer, pr);
	}
	return 0;
}
