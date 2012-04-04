/* sos.c
 *
 * Giannakos Filippos <philipgian@cslab.ece.ntua.gr>
 *
 */

#include "sos.h"
#include <stdlib.h>
#include <stdio.h>
#include <rados/librados.h>
#ifdef __SOS_TIME
#include <sys/time.h>
#endif

#define REARRANGE(__fun_name__, __format__, ...) __format__ "%s", __fun_name__, ##__VA_ARGS__
#define SOSLOG(level, ...)                                              \
        do {                                                                    \
                if (level <=  sos_debug_level) {                                \
                        fprintf(stderr, "%s: "  REARRANGE( __func__ , ## __VA_ARGS__, "" )); \
                }                                                               \
        }while (0)

#define MAX_NAME_LEN 256

struct sos_handle {
	rados_t cluster;
	rados_ioctx_t ioctx;
	sos_cb_t cb;
	char *sos_pool;
};

struct rados_arg {
	sos_handle_t sos;
	struct sos_request *req;
	volatile unsigned long state;
	char obj_name[MAX_NAME_LEN];
#ifdef __SOS_TIME
	struct timeval start;
#endif
};

/* sos debug level */
volatile unsigned int sos_debug_level=0;

void sos_set_debug_level(unsigned int level)
{
	sos_debug_level = level;
}

static int handle_io(sos_handle_t sos, struct sos_request *req);

sos_handle_t sos_init(sos_cb_t cb)
{
	sos_handle_t sos = (sos_handle_t) malloc(sizeof(struct sos_handle));
	sos->cb = cb;

	if (rados_create(&sos->cluster, NULL) < 0) {
		printf("Rados create failed!\n");
		return NULL;
	}
	SOSLOG(1, "Rados create OK \n");
	if (rados_conf_read_file(sos->cluster, NULL) < 0){
		SOSLOG(0, "Error reading rados conf files!\n");
		return NULL;
	}
	if (rados_connect(sos->cluster) < 0) {
		SOSLOG(0, "Rados connect failed!\n");
		rados_shutdown(sos->cluster);
		free(sos);
		return NULL;
	}
	SOSLOG(1, "Rados connect OK \n");
	if (rados_pool_lookup(sos->cluster, SOS_POOL) < 0) {
		SOSLOG(0, "Pool does not exists. I will try to create it\n");
		if (rados_pool_create(sos->cluster, SOS_POOL) < 0){
			SOSLOG(0, "Couldn't create pool!\n");
			rados_shutdown(sos->cluster);
			free(sos);
		return NULL;
		}
		SOSLOG(1, "Pool created.\n");
	}
	if (rados_ioctx_create(sos->cluster, SOS_POOL, &(sos->ioctx)) < 0) {
		SOSLOG(0, "ioctx create problem.\n");
		rados_shutdown(sos->cluster);
		free(sos);
		return NULL;
	}

	return sos;
}

void sos_shut(sos_handle_t sos)
{
	rados_ioctx_destroy(sos->ioctx);
	rados_shutdown(sos->cluster);
	free(sos);
	return;
}

int sos_submit(sos_handle_t sos, struct sos_request *req)
{
	int r;
	switch (req->op){
	case S_READ:
	case S_WRITE:
		r =handle_io(sos, req);
		break;
	case S_NONE:
	default:
		r = -1;
	}
	return r;
}


int sos_isRead(struct sos_request *req)
{
	/* lets define this for now */
	return (req->op == S_READ);
}


void rados_ack_cb(rados_completion_t c, void *arg)
{
	int ret = rados_aio_get_return_value(c);
	struct rados_arg *rarg = (struct rados_arg *) arg;
	sos_handle_t sos = rarg->sos;
	struct sos_request *req = rarg->req;

#ifdef __SOS_TIME
	/* calculate time for ack */
	struct timeval tv;
	unsigned long us;
	gettimeofday(&tv, NULL);
	timersub(&tv, &rarg->start, &tv);
	us = tv.tv_sec*1000000 +tv.tv_usec;
	SOSLOG(2, "Request %lu acked after %lu us\n", req->id, us);
#endif
	SOSLOG(2, "Request %lu acked with ret value %d \n", req->id, ret);

	/* rados writes return 0 upon success or an error code. so fix retval to
	 * represent bytes succesfully written.
	 */
	if (req->op == S_WRITE && ret == 0)
		req->retval = req->size;
	else	
		req->retval = ret;
	if (ret < 0) {
		sos->cb(req, S_NOTIFY_FAIL);
		rarg->state = S_FAILED;
	}
	else {
		sos->cb(req, S_NOTIFY_ACK);
		rarg->state = S_ACKED;
	}
	/* substitute with rarg->istherecommit ? */
	if (sos_isRead(req) || !(req->flags & SF_FUA)){
		/* no commit, so free rarg */
		free(rarg);
		rados_aio_release(c);
	}
}

void rados_commit_cb(rados_completion_t c, void *arg)
{
	int ret = rados_aio_get_return_value(c);
	struct rados_arg *rarg = (struct rados_arg *) arg;
	sos_handle_t sos = rarg->sos;
	struct sos_request *req = rarg->req;

#ifdef __SOS_TIME	
	/* calculate time for commit */
	struct timeval tv;
	unsigned long us;
	gettimeofday(&tv, NULL);
	timersub(&tv, &rarg->start, &tv);
	us = tv.tv_sec*1000000 +tv.tv_usec;
	SOSLOG(2, "Request %lu commited after %lu us\n", req->id, us);
#endif
	SOSLOG(2, "Request %lu commited with ret value %d \n", req->id, ret);
	
	/* rados writes return 0 upon success or an error code. so fix retval to
	 * represent bytes succesfully written.
	 */
	if (req->op == S_WRITE && ret == 0)
		req->retval = req->size;
	else	
		req->retval = ret;
	if (ret < 0 && !(rarg->state & S_FAILED)) {
		/* notify failure only once */
		sos->cb(req, S_NOTIFY_FAIL);
	}
	/* discard failed commits with failed acks */
	else if (ret >= 0 ) {
		sos->cb(req, S_NOTIFY_COMMIT);
	}
	free(rarg); 
	rados_aio_release(c);
}

static int handle_async_io(sos_handle_t sos, struct sos_request *req){
	int r;
	rados_completion_t rados_compl;
	struct rados_arg *rarg;
	if (req->namesize >= MAX_NAME_LEN){
		req->retval = -1;
		return -1;
	}
	rarg = malloc(sizeof(struct rados_arg));
	if (!rarg){
		return -1;
	}
	rarg->sos = sos;
	rarg->req = req;
	rarg->state = S_PENDING;
	strncpy(rarg->obj_name, req->name, req->namesize);
       	rarg->obj_name[req->namesize]=0;
	SOSLOG(2, "Request %lu assigned to object[%u]: %s  \n", req->id, \
			req->namesize, rarg->obj_name);
	
#ifdef __SOS_TIME	
	/* set time request started */
	gettimeofday(&rarg->start, NULL);
#endif
	if (!sos_isRead(req) && (req->flags & SF_FUA))
		r = rados_aio_create_completion(rarg,NULL, rados_commit_cb,
			       	&rados_compl);
	else	
		r = rados_aio_create_completion(rarg, rados_ack_cb, NULL, 
				&rados_compl);
	if (r < 0) {
		free (rarg);
		return r;
	}

	if (sos_isRead(req)) {
		r = rados_aio_read(sos->ioctx, rarg->obj_name, rados_compl,
				req->data, req->size, req->offset);
	}
	else {
		r = rados_aio_write(sos->ioctx, rarg->obj_name, rados_compl, 
				req->data, req->size, req->offset);
	}
	if (r < 0){ 
		rados_aio_release(rados_compl);
		free (rarg);
	}
	
	return r;
}

static int handle_sync_io(sos_handle_t sos, struct sos_request *req){
	int r;
	rados_completion_t rados_compl;
	struct rados_arg *rarg;
	if (req->namesize >= MAX_NAME_LEN){
		req->retval = -1;
		return -1;
	}
	rarg = malloc(sizeof(struct rados_arg));
	if (!rarg){
		return -1;
	}
	rarg->sos = sos;
	rarg->req = req;
	rarg->state = S_PENDING;
	strncpy(rarg->obj_name, req->name, req->namesize);
       	rarg->obj_name[req->namesize]=0;
	SOSLOG(2, "Request %lu assigned to object[%u]: %s  \n", req->id, \
			req->namesize, rarg->obj_name);
#ifdef __SOS_TIME	
	/* set time request started */
	gettimeofday(&rarg->start, NULL);
#endif
	
	if (sos_isRead(req)) {
		r = rados_read(sos->ioctx, rarg->obj_name, req->data, req->size,
			       	req->offset);
	}
	else {
		if (req->flags & SF_FUA) {
			r = rados_aio_create_completion(rarg,NULL, NULL,
				       &rados_compl);
			if (r < 0)
				goto syncio_exit;
			r = rados_aio_write(sos->ioctx, rarg->obj_name, rados_compl,
					req->data, req->size, req->offset);
			if (r < 0){
				rados_aio_release(rados_compl);
				goto syncio_exit;
			}
			r = rados_aio_wait_for_safe(rados_compl);
			rados_aio_release(rados_compl);
			/* there is no sync FUA. rados should be patched to support 
			 * sync safe writes.

			r = rados_safe_write(sos->ioctx, rarg->obj_name, req->data, 
					req->size, req->offset);
			 */
		}
		else {
			r = rados_write(sos->ioctx, rarg->obj_name, req->data, 
					req->size, req->offset);
			/* TODO does return value need to be fixed as in aio write ? */
		}
	}
syncio_exit:
	free(rarg);
	req->retval = r;
	return r;
}

static int handle_io(sos_handle_t sos, struct sos_request *req)
{
	int r;
	if (!req->size && req->flags & SF_FLUSH){
		r = rados_aio_flush(sos->ioctx);
		req->retval = r;
		return r;
	}
	if (req->flags & SF_SYNC)
		r = handle_sync_io(sos,req);
	else 
		r = handle_async_io(sos,req);

	return r;
}
