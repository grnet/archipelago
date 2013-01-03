/*
 * Copyright 2012 GRNET S.A. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 *   1. Redistributions of source code must retain the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer.
 *   2. Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials
 *      provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY GRNET S.A. ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL GRNET S.A OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and
 * documentation are those of the authors and should not be
 * interpreted as representing official policies, either expressed
 * or implied, of GRNET S.A.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <xseg/xseg.h>
#include <xseg/protocol.h>
#include <peer.h>
#include <sched.h>
#include <sys/syscall.h>

enum io_state_enum {
	ACCEPTED = 0,
	MAPPING = 1,
	SERVING = 2,
	CONCLUDED = 3
};

#define VF_VOLUME_FREEZED (1 << 0)

struct volume_info{
	char name[XSEG_MAX_TARGETLEN + 1];
	uint32_t flags;
	uint32_t active_reqs;
	struct xq *pending_reqs;
	struct peer_req *pending_pr;
};

struct vlmcd {
	xport mportno;
	xport bportno;
	xhash_t *volumes; //hash [volumename] -> struct volume_info
};

struct vlmc_io {
	int err;
	struct xlock lock;
	volatile enum io_state_enum state;
	struct xseg_request *mreq;
	struct xseg_request **breqs;
	unsigned long breq_len, breq_cnt;
};

void custom_peer_usage()
{
	fprintf(stderr, "Custom peer options: \n"
			"-mp : mapper port\n"
			"-bp : blocker port for blocks\n"
			"\n");
}

static inline void __set_vio_state(struct vlmc_io *vio, enum io_state_enum state)
{
	vio->state = state;
}

static inline enum io_state_enum __get_vio_state(struct vlmc_io *vio)
{
	enum io_state_enum state;
	state = vio->state;
	return state;
}

static inline struct vlmc_io * __get_vlmcio(struct peer_req *pr)
{
	return (struct vlmc_io *) pr->priv;
}

static inline struct vlmcd * __get_vlmcd(struct peerd *peer)
{
	return (struct vlmcd *) peer->priv;
}

static struct xq * allocate_queue(xqindex nr)
{
	struct xq *q = malloc(sizeof(struct xq));
	if (!q)
		return NULL;
	if (!xq_alloc_empty(q, nr)){
		free(q);
		return NULL;
	}
	return q;
}

static int doubleup_queue(struct volume_info *vi)
{
	//assert vi->pending_reqs
	struct xq *newq = allocate_queue(vi->pending_reqs->size * 2);
	if (!newq)
		return -1;

	if (__xq_resize(vi->pending_reqs, newq) == Noneidx){
		xq_free(newq);
		free(newq);
		return -1;
	}
	xq_free(vi->pending_reqs);
	free(vi->pending_reqs);
	vi->pending_reqs = newq;
	return 0;
}

static struct volume_info * find_volume(struct vlmcd *vlmc, char *volume)
{
	struct volume_info *vi = NULL;
	int r = xhash_lookup(vlmc->volumes, (xhashidx) volume,
			(xhashidx *) &vi);
	if (r < 0)
		return NULL;
	return vi;
}

static struct volume_info * find_volume_len(struct vlmcd *vlmc, char *target,
						uint32_t targetlen)
{
	char buf[XSEG_MAX_TARGETLEN+1];
	strncpy(buf, target, targetlen);
	buf[targetlen] = 0;
	XSEGLOG2(&lc, D, "looking up volume %s, len %u",
			buf, targetlen);
	return find_volume(vlmc, buf);

}

static int insert_volume(struct vlmcd *vlmc, struct volume_info *vi)
{
	int r = -1;

	if (find_volume(vlmc, vi->name)){
		XSEGLOG2(&lc, W, "Volume %s found in hash", vi->name);
		return r;
	}

	XSEGLOG2(&lc, D, "Inserting volume %s, len: %d (volume_info: %lx)", 
			vi->name, strlen(vi->name), (unsigned long) vi);
	r = xhash_insert(vlmc->volumes, (xhashidx) vi->name, (xhashidx) vi);
	while (r == -XHASH_ERESIZE) {
		xhashidx shift = xhash_grow_size_shift(vlmc->volumes);
		xhash_t *new_hashmap = xhash_resize(vlmc->volumes, shift, NULL);
		if (!new_hashmap){
			XSEGLOG2(&lc, E, "Cannot grow vlmc->volumes to sizeshift %llu",
					(unsigned long long) shift);
			return r;
		}
		vlmc->volumes = new_hashmap;
		r = xhash_insert(vlmc->volumes, (xhashidx) vi->name, (xhashidx) vi);
	}

	return r;

}

static int remove_volume(struct vlmcd *vlmc, struct volume_info *vi)
{
	int r = -1;

	r = xhash_delete(vlmc->volumes, (xhashidx) vi->name);
	while (r == -XHASH_ERESIZE) {
		xhashidx shift = xhash_shrink_size_shift(vlmc->volumes);
		xhash_t *new_hashmap = xhash_resize(vlmc->volumes, shift, NULL);
		if (!new_hashmap){
			XSEGLOG2(&lc, E, "Cannot shrink vlmc->volumes to sizeshift %llu",
					(unsigned long long) shift);
			return r;
		}
		vlmc->volumes = new_hashmap;
		r = xhash_delete(vlmc->volumes, (xhashidx) vi->name);
	}

	return r;
}

static int do_accepted_pr(struct peerd *peer, struct peer_req *pr);

static int conclude_pr(struct peerd *peer, struct peer_req *pr)
{
	struct vlmcd *vlmc = __get_vlmcd(peer);
	struct vlmc_io *vio = __get_vlmcio(pr);
	char *target = xseg_get_target(peer->xseg, pr->req);
	struct volume_info *vi = find_volume_len(vlmc, target, pr->req->targetlen);

	__set_vio_state(vio, CONCLUDED);
	if (vio->err)
		fail(peer, pr);
	else
		complete(peer, pr);

	if (vi){
		//assert vi->active_reqs > 0
		uint32_t ar = --vi->active_reqs;
		if (!ar && vi->pending_pr)
			do_accepted_pr(peer, vi->pending_pr);
	}
	return 0;
}

static int do_accepted_pr(struct peerd *peer, struct peer_req *pr)
{
	struct vlmcd *vlmc = __get_vlmcd(peer);
	struct vlmc_io *vio = __get_vlmcio(pr);
	int r;
	xport p;
	char *target, *mtarget;
	void *dummy;

	struct volume_info *vi;

	target = xseg_get_target(peer->xseg, pr->req);
	if (!target)
		goto out_err;

	vi = find_volume_len(vlmc, target, pr->req->targetlen);
	if (!vi){
		XSEGLOG2(&lc, E, "Cannot find volume");
		goto out_err;
	}

	if (pr->req->op == X_CLOSE || pr->req->op == X_SNAPSHOT){
		vi->flags |= VF_VOLUME_FREEZED;
		if (vi->active_reqs){
			//assert vi->pending_pr == NULL;
			vi->pending_pr = pr;
			return 0;
		}
		else {
			//assert vi->pending_pr == pr
			vi->pending_pr = NULL;
		}
	}

	vi->active_reqs++;

	vio->err = 0; //reset error state

	if (pr->req->op == X_WRITE && !pr->req->size &&
			(pr->req->flags & (XF_FLUSH|XF_FUA))){
		//hanlde flush requests here, so we don't mess with mapper
		//because of the -1 offset
		XSEGLOG2(&lc, I, "Completing flush request");
		pr->req->serviced = pr->req->size;
		conclude_pr(peer, pr);
		return 0;
	}

	vio->mreq = xseg_get_request(peer->xseg, pr->portno,
					vlmc->mportno, X_ALLOC);
	if (!vio->mreq)
		goto out_err;

	/* use datalen 0. let mapper allocate buffer space as needed */
	r = xseg_prep_request(peer->xseg, vio->mreq, pr->req->targetlen, 0);
	if (r < 0) {
		goto out_put;
	}
	mtarget = xseg_get_target(peer->xseg, vio->mreq);
	if (!mtarget)
		goto out_put;

	strncpy(mtarget, target, pr->req->targetlen);
	vio->mreq->size = pr->req->size;
	vio->mreq->offset = pr->req->offset;
	vio->mreq->flags = 0;
	switch (pr->req->op) {
		case X_READ: vio->mreq->op = X_MAPR; break;
		case X_WRITE: vio->mreq->op = X_MAPW; break;
		case X_INFO: vio->mreq->op = X_INFO; break;
		case X_CLOSE: vio->mreq->op = X_CLOSE; break;
		case X_OPEN: vio->mreq->op = X_OPEN; break;
		case X_SNAPSHOT: vio->mreq->op = X_SNAPSHOT; break;
		default: goto out_put;
	}
	xseg_set_req_data(peer->xseg, vio->mreq, pr);
	__set_vio_state(vio, MAPPING);
	p = xseg_submit(peer->xseg, vio->mreq, pr->portno, X_ALLOC);
	if (p == NoPort)
		goto out_unset;
	r = xseg_signal(peer->xseg, p);
	if (r < 0) {
		/* since submission is successful, just print a warning message */
		XSEGLOG2(&lc, W, "Couldnt signal port %u", p);
	}

	return 0;

out_unset:
	xseg_get_req_data(peer->xseg, vio->mreq, &dummy);
out_put:
	xseg_put_request(peer->xseg, vio->mreq, pr->portno);
out_err:
	vio->err = 1;
	conclude_pr(peer, pr);
	return -1;
}

static int append_to_pending_reqs(struct volume_info *vi, struct peer_req *pr)
{
	if (!vi->pending_reqs){
		//allocate 8 as default. FIXME make it relevant to nr_ops;
		vi->pending_reqs = allocate_queue(8);
	}

	if (!vi->pending_reqs){
		XSEGLOG2(&lc, E, "Cannot allocate pending reqs queue for volume %s",
				vi->name);
		return -1;
	}

	xqindex r = __xq_append_tail(vi->pending_reqs, (xqindex) pr);
	if (r == Noneidx){
		if (doubleup_queue(vi) < 0)
			return -1;
		r = __xq_append_tail(vi->pending_reqs, (xqindex) pr);
	}

	if (r == Noneidx)
		return -1;

	return 0;
}

static int handle_accepted(struct peerd *peer, struct peer_req *pr,
				struct xseg_request *req)
{
	struct vlmc_io *vio = __get_vlmcio(pr);
	struct vlmcd *vlmc = __get_vlmcd(peer);
	char *target = xseg_get_target(peer->xseg, req);
	struct volume_info *vi = find_volume_len(vlmc, target, req->targetlen); 
	if (!vi){
		vi = malloc(sizeof(struct volume_info));
		if (!vi){
			vio->err = 1;
			conclude_pr(peer, pr);
			return -1;
		}
		strncpy(vi->name, target, req->targetlen);
		vi->name[req->targetlen] = 0;
		vi->flags = 0;
		vi->pending_pr = NULL;
		vi->active_reqs = 0;
		vi->pending_reqs = 0;
		if (insert_volume(vlmc, vi) < 0){
			vio->err = 1;
			conclude_pr(peer, pr);
			free(vi);
			return -1;
		}
	}

	if (vi->flags & VF_VOLUME_FREEZED){
		if (append_to_pending_reqs(vi, pr) < 0){
			vio->err = 1;
			conclude_pr(peer, pr);
			return -1;
		}
		return 0;
	}

	return do_accepted_pr(peer, pr);
}


static int mapping_info(struct peerd *peer, struct peer_req *pr)
{
	struct vlmc_io *vio = __get_vlmcio(pr);
	if (vio->mreq->state & XS_FAILED){
		XSEGLOG2(&lc, E, "req %lx (op: %d) failed",
				(unsigned long)vio->mreq, vio->mreq->op);
		vio->err = 1;
	}
	else {
		struct xseg_reply_info *xinfo = (struct xseg_reply_info *) xseg_get_data(peer->xseg, vio->mreq);
		char *data = xseg_get_data(peer->xseg, pr->req);
		*(uint64_t *)data = xinfo->size;
	}
	xseg_put_request(peer->xseg, vio->mreq, pr->portno);
	vio->mreq = NULL;
	conclude_pr(peer, pr);
	return 0;
}

static int mapping_open(struct peerd *peer, struct peer_req *pr)
{
	struct vlmc_io *vio = __get_vlmcio(pr);
	if (vio->mreq->state & XS_FAILED){
		XSEGLOG2(&lc, E, "req %lx (op: %d) failed",
				(unsigned long)vio->mreq, vio->mreq->op);
		vio->err = 1;
	}
	xseg_put_request(peer->xseg, vio->mreq, pr->portno);
	vio->mreq = NULL;
	conclude_pr(peer, pr);
	return 0;
}

static int mapping_close(struct peerd *peer, struct peer_req *pr)
{
	struct vlmcd *vlmc = __get_vlmcd(peer);
	struct vlmc_io *vio = __get_vlmcio(pr);
	if (vio->mreq->state & XS_FAILED){
		XSEGLOG2(&lc, E, "req %lx (op: %d) failed",
				(unsigned long)vio->mreq, vio->mreq->op);
		vio->err = 1;
	}
	char *target = xseg_get_target(peer->xseg, pr->req);
	struct volume_info *vi = find_volume_len(vlmc, target, pr->req->targetlen);

	xseg_put_request(peer->xseg, vio->mreq, pr->portno);
	vio->mreq = NULL;
	conclude_pr(peer, pr);

	//assert active_reqs == 1
	//assert volume freezed
	//unfreeze
	if (!vi){
		XSEGLOG2(&lc, E, "Volume has not volume info");
		return 0;
	}
	vi->flags &= ~ VF_VOLUME_FREEZED;
	if (!vi->pending_reqs || !xq_count(vi->pending_reqs)){
		if (vi->pending_reqs)
			xq_free(vi->pending_reqs);
		remove_volume(vlmc, vi);
		free(vi);
	}
	else {
		xqindex xqi;
		while (!(vi->flags & VF_VOLUME_FREEZED) &&
				(xqi = __xq_pop_head(vi->pending_reqs)) != Noneidx) {
			struct peer_req *ppr = (struct peer_req *) xqi;
			do_accepted_pr(peer, ppr);
		}
	}
	return 0;
}

static int mapping_snapshot(struct peerd *peer, struct peer_req *pr)
{
	struct vlmcd *vlmc = __get_vlmcd(peer);
	struct vlmc_io *vio = __get_vlmcio(pr);
	char *target = xseg_get_target(peer->xseg, pr->req);
	struct volume_info *vi = find_volume_len(vlmc, target, pr->req->targetlen);
	if (vio->mreq->state & XS_FAILED){
		XSEGLOG2(&lc, E, "req %lx (op: %d) failed",
				(unsigned long)vio->mreq, vio->mreq->op);
		vio->err = 1;
	}
	else {
		struct xseg_reply_snapshot *xreply = (struct xseg_reply_snapshot *) xseg_get_data(peer->xseg, vio->mreq);
		char buf[XSEG_MAX_TARGETLEN];
		strncpy(buf, target, pr->req->targetlen);
		int r = xseg_resize_request(peer->xseg, pr->req, pr->req->targetlen, sizeof(struct xseg_reply_snapshot));
		if (r < 0) {
			XSEGLOG2(&lc, E, "Cannot resize request");
			vio->err = 1;
		}
		else {
			target = xseg_get_target(peer->xseg, pr->req);
			strncpy(target, buf, pr->req->targetlen);
			char *data = xseg_get_data(peer->xseg, pr->req);
			struct xseg_reply_snapshot *xsnapshot = (struct xseg_reply_snapshot *) data;
			*xsnapshot = *xreply;
		}
	}

	xseg_put_request(peer->xseg, vio->mreq, pr->portno);
	vio->mreq = NULL;
	conclude_pr(peer, pr);

	//assert volume freezed
	//unfreeze
	if (!vi){
		XSEGLOG2(&lc, E, "Volume has no volume info");
		return 0;
	}

	vi->flags &= ~ VF_VOLUME_FREEZED;

	xqindex xqi;
	while (vi->pending_reqs && !(vi->flags & VF_VOLUME_FREEZED) &&
			(xqi = __xq_pop_head(vi->pending_reqs) != Noneidx)) {
		struct peer_req *ppr = (struct peer_req *) xqi;
		do_accepted_pr(peer, ppr);
	}
	return 0;
}

static int mapping_readwrite(struct peerd *peer, struct peer_req *pr)
{
	struct vlmcd *vlmc = __get_vlmcd(peer);
	struct vlmc_io *vio = __get_vlmcio(pr);
	struct xseg_reply_map *mreply = (struct xseg_reply_map *) xseg_get_data(peer->xseg, vio->mreq);
	uint64_t pos, datalen, offset;
	uint32_t targetlen;
	struct xseg_request *breq;
	char *target;
	int i,r;
	xport p;
	if (vio->mreq->state & XS_FAILED){
		XSEGLOG2(&lc, E, "req %lx (op: %d) failed",
				(unsigned long)vio->mreq, vio->mreq->op);
		xseg_put_request(peer->xseg, vio->mreq, pr->portno);
		vio->mreq = NULL;
		vio->err = 1;
		conclude_pr(peer, pr);
		return 0;
	}

	if (!mreply || !mreply->cnt){
		xseg_put_request(peer->xseg, vio->mreq, pr->portno);
		vio->mreq = NULL;
		vio->err = 1;
		conclude_pr(peer, pr);
		return -1;
	}

	vio->breq_len = mreply->cnt;
	vio->breqs = calloc(vio->breq_len, sizeof(struct xseg_request *));
	if (!vio->breqs) {
		xseg_put_request(peer->xseg, vio->mreq, pr->portno);
		vio->mreq = NULL;
		vio->err = 1;
		conclude_pr(peer, pr);
		return -1;
	}

	pos = 0;
	__set_vio_state(vio, SERVING);
	for (i = 0; i < vio->breq_len; i++) {
		datalen = mreply->segs[i].size;
		offset = mreply->segs[i].offset;
		targetlen = mreply->segs[i].targetlen;
		breq = xseg_get_request(peer->xseg, pr->portno, vlmc->bportno, X_ALLOC);
		if (!breq) {
			vio->err = 1;
			break;
		}
		r = xseg_prep_request(peer->xseg, breq, targetlen, datalen);
		if (r < 0) {
			vio->err = 1;
			xseg_put_request(peer->xseg, breq, pr->portno);
			break;
		}
		breq->offset = offset;
		breq->size = datalen;
		breq->op = pr->req->op;
		target = xseg_get_target(peer->xseg, breq);
		if (!target) {
			vio->err = 1;
			xseg_put_request(peer->xseg, breq, pr->portno);
			break;
		}
		strncpy(target, mreply->segs[i].target, targetlen);
		r = xseg_set_req_data(peer->xseg, breq, pr);
		if (r<0) {
			vio->err = 1;
			xseg_put_request(peer->xseg, breq, pr->portno);
			break;
		}

		// this should work, right ?
		breq->data = pr->req->data + pos;
		pos += datalen;
		p = xseg_submit(peer->xseg, breq, pr->portno, X_ALLOC);
		if (p == NoPort){
			void *dummy;
			vio->err = 1;
			xseg_get_req_data(peer->xseg, breq, &dummy);
			xseg_put_request(peer->xseg, breq, pr->portno);
			break;
		}
		r = xseg_signal(peer->xseg, p);
		if (r < 0){
			XSEGLOG2(&lc, W, "Couldnt signal port %u", p);
		}
		vio->breqs[i] = breq;
	}
	vio->breq_cnt = i;
	xseg_put_request(peer->xseg, vio->mreq, pr->portno);
	vio->mreq = NULL;
	if (i == 0) {
		free(vio->breqs);
		vio->breqs = NULL;
		vio->err = 1;
		conclude_pr(peer, pr);
		return -1;
	}
	return 0;
}

static int handle_mapping(struct peerd *peer, struct peer_req *pr,
				struct xseg_request *req)
{
	struct vlmc_io *vio = __get_vlmcio(pr);

	//assert vio>mreq == req
	if (vio->mreq != req){
		XSEGLOG2(&lc, E ,"vio->mreq %lx, req: %lx state: %d breq[0]: %lx",
				(unsigned long)vio->mreq, (unsigned long)req,
				vio->state, (unsigned long)vio->breqs[0]);
		return -1;
	}

	switch (vio->mreq->op){
		case X_INFO:
			mapping_info(peer, pr);
			break;
		case X_SNAPSHOT:
			mapping_snapshot(peer, pr);
			break;
		case X_CLOSE:
			mapping_close(peer, pr);
			break;
		case X_OPEN:
			mapping_open(peer, pr);
			break;
		case X_READ:
		case X_WRITE:
			mapping_readwrite(peer, pr);
			break;
		default:
			XSEGLOG2(&lc, W, "Invalid mreq op");
			//vio->err = 1;
			//conclude_pr(peer, pr);
			break;
	}

	return 0;
}

static int handle_serving(struct peerd *peer, struct peer_req *pr, 
				struct xseg_request *req)
{
	struct vlmc_io *vio = __get_vlmcio(pr);
	struct vlmcd *vlmc = __get_vlmcd(peer);
	(void)vlmc;
	struct xseg_request *breq = req;

	if (breq->state & XS_FAILED && !(breq->state & XS_SERVED)) {
		XSEGLOG2(&lc, E, "req %lx (op: %d) failed at offset %llu\n",
				(unsigned long)req, req->op,
				(unsigned long long)req->offset);
		vio->err = 1;
	} else {
		//assert breq->serviced == breq->size
		pr->req->serviced += breq->serviced;
	}
	xseg_put_request(peer->xseg, breq, pr->portno);

	if (!--vio->breq_cnt){
		__set_vio_state(vio, CONCLUDED);
		free(vio->breqs);
		vio->breqs = NULL;
		vio->breq_len = 0;
		conclude_pr(peer, pr);
	}
	return 0;
}

int dispatch(struct peerd *peer, struct peer_req *pr, struct xseg_request *req,
		enum dispatch_reason reason)
{
	struct vlmc_io *vio = __get_vlmcio(pr);
	struct vlmcd *vlmc = __get_vlmcd(peer);
	(void)vlmc;

	if (reason == dispatch_accept)
		//assert (pr->req == req)
		__set_vio_state(vio, ACCEPTED);

	enum io_state_enum state = __get_vio_state(vio);
	switch (state) {
		case ACCEPTED:
			handle_accepted(peer, pr, req);
			break;
		case MAPPING:
			handle_mapping(peer, pr, req);
			break;
		case SERVING:
			handle_serving(peer, pr, req);
			break;
		case CONCLUDED:
			XSEGLOG2(&lc, W, "invalid state. dispatch called for CONCLUDED");
			break;
		default:
			XSEGLOG2(&lc, E, "wtf dude? invalid state");
			break;
	}
	return 0;
}


int custom_peer_init(struct peerd *peer, int argc, char *argv[])
{
	struct vlmc_io *vio;
	struct vlmcd *vlmc = malloc(sizeof(struct vlmcd));
	int i, j;

	if (!vlmc) {
		XSEGLOG2(&lc, E, "Cannot alloc vlmc");
		return -1;
	}
	peer->priv = (void *) vlmc;

	vlmc->volumes = xhash_new(3, STRING);
	if (!vlmc->volumes){
		XSEGLOG2(&lc, E, "Cannot alloc vlmc");
		return -1;
	}
	vlmc->mportno = NoPort;
	vlmc->bportno = NoPort;

        BEGIN_READ_ARGS(argc, argv);
	READ_ARG_ULONG("-mp", vlmc->mportno);
	READ_ARG_ULONG("-bp", vlmc->bportno);
	END_READ_ARGS();

	if (vlmc->bportno == NoPort) {
		XSEGLOG2(&lc, E, "bportno must be provided");
		usage(argv[0]);
		return -1;
	}
	if (vlmc->mportno == NoPort) {
		XSEGLOG2(&lc, E, "mportno must be provided");
		usage(argv[0]);
		return -1;
	}

	for (i = 0; i < peer->nr_ops; i++) {
		vio = malloc(sizeof(struct vlmc_io));
		if (!vio) {
			break;
		}
		vio->mreq = NULL;
		vio->breqs = NULL;
		vio->breq_cnt = 0;
		vio->breq_len = 0;
		xlock_release(&vio->lock);
		peer->peer_reqs[i].priv = (void *) vio;
	}
	if (i < peer->nr_ops) {
		for (j = 0; j < i; j++) {
			free(peer->peer_reqs[i].priv);
		}
		return -1;
	}


	const struct sched_param param = { .sched_priority = 99 };
	sched_setscheduler(syscall(SYS_gettid), SCHED_FIFO, &param);

	return 0;
}

void custom_peer_finalize(struct peerd *peer)
{
	return;
}
