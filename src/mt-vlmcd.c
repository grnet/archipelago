/*
Copyright (C) 2010-2014 GRNET S.A.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

#define VF_VOLUME_FROZEN (1 << 0)

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
	XSEGLOG2(D, "Doubling up queue of volume %s", vi->name);
	struct xq *newq = allocate_queue(vi->pending_reqs->size * 2);
	if (!newq){
		XSEGLOG2(E, "Doubling up queue of volume %s failed. Allocation error",
				vi->name);
		return -1;
	}

	if (__xq_resize(vi->pending_reqs, newq) == Noneidx){
		xq_free(newq);
		free(newq);
		XSEGLOG2(E, "Doubling up queue of volume %s failed. Resize error",
				vi->name);
		return -1;
	}
	xq_free(vi->pending_reqs);
	free(vi->pending_reqs);
	vi->pending_reqs = newq;
	XSEGLOG2(D, "Doubling up queue of volume %s completed", vi->name);
	return 0;
}

static struct volume_info * find_volume(struct vlmcd *vlmc, char *volume)
{
	struct volume_info *vi = NULL;
	XSEGLOG2(D, "looking up volume %s", volume);
	int r = xhash_lookup(vlmc->volumes, (xhashidx) volume,
			(xhashidx *) &vi);
	if (r < 0){
		XSEGLOG2(D, "looking up volume %s failed", volume);
		return NULL;
	}
	XSEGLOG2(D, "looking up volume %s completed. VI: %lx",
			volume, (unsigned long)vi);
	return vi;
}

static struct volume_info * find_volume_len(struct vlmcd *vlmc, char *target,
						uint32_t targetlen)
{
	char buf[XSEG_MAX_TARGETLEN+1];
	strncpy(buf, target, targetlen);
	buf[targetlen] = 0;
	XSEGLOG2(D, "looking up volume %s, len %u",
			buf, targetlen);
	return find_volume(vlmc, buf);

}

static int insert_volume(struct vlmcd *vlmc, struct volume_info *vi)
{
	int r = -1;

	if (find_volume(vlmc, vi->name)){
		XSEGLOG2(W, "Volume %s found in hash", vi->name);
		return r;
	}

	XSEGLOG2(D, "Inserting volume %s, len: %d (volume_info: %lx)", 
			vi->name, strlen(vi->name), (unsigned long) vi);
	r = xhash_insert(vlmc->volumes, (xhashidx) vi->name, (xhashidx) vi);
	while (r == -XHASH_ERESIZE) {
		xhashidx shift = xhash_grow_size_shift(vlmc->volumes);
		xhash_t *new_hashmap = xhash_resize(vlmc->volumes, shift, 0, NULL);
		if (!new_hashmap){
			XSEGLOG2(E, "Cannot grow vlmc->volumes to sizeshift %llu",
					(unsigned long long) shift);
			return r;
		}
		vlmc->volumes = new_hashmap;
		r = xhash_insert(vlmc->volumes, (xhashidx) vi->name, (xhashidx) vi);
	}
	XSEGLOG2(D, "Inserting volume %s, len: %d (volume_info: %lx) completed", 
			vi->name, strlen(vi->name), (unsigned long) vi);

	return r;

}

static int remove_volume(struct vlmcd *vlmc, struct volume_info *vi)
{
	int r = -1;

	XSEGLOG2(D, "Removing volume %s, len: %d (volume_info: %lx)", 
			vi->name, strlen(vi->name), (unsigned long) vi);
	r = xhash_delete(vlmc->volumes, (xhashidx) vi->name);
	while (r == -XHASH_ERESIZE) {
		xhashidx shift = xhash_shrink_size_shift(vlmc->volumes);
		xhash_t *new_hashmap = xhash_resize(vlmc->volumes, shift, 0, NULL);
		if (!new_hashmap){
			XSEGLOG2(E, "Cannot shrink vlmc->volumes to sizeshift %llu",
					(unsigned long long) shift);
			XSEGLOG2(E, "Removing volume %s, (volume_info: %lx) failed", 
					vi->name, (unsigned long) vi);
			return r;
		}
		vlmc->volumes = new_hashmap;
		r = xhash_delete(vlmc->volumes, (xhashidx) vi->name);
	}
	if (r < 0)
		XSEGLOG2(W, "Removing volume %s, len: %d (volume_info: %lx) failed", 
			vi->name, strlen(vi->name), (unsigned long) vi);
	else
		XSEGLOG2(D, "Removing volume %s, len: %d (volume_info: %lx) completed", 
			vi->name, strlen(vi->name), (unsigned long) vi);
	return r;
}

static int do_accepted_pr(struct peerd *peer, struct peer_req *pr);

static int conclude_pr(struct peerd *peer, struct peer_req *pr)
{
	struct vlmcd *vlmc = __get_vlmcd(peer);
	struct vlmc_io *vio = __get_vlmcio(pr);
	char *target = xseg_get_target(peer->xseg, pr->req);
	struct volume_info *vi = find_volume_len(vlmc, target, pr->req->targetlen);

	XSEGLOG2(D, "Concluding pr %lx, req: %lx vi: %lx", pr, pr->req, vi);

	__set_vio_state(vio, CONCLUDED);
	if (vio->err)
		fail(peer, pr);
	else
		complete(peer, pr);

	if (vi){
		//assert vi->active_reqs > 0
		uint32_t ar = --vi->active_reqs;
		XSEGLOG2(D, "vi: %lx, volume name: %s, active_reqs: %lu, pending_pr: %lx",
				vi, vi->name, ar, vi->pending_pr);
		if (!ar && vi->pending_pr)
			do_accepted_pr(peer, vi->pending_pr);
	}
	XSEGLOG2(D, "Concluded pr %lx, vi: %lx", pr, vi);
	return 0;
}

static int should_freeze_volume(struct xseg_request *req)
{
	if (req->op == X_CLOSE || req->op == X_SNAPSHOT || req->op == X_DELETE || 
		(req->op == X_WRITE && !req->size && (req->flags & XF_FLUSH)) ||
               req->op == X_FLUSH)
		return 1;
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

	XSEGLOG2(I, "Do accepted pr started for pr %lx", pr);
	target = xseg_get_target(peer->xseg, pr->req);
	if (!target){
		vio->err = 1;
		conclude_pr(peer, pr);
		return -1;
	}

	vi = find_volume_len(vlmc, target, pr->req->targetlen);
	if (!vi){
		XSEGLOG2(E, "Cannot find volume");
		XSEGLOG2(E, "Pr %lx", pr);
		vio->err = 1;
		conclude_pr(peer, pr);
		return -1;
	}

	if (should_freeze_volume(pr->req)){
		XSEGLOG2(I, "Freezing volume %s", vi->name);
		vi->flags |= VF_VOLUME_FROZEN;
		if (vi->active_reqs){
			//assert vi->pending_pr == NULL;
			XSEGLOG2(I, "Active reqs of %s: %lu. Pending pr is set to %lx",
					vi->name, vi->active_reqs, pr);
			vi->pending_pr = pr;
			return 0;
		}
		else {
			XSEGLOG2(I, "No active reqs of %s. Pending pr is set to NULL",
					vi->name);
			//assert vi->pending_pr == pr
			vi->pending_pr = NULL;
		}

	}

	vi->active_reqs++;

	vio->err = 0; //reset error state

	if (pr->req->op == X_FLUSH) {
               /* We have no active requests here.
                * Unfreeze volume and start serving waiting/pending requests.
                */
		vi->flags &= ~VF_VOLUME_FROZEN;
		XSEGLOG2(I, "Completing flush request");
		pr->req->serviced = 0;
		conclude_pr(peer, pr);
		xqindex xqi;
		while (vi->pending_reqs && !(vi->flags & VF_VOLUME_FROZEN) &&
				(xqi = __xq_pop_head(vi->pending_reqs)) != Noneidx) {
			struct peer_req *ppr = (struct peer_req *) xqi;
			do_accepted_pr(peer, ppr);
		}
		return 0;
	}

       //FIXME Remove this suboperation of X_WRITE. Support only X_FLUSH.
	if (pr->req->op == X_WRITE && !pr->req->size &&
			(pr->req->flags & (XF_FLUSH|XF_FUA))) {
		//handle flush requests here, so we don't mess with mapper
		//because of the -1 offset
		vi->flags &= ~VF_VOLUME_FROZEN;
		XSEGLOG2(I, "Completing flush request");
		pr->req->serviced = pr->req->size;
		conclude_pr(peer, pr);
		xqindex xqi;
		while (vi->pending_reqs && !(vi->flags & VF_VOLUME_FROZEN) &&
				(xqi = __xq_pop_head(vi->pending_reqs)) != Noneidx) {
			struct peer_req *ppr = (struct peer_req *) xqi;
			do_accepted_pr(peer, ppr);
		}
		return 0;
	}

	vio->mreq = xseg_get_request(peer->xseg, pr->portno,
					vlmc->mportno, X_ALLOC);
	if (!vio->mreq)
		goto out_err;

	/* use datalen 0. let mapper allocate buffer space as needed */
	r = xseg_prep_request(peer->xseg, vio->mreq, pr->req->targetlen, 0);
	if (r < 0) {
		XSEGLOG2(E, "Cannot prep request %lx, of pr %lx for volume %s",
				vio->mreq, pr, vi->name);
		goto out_put;
	}
	mtarget = xseg_get_target(peer->xseg, vio->mreq);
	if (!mtarget)
		goto out_put;

	strncpy(mtarget, target, pr->req->targetlen);
	vio->mreq->size = pr->req->size;
	vio->mreq->offset = pr->req->offset;
	vio->mreq->flags = 0;
	/* propagate v0 info */
	vio->mreq->flags |= pr->req->flags & XF_ASSUMEV0;
	vio->mreq->v0_size= pr->req->v0_size;
	switch (pr->req->op) {
		case X_READ: vio->mreq->op = X_MAPR; break;
		case X_WRITE: vio->mreq->op = X_MAPW; break;
		case X_INFO: vio->mreq->op = X_INFO; break;
		case X_CLOSE: vio->mreq->op = X_CLOSE; break;
		case X_OPEN: vio->mreq->op = X_OPEN; break;
		case X_DELETE: vio->mreq->op = X_DELETE; break;
		case X_SNAPSHOT:
			     //FIXME hack
			     vio->mreq->op = X_SNAPSHOT;
			     vio->mreq->data = pr->req->data;
			     break;
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
		XSEGLOG2(W, "Couldnt signal port %u", p);
	}

	XSEGLOG2(I, "Pr %lx of volume %s completed", pr, vi->name);
	return 0;

out_unset:
	xseg_get_req_data(peer->xseg, vio->mreq, &dummy);
out_put:
	xseg_put_request(peer->xseg, vio->mreq, pr->portno);
out_err:
	vio->err = 1;
	XSEGLOG2(E, "Pr %lx of volume %s failed", pr, vi->name);
	conclude_pr(peer, pr);
	return -1;
}

static int append_to_pending_reqs(struct volume_info *vi, struct peer_req *pr)
{
	XSEGLOG2(I, "Appending pr %lx to vi %lx, volume name %s",
			pr, vi, vi->name);
	if (!vi->pending_reqs){
		//allocate 8 as default. FIXME make it relevant to nr_ops;
		vi->pending_reqs = allocate_queue(8);
	}

	if (!vi->pending_reqs){
		XSEGLOG2(E, "Cannot allocate pending reqs queue for volume %s",
				vi->name);
		XSEGLOG2(E, "Appending pr %lx to vi %lx, volume name %s failed",
				pr, vi, vi->name);
		return -1;
	}

	xqindex r = __xq_append_tail(vi->pending_reqs, (xqindex) pr);
	if (r == Noneidx){
		if (doubleup_queue(vi) < 0){
			XSEGLOG2(E, "Appending pr %lx to vi %lx, volume name %s failed",
					pr, vi, vi->name);
			return -1;
		}
		r = __xq_append_tail(vi->pending_reqs, (xqindex) pr);
	}

	if (r == Noneidx){
		XSEGLOG2(E, "Appending pr %lx to vi %lx, volume name %s failed",
				pr, vi, vi->name);
		return -1;
	}

	XSEGLOG2(I, "Appending pr %lx to vi %lx, volume name %s completed",
			pr, vi, vi->name);
	return 0;
}

static int handle_accepted(struct peerd *peer, struct peer_req *pr,
				struct xseg_request *req)
{
	struct vlmc_io *vio = __get_vlmcio(pr);
	struct vlmcd *vlmc = __get_vlmcd(peer);
	char *target = xseg_get_target(peer->xseg, req);
	struct volume_info *vi = find_volume_len(vlmc, target, req->targetlen);
	XSEGLOG2(I, "Handle accepted for pr %lx, req %lx started", pr, req);
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

	if (vi->flags & VF_VOLUME_FROZEN){
		XSEGLOG2(I, "Volume %s (vi %lx) frozen. Appending to pending_reqs",
				vi->name, vi);
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
	struct xseg_request *req = pr->req;
	char *target;
	char buf[XSEG_MAX_TARGETLEN + 1];
	int r;

	if (vio->mreq->state & XS_FAILED){
		XSEGLOG2(E, "Info req %lx failed",
				(unsigned long)vio->mreq);
		vio->err = 1;
	}
	else {
		if (req->datalen < sizeof(struct xseg_reply_info)) {
			target = xseg_get_target(peer->xseg, req);
			strncpy(buf, target, req->targetlen);
			r = xseg_resize_request(peer->xseg, req, req->targetlen, sizeof(struct xseg_reply_info));
			if (r < 0) {
				XSEGLOG2(E, "Cannot resize request");
				vio->err = 1;
				goto out;
			}
			target = xseg_get_target(peer->xseg, req);
			strncpy(target, buf, req->targetlen);
		}
		struct xseg_reply_info *xinfo = (struct xseg_reply_info *)xseg_get_data(peer->xseg, vio->mreq);
		char *data = xseg_get_data(peer->xseg, pr->req);
		struct xseg_reply_info *xreply = (struct xseg_reply_info *)data;
		xreply->size = xinfo->size;
	}
out:
	xseg_put_request(peer->xseg, vio->mreq, pr->portno);
	vio->mreq = NULL;
	conclude_pr(peer, pr);
	return 0;
}

static int mapping_open(struct peerd *peer, struct peer_req *pr)
{
	struct vlmc_io *vio = __get_vlmcio(pr);
	if (vio->mreq->state & XS_FAILED){
		XSEGLOG2(E, "Open req %lx failed",
				(unsigned long)vio->mreq);
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
		XSEGLOG2(E, "Close req %lx failed",
				(unsigned long)vio->mreq);
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
		XSEGLOG2(E, "Volume has not volume info");
		return 0;
	}
	vi->flags &= ~ VF_VOLUME_FROZEN;
	if (!vi->pending_reqs || !xq_count(vi->pending_reqs)){
		XSEGLOG2(I, "Volume %s (vi %lx) had no pending reqs. Removing",
				vi->name, vi);
		if (vi->pending_reqs)
			xq_free(vi->pending_reqs);
		remove_volume(vlmc, vi);
		free(vi);
	}
	else {
		xqindex xqi;
		XSEGLOG2(I, "Volume %s (vi %lx) had pending reqs. Handling",
				vi->name, vi);
		while (!(vi->flags & VF_VOLUME_FROZEN) &&
				(xqi = __xq_pop_head(vi->pending_reqs)) != Noneidx) {
			struct peer_req *ppr = (struct peer_req *) xqi;
			do_accepted_pr(peer, ppr);
		}
		XSEGLOG2(I, "Volume %s (vi %lx) handling pending reqs completed",
				vi->name, vi);
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
		XSEGLOG2(E, "req %lx (op: %d) failed",
				(unsigned long)vio->mreq, vio->mreq->op);
		vio->err = 1;
	}

	xseg_put_request(peer->xseg, vio->mreq, pr->portno);
	vio->mreq = NULL;
	conclude_pr(peer, pr);

	//assert volume freezed
	//unfreeze
	if (!vi){
		XSEGLOG2(E, "Volume has no volume info");
		return 0;
	}
	XSEGLOG2(D, "Unfreezing volume %s", vi->name);
	vi->flags &= ~ VF_VOLUME_FROZEN;

	xqindex xqi;
	while (vi->pending_reqs && !(vi->flags & VF_VOLUME_FROZEN) &&
			(xqi = __xq_pop_head(vi->pending_reqs)) != Noneidx) {
		struct peer_req *ppr = (struct peer_req *) xqi;
		do_accepted_pr(peer, ppr);
	}
	return 0;
}

static int mapping_delete(struct peerd *peer, struct peer_req *pr)
{
	struct vlmcd *vlmc = __get_vlmcd(peer);
	struct vlmc_io *vio = __get_vlmcio(pr);
	char *target = xseg_get_target(peer->xseg, pr->req);
	struct volume_info *vi = find_volume_len(vlmc, target, pr->req->targetlen);
	if (vio->mreq->state & XS_FAILED){
		XSEGLOG2(E, "req %lx (op: %d) failed",
				(unsigned long)vio->mreq, vio->mreq->op);
		vio->err = 1;
	}

	xseg_put_request(peer->xseg, vio->mreq, pr->portno);
	vio->mreq = NULL;
	conclude_pr(peer, pr);

	//assert volume freezed
	//unfreeze
	if (!vi){
		XSEGLOG2(E, "Volume has no volume info");
		return 0;
	}
	XSEGLOG2(D, "Unfreezing volume %s", vi->name);
	vi->flags &= ~ VF_VOLUME_FROZEN;

	xqindex xqi;
	while (vi->pending_reqs && !(vi->flags & VF_VOLUME_FROZEN) &&
			(xqi = __xq_pop_head(vi->pending_reqs)) != Noneidx) {
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
	char *target, *data;
	int i,r;
	xport p;
	if (vio->mreq->state & XS_FAILED){
		XSEGLOG2(E, "req %lx (op: %d) failed",
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
	vio->breq_cnt = 0;
	for (i = 0; i < vio->breq_len; i++) {
		datalen = mreply->segs[i].size;
		if (mreply->segs[i].flags & XF_MAPFLAG_ZERO) {
			vio->breqs[i] = NULL;
			if (pr->req->op != X_READ) {
				XSEGLOG2(E, "Mapper returned zero object "
						"for a write I/O operation");
				vio->err = 1;
				break;
			}
			data = xseg_get_data(peer->xseg, pr->req);
			data += pos;
			memset(data, 0, datalen);
			pos += datalen;
			pr->req->serviced += datalen;
			continue;
		}
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
			XSEGLOG2(W, "Couldnt signal port %u", p);
		}
		vio->breqs[i] = breq;
		vio->breq_cnt++;
	}
	xseg_put_request(peer->xseg, vio->mreq, pr->portno);
	vio->mreq = NULL;
	if (vio->breq_cnt == 0) {
		free(vio->breqs);
		vio->breqs = NULL;
		conclude_pr(peer, pr);
		if (vio->err) {
			return -1;
		}
	}
	return 0;
}

static int handle_mapping(struct peerd *peer, struct peer_req *pr,
				struct xseg_request *req)
{
	struct vlmc_io *vio = __get_vlmcio(pr);

	//assert vio>mreq == req
	if (vio->mreq != req){
		XSEGLOG2(E ,"vio->mreq %lx, req: %lx state: %d breq[0]: %lx",
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
		case X_DELETE:
			mapping_delete(peer, pr);
			break;
		case X_OPEN:
			mapping_open(peer, pr);
			break;
		case X_MAPR:
		case X_MAPW:
			mapping_readwrite(peer, pr);
			break;
		default:
			XSEGLOG2(W, "Invalid mreq op");
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
		XSEGLOG2(E, "req %lx (op: %d) failed at offset %llu\n",
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
			XSEGLOG2(W, "invalid state. dispatch called for CONCLUDED");
			break;
		default:
			XSEGLOG2(E, "wtf dude? invalid state");
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
		XSEGLOG2(E, "Cannot alloc vlmc");
		return -1;
	}
	peer->priv = (void *) vlmc;

	vlmc->volumes = xhash_new(3, 0, XHASH_STRING);
	if (!vlmc->volumes){
		XSEGLOG2(E, "Cannot alloc vlmc");
		return -1;
	}
	vlmc->mportno = NoPort;
	vlmc->bportno = NoPort;

        BEGIN_READ_ARGS(argc, argv);
	READ_ARG_ULONG("-mp", vlmc->mportno);
	READ_ARG_ULONG("-bp", vlmc->bportno);
	END_READ_ARGS();

	if (vlmc->bportno == NoPort) {
		XSEGLOG2(E, "bportno must be provided");
		usage(argv[0]);
		return -1;
	}
	if (vlmc->mportno == NoPort) {
		XSEGLOG2(E, "mportno must be provided");
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
