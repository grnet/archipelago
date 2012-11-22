#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <xseg/xseg.h>
#include <xseg/protocol.h>
#include <speer.h>
#include <sched.h>
#include <sys/syscall.h>

enum io_state_enum {
	ACCEPTED = 0,
	MAPPING = 1,
	SERVING = 2,
	CONCLUDED = 3
};

struct vlmcd {
	xport mportno;
	xport bportno;
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
//	xlock_acquire(&vio->lock, 1);
	vio->state = state;
//	xlock_release(&vio->lock);
}

static inline enum io_state_enum __get_vio_state(struct vlmc_io *vio)
{
	enum io_state_enum state;
//	xlock_acquire(&vio->lock, 1);
	state = vio->state;
//	xlock_release(&vio->lock);
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

static int handle_accepted(struct peerd *peer, struct peer_req *pr,
				struct xseg_request *req)
{
	struct vlmc_io *vio = __get_vlmcio(pr);
	struct vlmcd *vlmc = __get_vlmcd(peer);
	int r;
	xport p;
	char *target, *mtarget;
	void *dummy;

	if (pr->req->op == X_WRITE && !req->size && (pr->req->flags & (XF_FLUSH|XF_FUA))){
		//hanlde flush requests here, so we don't mess with mapper
		//because of the -1 offset
		fprintf(stderr, "completing flush request\n");
		pr->req->serviced = pr->req->size;
		__set_vio_state(vio, CONCLUDED);
		complete(peer, pr);
		return 0;		
	}
	vio->err = 0; //reset error state
	vio->mreq = xseg_get_request(peer->xseg, pr->portno, 
					vlmc->mportno, X_ALLOC);
	if (!vio->mreq)
		goto out_err;

	/* use dalalen 0. let mapper allocate buffer space as needed */
	r = xseg_prep_request(peer->xseg, vio->mreq, pr->req->targetlen, 0); 
	if (r < 0) {
		goto out_put;
	}
	target = xseg_get_target(peer->xseg, pr->req);
	if (!target)
		goto out_put;
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
		fprintf(stderr, "couldnt signal port %u", p);
	}

	return 0;

out_unset:
	xseg_get_req_data(peer->xseg, vio->mreq, &dummy);
out_put:
	xseg_put_request(peer->xseg, vio->mreq, pr->portno);
out_err:
	__set_vio_state(vio, CONCLUDED);
	fail(peer, pr);
	return -1;
}

static int handle_mapping(struct peerd *peer, struct peer_req *pr,
				struct xseg_request *req)
{
	struct vlmc_io *vio = __get_vlmcio(pr);
	struct vlmcd *vlmc = __get_vlmcd(peer);
	uint64_t pos, datalen, offset;
	uint32_t targetlen;
	struct xseg_request *breq;
	char *target;
	int i,r;
	xport p;
	
	//assert vio>mreq == req 
	if (vio->mreq != req){
		printf("vio->mreq %lx, req: %lx state: %d breq[0]: %lx\n", vio->mreq, req, vio->state, vio->breqs[0]);
		r = *(volatile int *)0;
		return -1;
	}
	/* FIXME shouldn's XS_FAILED be sufficient ?? */
	if (vio->mreq->state & XS_FAILED && !(vio->mreq->state & XS_SERVED)){
		fprintf(stderr, "req %lx (op: %d) failed\n", vio->mreq, vio->mreq->op);
		xseg_put_request(peer->xseg, vio->mreq, pr->portno);
		vio->mreq = NULL;
		__set_vio_state(vio, CONCLUDED);
		fail(peer, pr);
	} else if (vio->mreq->op == X_INFO) {
		struct xseg_reply_info *xinfo = (struct xseg_reply_info *) xseg_get_data(peer->xseg, vio->mreq);
		char *data = xseg_get_data(peer->xseg, pr->req);
		*(uint64_t *)data = xinfo->size;
		xseg_put_request(peer->xseg, vio->mreq, pr->portno);
		vio->mreq = NULL;
		__set_vio_state(vio, CONCLUDED);
		complete(peer, pr);
	} else if (vio->mreq->op == X_CLOSE) {
		xseg_put_request(peer->xseg, vio->mreq, pr->portno);
		vio->mreq = NULL;
		__set_vio_state(vio, CONCLUDED);
		complete(peer, pr);
	} else {
		struct xseg_reply_map *mreply = (struct xseg_reply_map *) xseg_get_data(peer->xseg, vio->mreq);
		if (!mreply->cnt){
			printf("foo2\n");
			xseg_put_request(peer->xseg, vio->mreq, pr->portno);
			vio->mreq = NULL;
			__set_vio_state(vio, CONCLUDED);
			fail(peer, pr);
			goto out;
		}
		vio->breq_len = mreply->cnt;
		vio->breqs = calloc(vio->breq_len, sizeof(struct xseg_request *));
		if (!vio->breqs) {
			printf("foo3\n");
			xseg_put_request(peer->xseg, vio->mreq, pr->portno);
			vio->mreq = NULL;
			__set_vio_state(vio, CONCLUDED);
			fail(peer, pr);
			goto out_err;
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
				//XSEGLOG("couldn't signal port %u", p);
			}
			vio->breqs[i] = breq;
		}
		vio->breq_cnt = i;
		xseg_put_request(peer->xseg, vio->mreq, pr->portno);
		vio->mreq = NULL;
		if (i == 0) {
			printf("foo4\n");
			__set_vio_state(vio, CONCLUDED);
			free(vio->breqs);
			vio->breqs = NULL;
			fail(peer, pr);
			goto out_err;
		}
	}

out:
	return 0;

out_err:
	return -1;
}

static int handle_serving(struct peerd *peer, struct peer_req *pr, 
				struct xseg_request *req)
{
	struct vlmc_io *vio = __get_vlmcio(pr);
	struct vlmcd *vlmc = __get_vlmcd(peer);
	struct xseg_request *breq = req;

	if (breq->state & XS_FAILED && !(breq->state & XS_SERVED)) {
		fprintf(stderr, "req %lx (op: %d) failed at offset \n", req, req->op, req->offset);
		vio->err = 1;
	} else {
		//assert breq->serviced == breq->size
		__sync_fetch_and_add(&pr->req->serviced, breq->serviced);
	}
	xseg_put_request(peer->xseg, breq, pr->portno);

	if (!__sync_sub_and_fetch(&vio->breq_cnt, 1)) {
		__set_vio_state(vio, CONCLUDED);
		free(vio->breqs);
		vio->breqs = NULL;
		vio->breq_len = 0;
		if (vio->err)
			fail(peer, pr);
		else
			complete(peer, pr);
	}

	return 0;
}

int dispatch(struct peerd *peer, struct peer_req *pr, struct xseg_request *req,
		enum dispatch_reason reason)
{
	struct vlmc_io *vio = __get_vlmcio(pr);
	struct vlmcd *vlmc = __get_vlmcd(peer);

	xlock_acquire(&vio->lock,1);
	if (pr->req == req)
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
			fprintf(stderr, "invalid state. dispatch called for concluded\n");
			break;
		default:
			fprintf(stderr, "wtf dude? invalid state\n");
			break;
	}
	xlock_release(&vio->lock);
	return 0;
}


int custom_peer_init(struct peerd *peer, int argc, char *argv[])
{
	struct vlmc_io *vio;
	struct vlmcd *vlmc = malloc(sizeof(struct vlmcd));
	int i, j;

	if (!vlmc) {
		perror("malloc");
		return -1;
	}
	peer->priv = (void *) vlmc;

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

	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "-mp") && (i+1) < argc){
			vlmc->mportno = atoi(argv[i+1]);
			i += 1;
			continue;
		}
		if (!strcmp(argv[i], "-bp") && (i+1) < argc){
			vlmc->bportno = atoi(argv[i+1]);
			i += 1;
			continue;
		}
	}

	const struct sched_param param = { .sched_priority = 99 };
	sched_setscheduler(syscall(SYS_gettid), SCHED_FIFO, &param);

	return 0;
}
