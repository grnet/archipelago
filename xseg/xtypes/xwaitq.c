#include <xtypes/domain.h>
#include <xtypes/xwaitq.h>

static int __check_cond(struct xwaitq *wq)
{
	return wq->cond_fn(wq->cond_arg);
}

int xwaitq_init(struct xwaitq *wq, int (*cond_fn)(void *arg), void *arg, uint32_t flags)
{
	wq->cond_fn = cond_fn;
	wq->cond_arg = arg;
	wq->flags = flags;
	wq->q = xtypes_malloc(sizeof(struct xq));
	if (!wq->q)
		return -1;
	xlock_release(&wq->lock);
	if (!xq_alloc_empty(wq->q, 8)){
		xtypes_free(wq->q);
		return -1;
	}
	return 0;
}

void xwaitq_destroy(struct xwaitq *wq)
{
	xq_free(wq->q);
	xtypes_free(wq->q);
}

int __xwaitq_enqueue(struct xwaitq *wq, struct work *w)
{
	//enqueure and resize if necessary
	xqindex r;
	struct xq *newq;
	r = __xq_append_tail(wq->q, (xqindex)w);
	if (r == Noneidx){
		newq = xtypes_malloc(sizeof(struct xq));
		if (!newq){
			return -1;
		}
		if (!xq_alloc_empty(newq, wq->q->size*2)){
			xtypes_free(newq);
			return -1;
		}
		if (__xq_resize(wq->q, newq) == Noneidx){
			xq_free(newq);
			xtypes_free(newq);
			return -1;
		}
		xtypes_free(wq->q);
		wq->q = newq;
		r = __xq_append_tail(wq->q, (xqindex)w);
	}

	return ((r == Noneidx)? -1 : 0);
}

int xwaitq_enqueue(struct xwaitq *wq, struct work *w)
{
	int r;
	if (__check_cond(wq)){
		w->job_fn(wq, w->job);
		return 0;
	}
	xlock_acquire(&wq->lock, 1);
	r = __xwaitq_enqueue(wq, w);
	xlock_release(&wq->lock);
	xwaitq_signal(wq);
	return r;
}

void xwaitq_signal(struct xwaitq *wq)
{
	xqindex xqi;
	struct work *w;

	if (!xq_count(wq->q))
		return;

	if (wq->flags & XWAIT_SIGNAL_ONE){
		if (!xlock_try_lock(&wq->lock, 1))
			return;
	} else {
		xlock_acquire(&wq->lock, 1);
	}
	while (xq_count(wq->q) && __check_cond(wq)){
		xqi = __xq_pop_head(wq->q);
		if (xqi == Noneidx){
			break;
		}
		xlock_release(&wq->lock);
		w = (struct work *)xqi;
		w->job_fn(wq, w->job);
		if (wq->flags & XWAIT_SIGNAL_ONE){
			if (!xlock_try_lock(&wq->lock, 1))
				return;
		} else {
			xlock_acquire(&wq->lock, 1);
		}
	}
	xlock_release(&wq->lock);
}

#ifdef __KERNEL__
#include <linux/module.h>
#include <xtypes/xwaitq_exports.h>
#endif
