#ifndef __X_WAITQ_H
#define __X_WAITQ_H

#include <xtypes/xq.h>
#include <xtypes/xwork.h>

#define XWAIT_SIGNAL_ONE (1 << 0)

struct xwaitq {
	int (*cond_fn)(void *arg);
	void *cond_arg;
	uint32_t flags;
	struct xq *q;
	struct xlock lock;
};

int xwaitq_init(struct xwaitq *wq, int (*cond_fn)(void *arg), void *arg, uint32_t flags);
int xwaitq_enqueue(struct xwaitq *wq, struct work *w);
void xwaitq_signal(struct xwaitq *wq);
void xwaitq_destroy(struct xwaitq *wq);



#endif /* __X_WAITQ_H */
