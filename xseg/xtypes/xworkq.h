#ifndef __X_WORK_H
#define __X_WORK_H

#include <xtypes/xq.h>
#include <xtypes/xwork.h>

struct xworkq {
	struct xlock q_lock;
	uint32_t flags;
	struct xq *q;
	struct xlock *lock;
};

int xworkq_init(struct xworkq *wq, struct xlock * lock,  uint32_t flags);
int xworkq_enqueue(struct xworkq *wq, void (*job_fn)(void *q, void *arg), void *job);
void xworkq_signal(struct xworkq *wq);
void xworkq_destroy(struct xworkq *wq);



#endif /* __X_WORK_H */
