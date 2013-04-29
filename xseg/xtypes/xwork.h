#ifndef __XWORK_H
#define __XWORK_H

struct work {
	void *job;
	void (*job_fn)(void *q, void *arg);
};

#endif /* __XWORK_H */

