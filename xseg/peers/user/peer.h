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

#include <stddef.h>
#include <xseg/xseg.h>

#ifdef ST_THREADS
#include <st.h>
#endif


#define BEGIN_READ_ARGS(__ac, __av)					\
	int __argc = __ac;						\
	char **__argv = __av;						\
	int __i;							\
	for (__i = 0; __i < __argc; __i++) {

#define END_READ_ARGS()							\
	}

#define READ_ARG_ULONG(__name, __var)					\
	if (!strcmp(__argv[__i], __name) && __i + 1 < __argc){	\
		__var = strtoul(__argv[__i+1], NULL, 10);		\
		__i += 1;						\
		continue;						\
	}

#define READ_ARG_STRING(__name, __var, __max_len)			\
	if (!strcmp(__argv[__i], __name) && __i + 1 < __argc){	\
		strncpy(__var, __argv[__i+1], __max_len);		\
		__var[__max_len] = 0;				\
		__i += 1;						\
		continue;						\
	}

#define READ_ARG_BOOL(__name, __var)					\
	if (!strcmp(__argv[__i], __name)){				\
		__var = 1;						\
		continue;						\
	}




/* main peer structs */
struct peer_req {
	struct peerd *peer;
	struct xseg_request *req;
	ssize_t retval;
	xport portno;
	void *priv;
#ifdef ST_THREADS
	st_cond_t cond;
#endif
};

struct peerd {
	struct xseg *xseg;
	xport portno_start;
	xport portno_end;
	long nr_ops;
	uint32_t defer_portno;
	struct peer_req *peer_reqs;
	struct xq free_reqs;
	void *priv;
#ifdef MT
	uint32_t nr_threads;
	struct thread *thread;
	struct xq threads;
	void (*interactive_func)(void);
#endif
};

enum dispatch_reason {
	dispatch_accept = 0,
	dispatch_receive = 1,
	dispatch_internal = 2
};

void fail(struct peerd *peer, struct peer_req *pr);
void complete(struct peerd *peer, struct peer_req *pr);
void defer_request(struct peerd *peer, struct peer_req *pr);
void pending(struct peerd *peer, struct peer_req *req);
void log_pr(char *msg, struct peer_req *pr);
int canDefer(struct peerd *peer);
int submit_peer_req(struct peerd *peer, struct peer_req *pr);
struct peer_req *alloc_peer_req(struct peerd *peer);
void free_peer_req(struct peerd *peer, struct peer_req *pr);
void get_submits_stats();
void get_responds_stats();
void usage();
void print_req(struct xseg *xseg, struct xseg_request *req);
#ifdef MT
int thread_execute(struct peerd *peer, void (*func)(void *arg), void *arg);
#endif

static inline struct peerd * __get_peerd(void * custom_peerd)
{
	return (struct peerd *) ((unsigned long) custom_peerd  - offsetof(struct peerd, priv));
}


/* decration of "common" variables */
extern struct log_ctx lc;
#ifdef ST_THREADS
extern uint32_t ta;
#endif


/********************************
 *   mandatory peer functions   *
 ********************************/

/* peer main function */
int custom_peer_init(struct peerd *peer, int argc, char *argv[]);
void custom_peer_finalize(struct peerd *peer);

/* dispatch function */
int dispatch(struct peerd *peer, struct peer_req *pr, struct xseg_request *req,
		enum dispatch_reason reason);

void custom_peer_usage();
