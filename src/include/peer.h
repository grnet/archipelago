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

#ifndef PEER_H

#define PEER_H

#include <stddef.h>
#include <xseg/xseg.h>
#include <string.h>

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



#define PEER_DEFAULT_UMASK     0007

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
#ifdef MT
    int thread_no;
#endif
};

struct thread {
    pthread_t tid;
    struct peerd *peer;
    int thread_no;
    struct xq free_thread_reqs;
    void *priv;
    void *arg;
};

struct peerd {
    struct xseg *xseg;
    xport portno_start;
    xport portno_end;
    long nr_ops;
    uint64_t threshold;
    xport defer_portno;
    struct peer_req *peer_reqs;
    struct xq free_reqs;
    int (*peerd_loop) (void *arg);
    void *sd;
    void *priv;
#ifdef MT
    uint32_t nr_threads;
    struct thread *thread;
    struct xq threads;
    void (*interactive_func) (void);
#else
#endif
};

enum dispatch_reason {
    dispatch_accept = 0,
    dispatch_receive = 1,
    dispatch_internal = 2
};

void fail(struct peerd *peer, struct peer_req *pr);
void complete(struct peerd *peer, struct peer_req *pr);
int defer_request(struct peerd *peer, struct peer_req *pr);
void pending(struct peerd *peer, struct peer_req *req);
void log_pr(char *msg, struct peer_req *pr);
int canDefer(struct peerd *peer);
void free_peer_req(struct peerd *peer, struct peer_req *pr);
int submit_peer_req(struct peerd *peer, struct peer_req *pr);
void get_submits_stats();
void get_responds_stats();
void usage();
void print_req(struct xseg *xseg, struct xseg_request *req);
int all_peer_reqs_free(struct peerd *peer);

#ifdef MT
int thread_execute(struct peerd *peer, void (*func) (void *arg), void *arg);
struct peer_req *alloc_peer_req(struct peerd *peer, struct thread *t);
int check_ports(struct peerd *peer, struct thread *t);
#else
struct peer_req *alloc_peer_req(struct peerd *peer);
int check_ports(struct peerd *peer);
#endif

static inline struct peerd *__get_peerd(void *custom_peerd)
{
    return (struct peerd *) ((unsigned long) custom_peerd -
                             offsetof(struct peerd, priv));
}



/* decration of "common" variables */
extern volatile unsigned int terminated;
extern struct log_ctx lc;
#ifdef ST_THREADS
extern uint32_t ta;
#endif

static inline int isTerminate(void)
{
    return terminated;
}

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

#endif                          /* end of PEER_H */
