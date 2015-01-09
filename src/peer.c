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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <pwd.h>
#include <grp.h>
#include <xseg/xseg.h>
#ifdef MT
#include <pthread.h>
#endif

#include "peer.h"

#ifdef MT
#ifdef ST_THREADS
#error "MT and ST_THREADS defines are mutually exclusive"
#endif
#endif

#define PEER_TYPE "posixfd"

//FIXME this should not be defined here probably
#define MAX_SPEC_LEN 128
#define MAX_PIDFILE_LEN 512
#define MAX_CPUS_LEN 512

/* Define the cpus on which the threads/process will be pinned */
struct cpu_list {
    int cpus[48];
    int len;
};

struct cpu_list cpu_list;
volatile unsigned int terminated = 0;
unsigned int verbose = 0;
struct log_ctx lc;
#ifdef ST_THREADS
uint32_t ta = 0;
#endif

#ifdef MT
struct peerd *global_peer;
static pthread_key_t threadkey;

inline static int wake_up_next_thread(struct peerd *peer)
{
    return (xseg_signal(peer->xseg, peer->portno_start));
}
#endif

/*
 * extern is needed if this function is going to be called by another file
 * such as bench-xseg.c
 */

void signal_handler(int signal)
{
//      XSEGLOG2(&lc, I, "Caught signal. Terminating gracefully");
    terminated = 1;
#ifdef MT
    wake_up_next_thread(global_peer);
#endif
}

/*
 * We want to both print the backtrace and dump the core. To do so, we fork a
 * process that prints its stack trace, that should be the same as the parents.
 * Then we wait for 1 sec and we abort. The reason we don't abort immediately
 * is because it may interrupt the printing of the backtrace.
 */
void segv_handler(int signal)
{
    if (fork() == 0) {
        xseg_printtrace();
        _exit(1);
    }

    sleep(1);
    abort();
}

void renew_logfile(int signal)
{
//      XSEGLOG2(&lc, I, "Caught signal. Renewing logfile");
    renew_logctx(&lc, NULL, verbose, NULL, REOPEN_FILE);
}

static int setup_signals(struct peerd *peer)
{
    int r;
    struct sigaction sa;
    struct rlimit rlim;
#ifdef MT
    global_peer = peer;
#endif
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = signal_handler;
    r = sigaction(SIGTERM, &sa, NULL);
    if (r < 0) {
        return r;
    }
    r = sigaction(SIGINT, &sa, NULL);
    if (r < 0) {
        return r;
    }
    r = sigaction(SIGQUIT, &sa, NULL);
    if (r < 0) {
        return r;
    }

    /*
     * Get the current limits for core files and raise them to the largest
     * value possible
     */
    if (getrlimit(RLIMIT_CORE, &rlim) < 0) {
        return r;
    }

    rlim.rlim_cur = rlim.rlim_max;

    if (setrlimit(RLIMIT_CORE, &rlim) < 0) {
        return r;
    }

    /* Install handler for segfaults */
    sa.sa_handler = segv_handler;
    r = sigaction(SIGSEGV, &sa, NULL);
    if (r < 0) {
        return r;
    }

    sa.sa_handler = renew_logfile;
    r = sigaction(SIGUSR1, &sa, NULL);

    return r;
}

inline int canDefer(struct peerd *peer)
{
    return !(peer->defer_portno == NoPort);
}

void print_req(struct xseg *xseg, struct xseg_request *req)
{
    char target[64], data[64];
    char *req_target, *req_data;
    unsigned int end = (req->targetlen > 63) ? 63 : req->targetlen;
    req_target = xseg_get_target(xseg, req);
    req_data = xseg_get_data(xseg, req);

    strncpy(target, req_target, end);
    target[end] = '\0';
    strncpy(data, req_data, 63);
    data[63] = '\0';
    printf("req id:%lu, op:%u %llu:%lu serviced: %lu, reqstate: %u\n"
           "src: %u, transit: %u, dst: %u effective dst: %u\n"
           "target[%u]:'%s', data[%llu]:\n%s------------------\n\n",
           (unsigned long) (req),
           (unsigned int) req->op,
           (unsigned long long) req->offset,
           (unsigned long) req->size,
           (unsigned long) req->serviced,
           (unsigned int) req->state,
           (unsigned int) req->src_portno,
           (unsigned int) req->transit_portno,
           (unsigned int) req->dst_portno,
           (unsigned int) req->effective_dst_portno,
           (unsigned int) req->targetlen, target,
           (unsigned long long) req->datalen, data);
}

void log_pr(char *msg, struct peer_req *pr)
{
    char target[64], data[64];
    char *req_target, *req_data;
    struct peerd *peer = pr->peer;
    struct xseg *xseg = pr->peer->xseg;
    req_target = xseg_get_target(xseg, pr->req);
    req_data = xseg_get_data(xseg, pr->req);
    /* null terminate name in case of req->target is less than 63 characters,
     * and next character after name (aka first byte of next buffer) is not
     * null
     */
    unsigned int end = (pr->req->targetlen > 63) ? 63 : pr->req->targetlen;
    if (verbose) {
        strncpy(target, req_target, end);
        target[end] = '\0';
        strncpy(data, req_data, 63);
        data[63] = '\0';
        printf
            ("%s: req id:%u, op:%u %llu:%lu serviced: %lu, retval: %lu, reqstate: %u\n"
             "target[%u]:'%s', data[%llu]:\n%s------------------\n\n", msg,
             (unsigned int) (pr - peer->peer_reqs), (unsigned int) pr->req->op,
             (unsigned long long) pr->req->offset,
             (unsigned long) pr->req->size, (unsigned long) pr->req->serviced,
             (unsigned long) pr->retval, (unsigned int) pr->req->state,
             (unsigned int) pr->req->targetlen, target,
             (unsigned long long) pr->req->datalen, data);
    }
}

#ifdef MT
inline struct peer_req *alloc_peer_req(struct peerd *peer, struct thread *t)
{
    struct peer_req *pr;
    xqindex idx = xq_pop_head(&t->free_thread_reqs);
    if (idx != Noneidx) {
        goto out;
    }

    /* try to steal from another thread */
    /*
   int i;
   struct thread *nt;
   for (i = t->thread_no + 1; i < (t->thread_no + peer->nr_threads); i++) {
       nt = &peer->thread[(t->thread_no + i) % peer->nr_threads];
       if (!xq_count(&nt->free_thread_reqs)) {
           continue;
       }
       idx = xq_pop_head(&nt->free_thread_reqs);
       if (idx != Noneidx) {
           goto out;
       }
   }
     */
    return NULL;
  out:
    pr = peer->peer_reqs + idx;
    pr->thread_no = t - peer->thread;
    return pr;
}
#else
/*
 * free_reqs is a queue that simply contains pointer offsets to the peer_reqs
 * queue. If a pointer from peer_reqs is popped, we are certain that the
 * associated memory in peer_reqs is free to use
 */
inline struct peer_req *alloc_peer_req(struct peerd *peer)
{
    xqindex idx = xq_pop_head(&peer->free_reqs);
    if (idx == Noneidx) {
        return NULL;
    }
    return peer->peer_reqs + idx;
}
#endif

inline void free_peer_req(struct peerd *peer, struct peer_req *pr)
{
    xqindex idx = pr - peer->peer_reqs;
    pr->req = NULL;
#ifdef MT
    struct thread *t = &peer->thread[pr->thread_no];
    xq_append_head(&t->free_thread_reqs, idx);
#else
    xq_append_head(&peer->free_reqs, idx);
#endif
}

/*
 * Count all free reqs in peer.
 * Racy, if multithreaded, but the sum should monotonicly increase when checked
 * after a termination signal is catched.
 */
int all_peer_reqs_free(struct peerd *peer)
{
    uint32_t free_reqs = 0;
#ifdef MT
    int i;
    for (i = 0; i < peer->nr_threads; i++) {
        free_reqs += xq_count(&peer->thread[i].free_thread_reqs);
    }
#else
    free_reqs = xq_count(&peer->free_reqs);
#endif
    if (free_reqs == peer->nr_ops) {
        return 1;
    }
    return 0;
}

struct timeval resp_start, resp_end, resp_accum = { 0, 0 };

uint64_t responds = 0;
void get_responds_stats()
{
    printf("Time waiting respond %lu.%06lu sec for %llu times.\n",
           //(unsigned int)(t - peer->thread),
           resp_accum.tv_sec, resp_accum.tv_usec,
           (long long unsigned int) responds);
}

//FIXME error check
void fail(struct peerd *peer, struct peer_req *pr)
{
    struct xseg_request *req = pr->req;
    uint32_t p;
    if (req) {
        XSEGLOG2(&lc, D, "failing req %u",
                 (unsigned int) (pr - peer->peer_reqs));
        req->state |= XS_FAILED;
        //xseg_set_req_data(peer->xseg, pr->req, NULL);
        p = xseg_respond(peer->xseg, req, pr->portno, X_ALLOC);
        xseg_signal(peer->xseg, p);
    }
    free_peer_req(peer, pr);
#ifdef MT
    wake_up_next_thread(peer);
#endif
}

//FIXME error check
void complete(struct peerd *peer, struct peer_req *pr)
{
    struct xseg_request *req = pr->req;
    uint32_t p;
    if (req) {
        req->state |= XS_SERVED;
        //xseg_set_req_data(peer->xseg, pr->req, NULL);
        //gettimeofday(&resp_start, NULL);
        p = xseg_respond(peer->xseg, req, pr->portno, X_ALLOC);
        //gettimeofday(&resp_end, NULL);
        //responds++;
        //timersub(&resp_end, &resp_start, &resp_end);
        //timeradd(&resp_end, &resp_accum, &resp_accum);
        //printf("xseg_signal: %u\n", p);
        xseg_signal(peer->xseg, p);
    }
    free_peer_req(peer, pr);
#ifdef MT
    wake_up_next_thread(peer);
#endif
}

static void handle_accepted(struct peerd *peer, struct peer_req *pr,
                            struct xseg_request *req)
{
    struct xseg_request *xreq = pr->req;
    //assert xreq == req;
    XSEGLOG2(&lc, D, "Handle accepted");
    xreq->serviced = 0;
    //xreq->state = XS_ACCEPTED;
    pr->retval = 0;
    dispatch(peer, pr, req, dispatch_accept);
}

static void handle_received(struct peerd *peer, struct peer_req *pr,
                            struct xseg_request *req)
{
    //struct xseg_request *req = pr->req;
    //assert req->state != XS_ACCEPTED;
    XSEGLOG2(&lc, D, "Handle received \n");
    dispatch(peer, pr, req, dispatch_receive);

}
struct timeval sub_start, sub_end, sub_accum = { 0, 0 };

uint64_t submits = 0;
void get_submits_stats()
{
    printf("Time waiting submit %lu.%06lu sec for %llu times.\n",
           //(unsigned int)(t - peer->thread),
           sub_accum.tv_sec, sub_accum.tv_usec,
           (long long unsigned int) submits);
}

int submit_peer_req(struct peerd *peer, struct peer_req *pr)
{
    uint32_t ret;
    struct xseg_request *req = pr->req;
    // assert req->portno == peer->portno ?
    //TODO small function with error checking
    XSEGLOG2(&lc, D, "submitting peer req %u\n",
             (unsigned int) (pr - peer->peer_reqs));
    ret = xseg_set_req_data(peer->xseg, req, (void *) (pr));
    if (ret < 0) {
        return -1;
    }
    //printf("pr: %x , req_data: %x \n", pr, xseg_get_req_data(peer->xseg, req));
    //gettimeofday(&sub_start, NULL);
    ret = xseg_submit(peer->xseg, req, pr->portno, X_ALLOC);
    //gettimeofday(&sub_end, NULL);
    //submits++;
    //timersub(&sub_end, &sub_start, &sub_end);
    //timeradd(&sub_end, &sub_accum, &sub_accum);
    if (ret == NoPort) {
        return -1;
    }
    xseg_signal(peer->xseg, ret);
    return 0;
}

#ifdef MT
int check_ports(struct peerd *peer, struct thread *t)
#else
int check_ports(struct peerd *peer)
#endif
{
    struct xseg *xseg = peer->xseg;
    xport portno_start = peer->portno_start;
    xport portno_end = peer->portno_end;
    struct xseg_request *accepted, *received;
    struct peer_req *pr;
    xport i;
    int r, c = 0;

    for (i = portno_start; i <= portno_end; i++) {
        accepted = NULL;
        received = NULL;
        if (!isTerminate()) {
#ifdef MT
            pr = alloc_peer_req(peer, t);
#else
            pr = alloc_peer_req(peer);
#endif
            if (pr) {
                accepted = xseg_accept(xseg, i, X_NONBLOCK);
                if (accepted) {
                    pr->req = accepted;
                    pr->portno = i;
                    xseg_cancel_wait(xseg, i);
                    handle_accepted(peer, pr, accepted);
                    c = 1;
                } else {
                    free_peer_req(peer, pr);
                }
            }
        }
        received = xseg_receive(xseg, i, X_NONBLOCK);
        if (received) {
            r = xseg_get_req_data(xseg, received, (void **) &pr);
            if (r < 0 || !pr) {
                XSEGLOG2(&lc, W, "Received request with no pr data\n");
                xport p =
                    xseg_respond(peer->xseg, received, peer->portno_start,
                                 X_ALLOC);
                if (p == NoPort) {
                    XSEGLOG2(&lc, W, "Could not respond stale request");
                    xseg_put_request(xseg, received, portno_start);
                    continue;
                } else {
                    xseg_signal(xseg, p);
                }
            } else {
                //maybe perform sanity check for pr
                xseg_cancel_wait(xseg, i);
                handle_received(peer, pr, received);
                c = 1;
            }
        }
    }

    return c;
}

#ifdef MT
static void *thread_loop(void *arg)
{
    struct thread *t = (struct thread *) arg;
    struct peerd *peer = t->peer;
    struct xseg *xseg = peer->xseg;
    xport portno_start = peer->portno_start;
    xport portno_end = peer->portno_end;
    pid_t pid = syscall(SYS_gettid);
    uint64_t loops;
    uint64_t threshold = 1000 / (1 + portno_end - portno_start);

    XSEGLOG2(&lc, D, "thread %u\n", (unsigned int) (t - peer->thread));
    XSEGLOG2(&lc, I, "Thread %u has tid %u.\n",
             (unsigned int) (t - peer->thread), pid);
    for (; !(isTerminate() && xq_count(&peer->free_reqs) == peer->nr_ops);) {
        for (loops = threshold; loops > 0; loops--) {
            if (loops == 1) {
                xseg_prepare_wait(xseg, peer->portno_start);
            }
            if (check_ports(peer, t)) {
                loops = threshold;
            }
        }
        XSEGLOG2(&lc, I, "Thread %u goes to sleep\n",
                 (unsigned int) (t - peer->thread));
        xseg_wait_signal(xseg, peer->sd, 10000000UL);
        xseg_cancel_wait(xseg, peer->portno_start);
        XSEGLOG2(&lc, I, "Thread %u woke up\n",
                 (unsigned int) (t - peer->thread));
    }
    wake_up_next_thread(peer);
    custom_peer_finalize(peer);
    return NULL;
}

void *init_thread_loop(void *arg)
{
    struct thread *t = (struct thread *) arg;
    struct peerd *peer = t->peer;
    pthread_t thread = pthread_self();
    long int thread_num = t - t->peer->thread;
    char *thread_id;
    char *tmp;
    int i, thread_id_size;

    cpu_set_t mask;
    int r;

    if (cpu_list.len) {
        CPU_ZERO(&mask);
        CPU_SET(cpu_list.cpus[thread_num], &mask);
        r = pthread_setaffinity_np(thread, sizeof(mask), &mask);
        if (r < 0) {
            perror("sched_setaffinity");
            return NULL;
        }
    }


    /*
     * We need an identifier for every thread that will spin in peerd_loop.
     */
    thread_id_size = asprintf(&tmp, "Thread %ld", thread_num);
    thread_id = malloc((thread_id_size + 1) * sizeof(char));
    memcpy(thread_id, tmp, thread_id_size + 1);
    free(tmp);
    t->arg = (void *) thread_id;
    pthread_setspecific(threadkey, t);

    //Start thread loop
    (void) peer->peerd_loop(t);

    wake_up_next_thread(peer);
    custom_peer_finalize(peer);

    return NULL;
}

int peerd_start_threads(struct peerd *peer)
{
    int i;
    uint32_t nr_threads = peer->nr_threads;
    //TODO err check
    for (i = 0; i < nr_threads; i++) {
        peer->thread[i].thread_no = i;
        peer->thread[i].peer = peer;
        pthread_create(&peer->thread[i].tid, NULL,
                       init_thread_loop, (void *) (peer->thread + i));
    }

    if (peer->interactive_func) {
        peer->interactive_func();
    }
    for (i = 0; i < nr_threads; i++) {
        pthread_join(peer->thread[i].tid, NULL);
    }
    xseg_quit_local_signal(peer->xseg, peer->portno_start);

    return 0;
}
#endif

int defer_request(struct peerd *peer, struct peer_req *pr)
{
    int r;
    xport p;
    if (!canDefer(peer)) {
        XSEGLOG2(&lc, E, "Peer cannot defer requests");
        return -1;
    }
    p = xseg_forward(peer->xseg, pr->req, peer->defer_portno, pr->portno,
                     X_ALLOC);
    if (p == NoPort) {
        XSEGLOG2(&lc, E, "Cannot defer request %lx", pr->req);
        return -1;
    }
    r = xseg_signal(peer->xseg, p);
    if (r < 0) {
        XSEGLOG2(&lc, W, "Cannot signal port %lu", p);
    }
    free_peer_req(peer, pr);
    return 0;
}

/*
 * generic_peerd_loop is a general-purpose port-checker loop that is
 * suitable both for multi-threaded and single-threaded peers.
 */
static int generic_peerd_loop(void *arg)
{
#ifdef MT
    struct thread *t = (struct thread *) arg;
    struct peerd *peer = t->peer;
    char *id = t->arg;
#else
    struct peerd *peer = (struct peerd *) arg;
    char id[4] = { 'P', 'e', 'e', 'r' };
#endif
    struct xseg *xseg = peer->xseg;
    xport portno_start = peer->portno_start;
    xport portno_end = peer->portno_end;
    pid_t pid = syscall(SYS_gettid);
    uint64_t threshold = peer->threshold;
    threshold /= (1 + portno_end - portno_start);
    threshold += 1;
    uint64_t loops;

    XSEGLOG2(&lc, I, "%s has tid %u.\n", id, pid);
    //for (;!(isTerminate() && xq_count(&peer->free_reqs) == peer->nr_ops);) {
    for (; !(isTerminate() && all_peer_reqs_free(peer));) {
        //Heart of peerd_loop. This loop is common for everyone.
        for (loops = threshold; loops > 0; loops--) {
            if (loops == 1)
                xseg_prepare_wait(xseg, peer->portno_start);
#ifdef MT
            if (check_ports(peer, t))
#else
            if (check_ports(peer))
#endif
                loops = threshold;
        }
#ifdef ST_THREADS
        if (ta) {
            st_sleep(0);
            continue;
        }
#endif
        XSEGLOG2(&lc, I, "%s goes to sleep\n", id);
        xseg_wait_signal(xseg, peer->sd, 10000000UL);
        xseg_cancel_wait(xseg, peer->portno_start);
        XSEGLOG2(&lc, I, "%s woke up\n", id);
    }
    return 0;
}

static int init_peerd_loop(struct peerd *peer)
{
    struct xseg *xseg = peer->xseg;
    cpu_set_t mask;
    int r;

    if (cpu_list.len) {
        CPU_ZERO(&mask);
        CPU_SET(cpu_list.cpus[0], &mask);

        r = sched_setaffinity(0, sizeof(mask), &mask);
        if (r < 0) {
            perror("sched_setaffinity");
            return -1;
        }
    }

    peer->peerd_loop(peer);
    custom_peer_finalize(peer);
    xseg_quit_local_signal(xseg, peer->portno_start);

    return 0;
}

#ifdef ST_THREADS
static void *st_peerd_loop(void *peer)
{
    struct peerd *peerd = peer;

    return init_peerd_loop(peerd) ? (void *) -1 : (void *) 0;
}
#endif

static struct xseg *join(char *spec)
{
    struct xseg_config config;
    struct xseg *xseg;

    (void) xseg_parse_spec(spec, &config);
    xseg = xseg_join(config.type, config.name, PEER_TYPE, NULL);
    if (xseg) {
        return xseg;
    }

    (void) xseg_create(&config);
    return xseg_join(config.type, config.name, PEER_TYPE, NULL);
}

static struct peerd *peerd_init(uint32_t nr_ops, char *spec, long portno_start,
                                long portno_end, uint32_t nr_threads,
                                xport defer_portno, uint64_t threshold)
{
    int i, r;
    struct peerd *peer;
    struct xseg_port *port;
    void *sd = NULL;
    xport p;

#ifdef ST_THREADS
    st_init();
#endif
    peer = malloc(sizeof(struct peerd));
    if (!peer) {
        perror("malloc");
        return NULL;
    }
    peer->nr_ops = nr_ops;
    peer->defer_portno = defer_portno;
    peer->threshold = threshold;
#ifdef MT
    peer->nr_threads = nr_threads;
    peer->thread = calloc(nr_threads, sizeof(struct thread));
    if (!peer->thread) {
        goto malloc_fail;
    }
    if (!xq_alloc_empty(&peer->threads, nr_threads)) {
        goto malloc_fail;
    }
    for (i = 0; i < nr_threads; i++) {
        if (!xq_alloc_empty(&peer->thread[i].free_thread_reqs, nr_ops)) {
            goto malloc_fail;
        }
    }
    for (i = 0; i < nr_ops; i++) {
        __xq_append_head(&peer->thread[i % nr_threads].free_thread_reqs,
                         (xqindex) i);
    }

    pthread_key_create(&threadkey, NULL);
#else
    if (!xq_alloc_seq(&peer->free_reqs, nr_ops, nr_ops)) {
        goto malloc_fail;
    }
    if (peer->free_reqs.size < peer->nr_ops) {
        peer->nr_ops = peer->free_reqs.size;
    }
#endif
    peer->peer_reqs = calloc(nr_ops, sizeof(struct peer_req));
    if (!peer->peer_reqs) {
      malloc_fail:
        perror("malloc");
        return NULL;
    }
    if (xseg_initialize()) {
        printf("cannot initialize library\n");
        return NULL;
    }
    peer->xseg = join(spec);
    if (!peer->xseg) {
        return NULL;
    }

    peer->portno_start = (xport) portno_start;
    peer->portno_end = (xport) portno_end;

    /*
     * Start binding ports from portno_start to portno_end.
     * The first port we bind will have its signal_desc initialized by xseg
     * and the same signal_desc will be used for all the other ports.
     */
    peer->sd = NULL;
    for (p = peer->portno_start; p <= peer->portno_end; p++) {
        port = xseg_bind_port(peer->xseg, p, peer->sd);
        if (!port) {
            printf("cannot bind to port %u\n", (unsigned int) p);
            return NULL;
        }
        if (p == peer->portno_start) {
            peer->sd = xseg_get_signal_desc(peer->xseg, port);
        }
    }

    printf("Peer on ports  %u-%u\n", peer->portno_start, peer->portno_end);

    r = xseg_init_local_signal(peer->xseg, peer->portno_start);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Could not initialize local signals");
        return NULL;
    }

    for (i = 0; i < nr_ops; i++) {
        peer->peer_reqs[i].peer = peer;
        peer->peer_reqs[i].req = NULL;
        peer->peer_reqs[i].retval = 0;
        peer->peer_reqs[i].priv = NULL;
        peer->peer_reqs[i].portno = NoPort;
#ifdef ST_THREADS
        peer->peer_reqs[i].cond = st_cond_new();        //FIXME err check
#endif
    }

    //Plug default peerd_loop. This can change later on by custom_peer_init.
    peer->peerd_loop = generic_peerd_loop;

#ifdef MT
    peer->interactive_func = NULL;
#endif
    return peer;
}

int pidfile_remove(char *path, int fd)
{
    close(fd);
    return (unlink(path));
}

int pidfile_write(int pid_fd)
{
    char buf[16];
    snprintf(buf, sizeof(buf), "%ld", syscall(SYS_gettid));
    buf[15] = '\0';

    lseek(pid_fd, 0, SEEK_SET);
    int ret = write(pid_fd, buf, strlen(buf));
    return ret;
}

int pidfile_read(char *path, pid_t * pid)
{
    char buf[16], *endptr;
    *pid = 0;

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    int ret = read(fd, buf, 15);
    buf[15] = '\0';
    close(fd);
    if (ret < 0) {
        return -1;
    } else {
        *pid = strtol(buf, &endptr, 10);
        if (endptr != &buf[ret]) {
            *pid = 0;
            return -1;
        }
    }
    return 0;
}

int pidfile_open(char *path, pid_t * old_pid)
{
    //nfs version > 3
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY,
                  S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    if (fd < 0) {
        if (errno == EEXIST) {
            pidfile_read(path, old_pid);
        }
    }
    return fd;
}

int get_cpu_list(char *cpus, struct cpu_list *cpu_list)
{
    char *tok, *rem;
    int i = 0;

    while ((tok = strtok(cpus, ",")) != NULL) {
        cpu_list->cpus[i++] = strtol(tok, &rem, 10);
        if (strlen(rem) > 0) {  /* Not a number */
            return -1;
        }
        cpus = NULL;
    }

    cpu_list->len = i;

    return 0;
}

void usage(char *argv0)
{
    fprintf(stderr, "Usage: %s [general options] [custom peer options]\n\n",
            argv0);
    fprintf(stderr,
            "General peer options:\n" "  Option      | Default | \n"
            "  --------------------------------------------\n"
            "    -g        | None    | Segment spec to join\n"
            "    -sp       | NoPort  | Start portno to bind\n"
            "    -ep       | NoPort  | End portno to bind\n"
            "    -p        | NoPort  | Portno to bind\n"
            "    -n        | 16      | Number of ops\n"
            "    -v        | 0       | Verbosity level\n"
            "    -l        | None    | Logfile \n"
            "    -d        | No      | Daemonize \n"
            "    --pidfile | None    | Pidfile \n"
            "    -uid      | None    | Set real EUID \n"
            "    -gid      | None    | Set real EGID \n"
#ifdef MT
            "    -t        | No      | Number of threads \n"
#endif
            "    --cpus    | No      | Coma-separated list of CPUs\n"
            "              |         | to pin the process or threads\n" "\n");
    custom_peer_usage();
}

int main(int argc, char *argv[])
{
    struct peerd *peer = NULL;
    //parse args
    int r;
    long portno_start = -1, portno_end = -1, portno = -1;

    //set defaults here
    int daemonize = 0, help = 0;
    uint32_t nr_ops = 16;
    uint32_t nr_threads = 1;
    uint64_t threshold = 1000;
    unsigned int debug_level = 0;
    xport defer_portno = NoPort;
    pid_t old_pid = 0;
    int pid_fd = -1;
    uid_t cur_uid, uid = -1;
    gid_t cur_gid, gid = -1;
    mode_t peer_umask = PEER_DEFAULT_UMASK;

    char spec[MAX_SPEC_LEN + 1];
    char logfile[MAX_LOGFILE_LEN + 1];
    char pidfile[MAX_PIDFILE_LEN + 1];
    char cpus[MAX_CPUS_LEN + 1];

    char *username = NULL;

    logfile[0] = '\0';
    pidfile[0] = '\0';
    spec[0] = '\0';
    cpus[0] = '\0';

    //capture here -g spec, -n nr_ops, -p portno, -t nr_threads -v verbose level
    // -dp xseg_portno to defer blocking requests
    // -l log file ?
    //TODO print messages on arg parsing error
    BEGIN_READ_ARGS(argc, argv);
    READ_ARG_STRING("-g", spec, MAX_SPEC_LEN);
    READ_ARG_ULONG("-sp", portno_start);
    READ_ARG_ULONG("-ep", portno_end);
    READ_ARG_ULONG("-p", portno);
    READ_ARG_ULONG("-n", nr_ops);
    READ_ARG_ULONG("-v", debug_level);
    READ_ARG_ULONG("-uid", uid);
    READ_ARG_ULONG("-gid", gid);
#ifdef MT
    READ_ARG_ULONG("-t", nr_threads);
#endif
    READ_ARG_ULONG("-dp", defer_portno);
    READ_ARG_STRING("-l", logfile, MAX_LOGFILE_LEN);
    READ_ARG_BOOL("-d", daemonize);
    READ_ARG_BOOL("-h", help);
    READ_ARG_BOOL("--help", help);
    READ_ARG_ULONG("--threshold", threshold);
    READ_ARG_STRING("--cpus", cpus, MAX_CPUS_LEN);
    READ_ARG_STRING("--pidfile", pidfile, MAX_PIDFILE_LEN);
    READ_ARG_ULONG("--umask", peer_umask);
    END_READ_ARGS();

    if (help) {
        usage(argv[0]);
        return 0;
    }

    if (gid != -1) {
        struct group *gr;
        gr = getgrgid(gid);
        if (!gr) {
            XSEGLOG2(&lc, E, "Group %d not found", gid);
            return -1;
        }
    }

    if (uid != -1) {
        struct passwd *pw;
        pw = getpwuid(uid);
        if (!pw) {
            XSEGLOG2(&lc, E, "User %d not found", uid);
            return -1;
        }
        username = pw->pw_name;
        if (gid == -1) {
            gid = pw->pw_gid;
        }
    }

    cur_uid = geteuid();
    cur_gid = getegid();

    if (gid != -1 && cur_gid != gid && setregid(gid, gid)) {
        XSEGLOG2(&lc, E, "Could not set gid to %d", gid);
        return -1;
    }

    if (uid != -1) {
        if ((cur_gid != gid || cur_uid != uid)
            && initgroups(username, gid)) {
            XSEGLOG2(&lc, E, "Could not initgroups for user %s, "
                     "gid %d", username, gid);
            return -1;
        }

        if (cur_uid != uid && setreuid(uid, uid)) {
            XSEGLOG2(&lc, E, "Failed to set uid %d", uid);
        }
    }

    /* set umask of the process. Only keep permission bits */
    peer_umask &= 0777;
    umask(peer_umask);

    r = init_logctx(&lc, argv[0], debug_level, logfile,
                    REDIRECT_STDOUT | REDIRECT_STDERR);
    if (r < 0) {
        XSEGLOG("Cannot initialize logging to logfile");
        return -1;
    }
    XSEGLOG2(&lc, D, "Main thread has tid %ld.\n", syscall(SYS_gettid));

    if (pidfile[0]) {
        pid_fd = pidfile_open(pidfile, &old_pid);
        if (pid_fd < 0) {
            if (old_pid) {
                XSEGLOG2(&lc, E, "Daemon already running, pid: %d.", old_pid);
            } else {
                XSEGLOG2(&lc, E, "Cannot open or create pidfile");
            }
            return -1;
        }
    }

    if (daemonize) {
        if (close(STDIN_FILENO)) {
            XSEGLOG2(&lc, W, "Could not close stdin");
        }
        if (daemon(0, 1) < 0) {
            XSEGLOG2(&lc, E, "Cannot daemonize");
            r = -1;
            goto out;
        }
        /* Break away from process group */
        (void) setpgrp();
    }

    pidfile_write(pid_fd);

    if (cpus[0]) {
        r = get_cpu_list(cpus, &cpu_list);

        if (r < 0) {
            XSEGLOG2(&lc, E, "--cpus %s: Invalid input", cpus);
            goto out;
        }
#ifdef MT
        if (nr_threads != cpu_list.len) {
            XSEGLOG2(&lc, E, "--cpus %s: Number of "
                     "threads (%d) and CPUs don't match", cpus, nr_threads);
            goto out;
        }
#else
        if (cpu_list.len != 1) {
            XSEGLOG2(&lc, E, "--cpus %s: Too many CPUs for a "
                     "single process", cpus);
            goto out;
        }
#endif
    }

    //TODO perform argument sanity checks
    verbose = debug_level;
    if (portno != -1) {
        portno_start = portno;
        portno_end = portno;
    }
    if (portno_start == -1 || portno_end == -1) {
        XSEGLOG2(&lc, E,
                 "Portno or {portno_start, portno_end} must be supplied");
        usage(argv[0]);
        r = -1;
        goto out;
    }

    peer =
        peerd_init(nr_ops, spec, portno_start, portno_end, nr_threads,
                   defer_portno, threshold);
    if (!peer) {
        r = -1;
        goto out;
    }
    setup_signals(peer);
    r = custom_peer_init(peer, argc, argv);
    if (r < 0) {
        goto out;
    }
#if defined(MT)
    //TODO err check
    peerd_start_threads(peer);
#elif defined(ST_THREADS)
    st_thread_t st = st_thread_create(st_peerd_loop, peer, 1, 0);
    r = st_thread_join(st, NULL);
#else
    r = init_peerd_loop(peer);
#endif
  out:
    if (pid_fd > 0) {
        pidfile_remove(pidfile, pid_fd);
    }
    return r;
}
