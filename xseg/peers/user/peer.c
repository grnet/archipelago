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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#ifdef MT
#include <pthread.h>
#endif

#include <xseg/xseg.h>
#include <peer.h>

#ifdef MT
#define PEER_TYPE "pthread"
#else
#define PEER_TYPE "posix"
#endif

//FIXME this should not be defined here probably
#define MAX_SPEC_LEN 128
#define MAX_PIDFILE_LEN 512

volatile unsigned int terminated = 0;
unsigned int verbose = 0;
struct log_ctx lc;
#ifdef ST_THREADS
uint32_t ta = 0;
#endif

#ifdef MT
struct peerd *global_peer;

struct thread {
	struct peerd *peer;
	pthread_t tid;
	pthread_cond_t cond;
	pthread_mutex_t lock;
	void (*func)(void *arg);
	void *arg;
};

inline static struct thread* alloc_thread(struct peerd *peer)
{
	xqindex idx = xq_pop_head(&peer->threads, 1);
	if (idx == Noneidx)
		return NULL;
	return peer->thread + idx;
}

inline static void free_thread(struct peerd *peer, struct thread *t)
{
	xqindex idx = t - peer->thread;
	xq_append_head(&peer->threads, idx, 1);
}


inline static void __wake_up_thread(struct thread *t)
{
	pthread_mutex_lock(&t->lock);
	pthread_cond_signal(&t->cond);
	pthread_mutex_unlock(&t->lock);
}

inline static void wake_up_thread(struct thread* t)
{
	if (t){
		__wake_up_thread(t);
	}
}

inline static int wake_up_next_thread(struct peerd *peer)
{
	return (xseg_signal(peer->xseg, peer->portno_start));
}
#endif

/*
 * extern is needed if this function is going to be called by another file
 * such as bench-xseg.c
 */
inline extern int isTerminate()
{
/* ta doesn't need to be taken into account, because the main loops
 * doesn't check the terminated flag if ta is not 0.
 */
	/*
#ifdef ST_THREADS
	return (!ta & terminated);
#else
	return terminated;
#endif
	*/
	return terminated;
}

void signal_handler(int signal)
{
	XSEGLOG2(&lc, I, "Caught signal. Terminating gracefully");
	terminated = 1;
#ifdef MT
	wake_up_next_thread(global_peer);
#endif
}

void renew_logfile(int signal)
{
	XSEGLOG2(&lc, I, "Caught signal. Renewing logfile");
	renew_logctx(&lc, NULL, verbose, NULL, REOPEN_FILE);
}

static int setup_signals(struct peerd *peer)
{
	int r;
	struct sigaction sa;
#ifdef MT
	global_peer = peer;
#endif
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = signal_handler;
	r = sigaction(SIGTERM, &sa, NULL);
	if (r < 0)
		return r;
	r = sigaction(SIGINT, &sa, NULL);
	if (r < 0)
		return r;
	r = sigaction(SIGQUIT, &sa, NULL);
	if (r < 0)
		return r;

	sa.sa_handler = renew_logfile;
	r = sigaction(SIGUSR1, &sa, NULL);
	if (r < 0)
		return r;

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
	unsigned int end = (req->targetlen> 63) ? 63 : req->targetlen;
	req_target = xseg_get_target(xseg, req);
	req_data = xseg_get_data(xseg, req);

	if (1) {
		strncpy(target, req_target, end);
		target[end] = 0;
		strncpy(data, req_data, 63);
		data[63] = 0;
		printf("req id:%lu, op:%u %llu:%lu serviced: %lu, reqstate: %u\n"
				"src: %u, transit: %u, dst: %u effective dst: %u\n"
				"target[%u]:'%s', data[%llu]:\n%s------------------\n\n",
				(unsigned long)(req),
				(unsigned int)req->op,
				(unsigned long long)req->offset,
				(unsigned long)req->size,
				(unsigned long)req->serviced,
				(unsigned int)req->state,
				(unsigned int)req->src_portno,
				(unsigned int)req->transit_portno,
				(unsigned int)req->dst_portno,
				(unsigned int)req->effective_dst_portno,
				(unsigned int)req->targetlen, target,
				(unsigned long long)req->datalen, data);
	}
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
	unsigned int end = (pr->req->targetlen> 63) ? 63 : pr->req->targetlen;
	if (verbose) {
		strncpy(target, req_target, end);
		target[end] = 0;
		strncpy(data, req_data, 63);
		data[63] = 0;
		printf("%s: req id:%u, op:%u %llu:%lu serviced: %lu, retval: %lu, reqstate: %u\n"
				"target[%u]:'%s', data[%llu]:\n%s------------------\n\n",
				msg,
				(unsigned int)(pr - peer->peer_reqs),
				(unsigned int)pr->req->op,
				(unsigned long long)pr->req->offset,
				(unsigned long)pr->req->size,
				(unsigned long)pr->req->serviced,
				(unsigned long)pr->retval,
				(unsigned int)pr->req->state,
				(unsigned int)pr->req->targetlen, target,
				(unsigned long long)pr->req->datalen, data);
	}
}

inline struct peer_req *alloc_peer_req(struct peerd *peer)
{
	xqindex idx = xq_pop_head(&peer->free_reqs, 1);
	if (idx == Noneidx)
		return NULL;
	return peer->peer_reqs + idx;
}

inline void free_peer_req(struct peerd *peer, struct peer_req *pr)
{
	xqindex idx = pr - peer->peer_reqs;
	pr->req = NULL;
	xq_append_head(&peer->free_reqs, idx, 1);
}

struct timeval resp_start, resp_end, resp_accum = {0, 0};
uint64_t responds = 0;
void get_responds_stats(){
		printf("Time waiting respond %lu.%06lu sec for %llu times.\n",
				//(unsigned int)(t - peer->thread),
				resp_accum.tv_sec, resp_accum.tv_usec, (long long unsigned int) responds);
}

//FIXME error check
void fail(struct peerd *peer, struct peer_req *pr)
{
	struct xseg_request *req = pr->req;
	uint32_t p;
	XSEGLOG2(&lc, D, "failing req %u", (unsigned int) (pr - peer->peer_reqs));
	req->state |= XS_FAILED;
	//xseg_set_req_data(peer->xseg, pr->req, NULL);
	p = xseg_respond(peer->xseg, req, pr->portno, X_ALLOC);
	xseg_signal(peer->xseg, p);
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
struct timeval sub_start, sub_end, sub_accum = {0, 0};
uint64_t submits = 0;
void get_submits_stats(){
		printf("Time waiting submit %lu.%06lu sec for %llu times.\n",
				//(unsigned int)(t - peer->thread),
				sub_accum.tv_sec, sub_accum.tv_usec, (long long unsigned int) submits);
}

int submit_peer_req(struct peerd *peer, struct peer_req *pr)
{
	uint32_t ret;
	struct xseg_request *req = pr->req;
	// assert req->portno == peer->portno ?
	//TODO small function with error checking
	XSEGLOG2 (&lc, D, "submitting peer req %u\n", (unsigned int)(pr - peer->peer_reqs));
	ret = xseg_set_req_data(peer->xseg, req, (void *)(pr));
	if (ret < 0)
		return -1;
	//printf("pr: %x , req_data: %x \n", pr, xseg_get_req_data(peer->xseg, req));
	//gettimeofday(&sub_start, NULL);
	ret = xseg_submit(peer->xseg, req, pr->portno, X_ALLOC);
	//gettimeofday(&sub_end, NULL);
	//submits++;
	//timersub(&sub_end, &sub_start, &sub_end);
	//timeradd(&sub_end, &sub_accum, &sub_accum);
	if (ret == NoPort)
		return -1;
	xseg_signal(peer->xseg, ret);
	return 0;
}

int check_ports(struct peerd *peer)
{
	struct xseg *xseg = peer->xseg;
	xport portno_start = peer->portno_start;
	xport portno_end = peer->portno_end;
	struct xseg_request *accepted, *received;
	struct peer_req *pr;
	xport i;
	int  r, c = 0;

	for (i = portno_start; i <= portno_end; i++) {
		accepted = NULL;
		received = NULL;
		if (!isTerminate()) {
			pr = alloc_peer_req(peer);
			if (pr) {
				accepted = xseg_accept(xseg, i, X_NONBLOCK);
				if (accepted) {
					pr->req = accepted;
					pr->portno = i;
					xseg_cancel_wait(xseg, i);
					handle_accepted(peer, pr, accepted);
					c = 1;
				}
				else {
					free_peer_req(peer, pr);
				}
			}
		}
		received = xseg_receive(xseg, i, X_NONBLOCK);
		if (received) {
			r =  xseg_get_req_data(xseg, received, (void **) &pr);
			if (r < 0 || !pr){
				XSEGLOG2(&lc, W, "Received request with no pr data\n");
				xport p = xseg_respond(peer->xseg, received, peer->portno_start, X_ALLOC);
				if (p == NoPort){
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
int thread_execute(struct peerd *peer, void (*func)(void *arg), void *arg)
{
	struct thread *t = alloc_thread(peer);
	if (t) {
		t->func = func;
		t->arg = arg;
		wake_up_thread(t);
		return 0;
	} else
		// we could hijack a thread
		return -1;
}

static void* thread_loop(void *arg)
{
	struct thread *t = (struct thread *) arg;
	struct peerd *peer = t->peer;
	struct xseg *xseg = peer->xseg;
	xport portno_start = peer->portno_start;
	xport portno_end = peer->portno_end;
	pid_t pid =syscall(SYS_gettid);
	uint64_t loops;
	uint64_t threshold=1000/(1 + portno_end - portno_start);

	XSEGLOG2(&lc, D, "thread %u\n",  (unsigned int) (t- peer->thread));

	XSEGLOG2(&lc, I, "Thread %u has tid %u.\n", (unsigned int) (t- peer->thread), pid);
	xseg_init_local_signal(xseg, peer->portno_start);
	for (;!(isTerminate() && xq_count(&peer->free_reqs) == peer->nr_ops);) {
		XSEGLOG("Head of loop.\n");
		if (t->func) {
			XSEGLOG2(&lc, D, "Thread %u executes function\n", (unsigned int) (t- peer->thread));
			xseg_cancel_wait(xseg, peer->portno_start);
			t->func(t->arg);
			t->func = NULL;
			t->arg = NULL;
			continue;
		}

		for(loops =  threshold; loops > 0; loops--) {
			if (loops == 1)
				xseg_prepare_wait(xseg, peer->portno_start);
			if (check_ports(peer))
				loops = threshold;
		}
		XSEGLOG2(&lc, I, "Thread %u goes to sleep\n", (unsigned int) (t- peer->thread));
		xseg_wait_signal(xseg, 10000000UL);
		xseg_cancel_wait(xseg, peer->portno_start);
		XSEGLOG2(&lc, I, "Thread %u woke up\n", (unsigned int) (t- peer->thread));
	}
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
		peer->thread[i].peer = peer;
		pthread_cond_init(&peer->thread[i].cond,NULL);
		pthread_mutex_init(&peer->thread[i].lock, NULL);
		pthread_create(&peer->thread[i].tid, NULL, thread_loop, (void *)(peer->thread + i));
		peer->thread[i].func = NULL;
		peer->thread[i].arg = NULL;

	}
	return 0;
}
#endif


int defer_request(struct peerd *peer, struct peer_req *pr)
{
	int r;
	xport p;
	if (!canDefer(peer)){
		XSEGLOG2(&lc, E, "Peer cannot defer requests");
		return -1;
	}
	p = xseg_forward(peer->xseg, pr->req, peer->defer_portno, pr->portno,
			X_ALLOC);
	if (p == NoPort){
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

static int peerd_loop(struct peerd *peer)
{
#ifdef MT
	int i;
	if (peer->interactive_func)
		peer->interactive_func();
	for (i = 0; i < peer->nr_threads; i++) {
		pthread_join(peer->thread[i].tid, NULL);
	}
#else
	struct xseg *xseg = peer->xseg;
	xport portno_start = peer->portno_start;
	xport portno_end = peer->portno_end;
	uint64_t threshold=1000/(1 + portno_end - portno_start);
	pid_t pid =syscall(SYS_gettid);
	uint64_t loops;

	XSEGLOG2(&lc, I, "Peer has tid %u.\n", pid);
	xseg_init_local_signal(xseg, peer->portno_start);
	for (;!(isTerminate() && xq_count(&peer->free_reqs) == peer->nr_ops);) {
		for(loops= threshold; loops > 0; loops--) {
			if (loops == 1)
				xseg_prepare_wait(xseg, peer->portno_start);
			if (check_ports(peer))
				loops = threshold;
		}
#ifdef ST_THREADS
		if (ta){
			st_sleep(0);
		} else {
#endif
			XSEGLOG2(&lc, I, "Peer goes to sleep\n");
			xseg_wait_signal(xseg, 10000000UL);
			xseg_cancel_wait(xseg, peer->portno_start);
			XSEGLOG2(&lc, I, "Peer woke up\n");
#ifdef ST_THREADS
		}
#endif
	}
	custom_peer_finalize(peer);
	xseg_quit_local_signal(xseg, peer->portno_start);
#endif
	return 0;
}

static struct xseg *join(char *spec)
{
	struct xseg_config config;
	struct xseg *xseg;

	(void)xseg_parse_spec(spec, &config);
	xseg = xseg_join(config.type, config.name, PEER_TYPE, NULL);
	if (xseg)
		return xseg;

	(void)xseg_create(&config);
	return xseg_join(config.type, config.name, PEER_TYPE, NULL);
}

static struct peerd* peerd_init(uint32_t nr_ops, char* spec, long portno_start,
			long portno_end, uint32_t nr_threads, xport defer_portno)
{
	int i;
	struct peerd *peer;
	struct xseg_port *port;

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
#ifdef MT
	peer->nr_threads = nr_threads;
	peer->thread = calloc(nr_threads, sizeof(struct thread));
	if (!peer->thread)
		goto malloc_fail;
#endif
	peer->peer_reqs = calloc(nr_ops, sizeof(struct peer_req));
	if (!peer->peer_reqs){
malloc_fail:
		perror("malloc");
		return NULL;
	}

	if (!xq_alloc_seq(&peer->free_reqs, nr_ops, nr_ops))
		goto malloc_fail;
#ifdef MT
	if (!xq_alloc_empty(&peer->threads, nr_threads))
		goto malloc_fail;
#endif
	if (xseg_initialize()){
		printf("cannot initialize library\n");
		return NULL;
	}
	peer->xseg = join(spec);
	if (!peer->xseg)
		return NULL;

	peer->portno_start = (xport) portno_start;
	peer->portno_end= (xport) portno_end;
	port = xseg_bind_port(peer->xseg, peer->portno_start, NULL);
	if (!port){
		printf("cannot bind to port %u\n", (unsigned int) peer->portno_start);
		return NULL;
	}

	xport p;
	for (p = peer->portno_start + 1; p <= peer->portno_end; p++) {
		struct xseg_port *tmp;
		tmp = xseg_bind_port(peer->xseg, p, (void *)xseg_get_signal_desc(peer->xseg, port));
		if (!tmp){
			printf("cannot bind to port %u\n", (unsigned int) p);
			return NULL;
		}
	}

	printf("Peer on ports  %u-%u\n", peer->portno_start,
			peer->portno_end);

	for (i = 0; i < nr_ops; i++) {
		peer->peer_reqs[i].peer = peer;
		peer->peer_reqs[i].req = NULL;
		peer->peer_reqs[i].retval = 0;
		peer->peer_reqs[i].priv = NULL;
		peer->peer_reqs[i].portno = NoPort;
#ifdef ST_THREADS
		peer->peer_reqs[i].cond = st_cond_new(); //FIXME err check
#endif
	}
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
	buf[15] = 0;

	lseek(pid_fd, 0, SEEK_SET);
	int ret = write(pid_fd, buf, strlen(buf));
	return ret;
}

int pidfile_read(char *path, pid_t *pid)
{
	char buf[16], *endptr;
	*pid = 0;

	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	int ret = read(fd, buf, 15);
	buf[15]=0;
	close(fd);
	if (ret < 0)
		return -1;
	else{
		*pid = strtol(buf, &endptr, 10);
		if (endptr != &buf[ret]){
			*pid = 0;
			return -1;
		}
	}
	return 0;
}

int pidfile_open(char *path, pid_t *old_pid)
{
	//nfs version > 3
	int fd = open(path, O_CREAT|O_EXCL|O_WRONLY, S_IWUSR);
	if (fd < 0){
		if (errno == EEXIST)
			pidfile_read(path, old_pid);
	}
	return fd;
}

void usage(char *argv0)
{
	fprintf(stderr, "Usage: %s [general options] [custom peer options]\n\n", argv0);
	fprintf(stderr, "General peer options:\n"
		"  Option      | Default | \n"
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
#ifdef MT
		"    -t        | No      | Number of threads \n"
#endif
		"\n"
	       );
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
	unsigned int debug_level = 0;
	xport defer_portno = NoPort;
	pid_t old_pid;
	int pid_fd = -1;

	char spec[MAX_SPEC_LEN + 1];
	char logfile[MAX_LOGFILE_LEN + 1];
	char pidfile[MAX_PIDFILE_LEN + 1];

	logfile[0] = 0;
	pidfile[0] = 0;
	spec[0] = 0;

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
#ifdef MT
	READ_ARG_ULONG("-t", nr_threads);
#endif
	READ_ARG_ULONG("-dp", defer_portno);
	READ_ARG_STRING("-l", logfile, MAX_LOGFILE_LEN);
	READ_ARG_BOOL("-d", daemonize);
	READ_ARG_BOOL("-h", help);
	READ_ARG_BOOL("--help", help);
	READ_ARG_STRING("--pidfile", pidfile, MAX_PIDFILE_LEN);
	END_READ_ARGS();

	if (help){
		usage(argv[0]);
		return 0;
	}

	r = init_logctx(&lc, argv[0], debug_level, logfile,
			REDIRECT_STDOUT|REDIRECT_STDERR);
	if (r < 0){
		XSEGLOG("Cannot initialize logging to logfile");
		return -1;
	}
	XSEGLOG2(&lc, D, "Main thread has tid %ld.\n", syscall(SYS_gettid));

	if (pidfile[0]){
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

	if (daemonize){
		if (daemon(0, 1) < 0){
			XSEGLOG2(&lc, E, "Cannot daemonize");
			r = -1;
			goto out;
		}
	}

	pidfile_write(pid_fd);

	//TODO perform argument sanity checks
	verbose = debug_level;
	if (portno != -1) {
		portno_start = portno;
		portno_end = portno;
	}
	if (portno_start == -1 || portno_end == -1){
		XSEGLOG2(&lc, E, "Portno or {portno_start, portno_end} must be supplied");
		usage(argv[0]);
		r = -1;
		goto out;
	}

	peer = peerd_init(nr_ops, spec, portno_start, portno_end, nr_threads, defer_portno);
	if (!peer){
		r = -1;
		goto out;
	}
	setup_signals(peer);
	r = custom_peer_init(peer, argc, argv);
	if (r < 0)
		goto out;
#ifdef MT
	//TODO err check
	peerd_start_threads(peer);
#endif

#ifdef ST_THREADS
	st_thread_t st = st_thread_create(peerd_loop, peer, 1, 0);
	r = st_thread_join(st, NULL);
#else
	if (peer->custom_peerd_loop)
		r = peer->custom_peerd_loop(peer);
	else
		r = peerd_loop(peer);
#endif
out:
	if (pid_fd > 0)
		pidfile_remove(pidfile, pid_fd);
	return r;
}
