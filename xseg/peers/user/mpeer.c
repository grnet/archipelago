#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <xseg/xseg.h>
#include <pthread.h>
#include <mpeer.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <signal.h>

#define REARRANGE(__fun_name__, __format__, ...) __format__ "%s", __fun_name__, ##__VA_ARGS__
#define LOG(level, ...)                                              \
	        do {                                                               \
			if (level <=  verbose) {                           \
				fprintf(stderr, "%s: "  REARRANGE( __func__ , ## __VA_ARGS__, "" )); \
			}                                                          \
		}while (0)


unsigned int verbose = 0;

struct thread {
	struct peerd *peer;
	pthread_t tid;
	pthread_cond_t cond;
	pthread_mutex_t lock;
	void (*func)(void *arg);
	void *arg;
};


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
				"src: %u, st: %u, dst: %u dt: %u\n"
				"target[%u]:'%s', data[%llu]:\n%s------------------\n\n",
				(unsigned long)(req),
				(unsigned int)req->op,
				(unsigned long long)req->offset,
				(unsigned long)req->size,
				(unsigned long)req->serviced,
				(unsigned int)req->state,
				(unsigned int)req->src_portno,
				(unsigned int)req->src_transit_portno,
				(unsigned int)req->dst_portno,
				(unsigned int)req->dst_transit_portno,
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
	 *          * and next character after name (aka first byte of next buffer) is not
	 *                   * null
	 *                            */
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
	//struct thread *t = alloc_thread(peer);
	//wake_up_thread(t);
	//return t;
	return (xseg_signal(peer->xseg, peer->portno));
}

struct timeval resp_start, resp_end, resp_accum = {0, 0};
uint64_t responds = 0;
void get_responds_stats(){
		printf("Time waiting respond %lu.%06lu sec for %llu times.\n",
				//(unsigned int)(t - peer->thread),
				resp_accum.tv_sec, resp_accum.tv_usec, responds);
}

//FIXME error check
void fail(struct peerd *peer, struct peer_req *pr)
{
	struct xseg_request *req = pr->req;
	uint32_t p;
	LOG(5, "failing req %u\n", (unsigned int) (pr - peer->peer_reqs));
	req->state |= XS_FAILED;
	//xseg_set_req_data(peer->xseg, pr->req, NULL);
	p = xseg_respond(peer->xseg, req, peer->portno, X_ALLOC);
	xseg_signal(peer->xseg, p);
	free_peer_req(peer, pr);
	wake_up_next_thread(peer);
}

//FIXME error check
void complete(struct peerd *peer, struct peer_req *pr)
{
	struct xseg_request *req = pr->req;
	uint32_t p;
	req->state |= XS_SERVED;
	//xseg_set_req_data(peer->xseg, pr->req, NULL);
	//gettimeofday(&resp_start, NULL);
	p = xseg_respond(peer->xseg, req, peer->portno, X_ALLOC);
	//gettimeofday(&resp_end, NULL);
	//responds++;
	//timersub(&resp_end, &resp_start, &resp_end);
	//timeradd(&resp_end, &resp_accum, &resp_accum);
	//printf("xseg_signal: %u\n", p);
	xseg_signal(peer->xseg, p);
	free_peer_req(peer, pr);
	wake_up_next_thread(peer);
}

void pending(struct peerd *peer, struct peer_req *pr)
{
	        pr->req->state = XS_PENDING;
}

static void handle_accepted(struct peerd *peer, struct peer_req *pr, 
				struct xseg_request *req)
{
	struct xseg_request *xreq = pr->req;
	//assert xreq == req;
	LOG(4, "Handle accepted \n");
	xreq->serviced = 0;
	//xreq->state = XS_ACCEPTED;
	pr->retval = 0;
	dispatch(peer, pr, req);
}

static void handle_received(struct peerd *peer, struct peer_req *pr,
				struct xseg_request *req)
{
	//struct xseg_request *req = pr->req;
	//assert req->state != XS_ACCEPTED;
	LOG(4, "Handle received \n");
	dispatch(peer, pr, req);

}
struct timeval sub_start, sub_end, sub_accum = {0, 0};
uint64_t submits = 0;
void get_submits_stats(){
		printf("Time waiting submit %lu.%06lu sec for %llu times.\n",
				//(unsigned int)(t - peer->thread),
				sub_accum.tv_sec, sub_accum.tv_usec, submits);
}

int submit_peer_req(struct peerd *peer, struct peer_req *pr)
{
	uint32_t ret;
	struct xseg_request *req = pr->req;
	// assert req->portno == peer->portno ?
	//TODO small function with error checking
	LOG (5, "submitting peer req %u\n", (unsigned int)(pr - peer->peer_reqs));
	ret = xseg_set_req_data(peer->xseg, req, (void *)(pr));
	if (ret < 0)
		return -1;
	//printf("pr: %x , req_data: %x \n", pr, xseg_get_req_data(peer->xseg, req));
	//gettimeofday(&sub_start, NULL);
	ret = xseg_submit(peer->xseg, req, peer->portno, X_ALLOC);
	//gettimeofday(&sub_end, NULL);
	//submits++;
	//timersub(&sub_end, &sub_start, &sub_end);
	//timeradd(&sub_end, &sub_accum, &sub_accum);
	if (ret == NoPort)
		return -1;
	xseg_signal(peer->xseg, ret);
	return 0;
}

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
	uint32_t portno = peer->portno;
	struct peer_req *pr;
	uint64_t threshold=1000;
	pid_t pid =syscall(SYS_gettid);
	uint64_t loops;
	struct xseg_request *accepted, *received;
	int r;
		
	printf("thread %u\n",  (unsigned int) (t- peer->thread));

	LOG(0, "Thread %u has tid %u.\n", (unsigned int) (t- peer->thread), pid);
	xseg_init_local_signal(xseg, portno);
	for (;;) {
		if (t->func) {
			LOG(5, "Thread %u executes function\n", (unsigned int) (t- peer->thread));
			xseg_cancel_wait(xseg, portno);
			t->func(t->arg);
			t->func = NULL;
			t->arg = NULL;
			continue;
		}

		for(loops= threshold; loops > 0; loops--) {
			accepted = NULL;
			received = NULL;
			if (loops == 1)
				xseg_prepare_wait(xseg, portno);

//			if (xq_count(&peer->xport->request_queue)){
				pr = alloc_peer_req(peer);
				if (pr) {
					accepted = xseg_accept(xseg, peer->portno);
					LOG(5, "Thread %u accepted\n", (unsigned int) (t- peer->thread));
					if (accepted) {
						pr->req = accepted;
						xseg_cancel_wait(xseg, portno);
						wake_up_next_thread(peer);
						handle_accepted(peer, pr, accepted);
						loops = threshold;
					}
					else {
						free_peer_req(peer, pr);
					}
				}
//			}
//			if (xq_count(&peer->xport->reply_queue)){
				received = xseg_receive(xseg, peer->portno);
				if (received) {
					//printf("received req id: %u\n", received - xseg->requests);
					//print_req(peer->xseg, received);
					r =  xseg_get_req_data(xseg, received, (void **) &pr);
					if (r < 0 || !pr){
						//FIXME what to do here ?
						LOG(0, "Received request with no pr data\n");
						xseg_respond(peer->xseg, received, peer->portno, X_ALLOC);
					}
					//fail(peer, received);
					//assert pr->req == received;
					xseg_cancel_wait(xseg, portno);
					wake_up_next_thread(peer);
					handle_received(peer, pr, received);
					loops = threshold;
				}
//			}
		}
		LOG(1, "Thread %u goes to sleep\n", (unsigned int) (t- peer->thread));
		xseg_wait_signal(xseg, 10000000UL);
		xseg_cancel_wait(xseg, portno);
		LOG(1, "Thread %u woke up\n", (unsigned int) (t- peer->thread));
	}
	return NULL;
}

void defer_request(struct peerd *peer, struct peer_req *pr)
{
	// assert canDefer(peer);
//	xseg_submit(peer->xseg, peer->defer_portno, pr->req);
//	xseg_signal(peer->xseg, peer->defer_portno);
//	free_peer_req(peer, pr);
}

static int peerd_loop(struct peerd *peer) 
{
	if (peer->interactive_func)
		peer->interactive_func();
	for (;;) {
		pthread_join(peer->thread[0].tid, NULL);
	}
	return 0;
}

static struct xseg *join(char *spec)
{
	struct xseg_config config;
	struct xseg *xseg;

	(void)xseg_parse_spec(spec, &config);
	xseg = xseg_join(config.type, config.name, "pthread", NULL);
	if (xseg)
		return xseg;

	(void)xseg_create(&config);
	return xseg_join(config.type, config.name, "pthread", NULL);
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

static struct peerd* peerd_init(uint32_t nr_ops, char* spec, long portno, uint32_t nr_threads, uint32_t defer_portno)
{
	int i;
	struct peerd *peer;
	peer = malloc(sizeof(struct peerd));
	if (!peer) {
		perror("malloc");
		return NULL;
	}
	peer->nr_ops = nr_ops;
	peer->defer_portno = defer_portno;
	peer->nr_threads = nr_threads;

	peer->thread = calloc(nr_threads, sizeof(struct thread));
	if (!peer->thread)
		goto malloc_fail;
	peer->peer_reqs = calloc(nr_ops, sizeof(struct peer_req));
	if (!peer->peer_reqs){
malloc_fail:
		perror("malloc");
		return NULL;
	}

	if (!xq_alloc_seq(&peer->free_reqs, nr_ops, nr_ops))
		goto malloc_fail;
	if (!xq_alloc_empty(&peer->threads, nr_threads))
		goto malloc_fail;

	if (xseg_initialize()){
		printf("cannot initialize library\n");
		return NULL;
	}
	peer->xseg = join(spec);
	if (!peer->xseg) 
		return NULL;

	peer->xport = xseg_bind_port(peer->xseg, portno);
	if (!peer->xport){
		printf("cannot bind to port %ld\n", portno);
		return NULL;
	}
	printf("%lx\n", (unsigned long) peer->xport);
	peer->portno = xseg_portno(peer->xseg, peer->xport);
	printf("Peer on port %u/%u\n", peer->portno,
			peer->xseg->config.nr_ports);

	for (i = 0; i < nr_ops; i++) {
		peer->peer_reqs[i].peer = peer;
		peer->peer_reqs[i].req = NULL;
		peer->peer_reqs[i].retval = 0;
		peer->peer_reqs[i].priv = NULL;
	}
	peer->interactive_func = NULL;
	return peer;
}


int main(int argc, const char *argv[])
{
	struct peerd *peer = NULL;
	//parse args
	char *spec = "";
	int i, r;
	long portno = -1;
	//set defaults here
	uint32_t nr_ops = 16;
	uint32_t nr_threads = 16 ;
	unsigned int debug_level = 0;
	uint32_t defer_portno = NoPort;
	
	//capture here -g spec, -n nr_ops, -p portno, -t nr_threads -v verbose level
	// -dp xseg_portno to defer blocking requests
	//maybe -l log file ?
	//TODO print messages on arg parsing error
	LOG(5, "Main thread has tid %ld.\n", syscall(SYS_gettid));
	
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-g") && i + 1 < argc) {
			spec = argv[i+1];
			i += 1;
			continue;
		}

		if (!strcmp(argv[i], "-p") && i + 1 < argc) {
			portno = strtoul(argv[i+1], NULL, 10);
			i += 1;
			continue;
		}

		if (!strcmp(argv[i], "-n") && i + 1 < argc) {
			nr_ops = strtoul(argv[i+1], NULL, 10);
			i += 1;
			continue;
		}
		if (!strcmp(argv[i], "-v") && i + 1 < argc ) {
			debug_level = atoi(argv[i+1]);
			i += 1;
			continue;
		}
		if (!strcmp(argv[i], "-t") && i + 1 < argc ) {
			nr_threads = strtoul(argv[i+1], NULL, 10);
			i += 1;
			continue;
		}
		if (!strcmp(argv[i], "-dp") && i + 1 < argc ) {
			defer_portno = strtoul(argv[i+1], NULL, 10);
			i += 1;
			continue;
		}

	}
	
	//TODO perform argument sanity checks
	verbose = debug_level;

	//TODO err check
	peer = peerd_init(nr_ops, spec, portno, nr_threads, defer_portno);
	r = custom_peer_init(peer, argc, argv);
	if (r < 0)
		return -1;
	peerd_start_threads(peer);
	return peerd_loop(peer);
}
