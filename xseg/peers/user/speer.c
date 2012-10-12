#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <xseg/xseg.h>
#include <speer.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <signal.h>


unsigned int verbose;
struct log_ctx lc;

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
	if (xseg_signal(peer->xseg, p) < 0)
		XSEGLOG2(&lc, W, "Cannot signal portno %u", p);
	free_peer_req(peer, pr);
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
	if (xseg_signal(peer->xseg, p) < 0)
		XSEGLOG2(&lc, W, "Cannot signal portno %u", p);
	free_peer_req(peer, pr);
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
	XSEGLOG2(&lc, D, "Handle accepted");
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
	XSEGLOG2(&lc, D, "Handle received \n");
	dispatch(peer, pr, req);

}

struct timeval sub_start, sub_end, sub_accum = {0, 0};
uint64_t submits = 0;
void get_submits_stats(){
		printf("Time waiting submit %lu.%06lu sec for %llu times.\n",
				sub_accum.tv_sec, sub_accum.tv_usec, (long long unsigned int) submits);
}

int submit_peer_req(struct peerd *peer, struct peer_req *pr)
{
	uint32_t ret;
	struct xseg_request *req = pr->req;
	// assert req->portno == peer->portno ?
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

static int check_ports(struct peerd *peer)
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

static int peerd_loop(struct peerd *peer)
{
	struct xseg *xseg = peer->xseg;
	xport portno_start = peer->portno_start;
	xport portno_end = peer->portno_end;
	uint64_t threshold=1000/(portno_end - portno_start);
	pid_t pid =syscall(SYS_gettid);
	uint64_t loops;
	
	XSEGLOG2(&lc, I, "Peer has tid %u.\n", pid);
	xseg_init_local_signal(xseg, peer->portno_start);
	for (;;) {
		for(loops= threshold; loops > 0; loops--) {
			if (loops == 1)
				xseg_prepare_wait(xseg, peer->portno_start);
			if (check_ports(peer))
				loops = threshold;
		}
		XSEGLOG2(&lc, I, "Peer goes to sleep\n");
		xseg_wait_signal(xseg, 10000000UL);
		xseg_cancel_wait(xseg, peer->portno_start);
		XSEGLOG2(&lc, I, "Peer woke up\n");
	}
	return 0;
}

void defer_request(struct peerd *peer, struct peer_req *pr)
{
	// assert canDefer(peer);
//	xseg_submit(peer->xseg, peer->defer_portno, pr->req);
//	xseg_signal(peer->xseg, peer->defer_portno);
//	free_peer_req(peer, pr);
}

static struct xseg *join(char *spec)
{
	struct xseg_config config;
	struct xseg *xseg;

	(void)xseg_parse_spec(spec, &config);
	xseg = xseg_join(config.type, config.name, "posix", NULL);
	if (xseg)
		return xseg;

	(void)xseg_create(&config);
	return xseg_join(config.type, config.name, "posix", NULL);
}

static struct peerd* peerd_init(uint32_t nr_ops, char* spec, long portno_start,
			long portno_end, uint32_t defer_portno)
{
	int i;
	struct peerd *peer;
	struct xseg_port *port;
	peer = malloc(sizeof(struct peerd));
	if (!peer) {
		perror("malloc");
		return NULL;
	}
	peer->nr_ops = nr_ops;
	peer->defer_portno = defer_portno;

	peer->peer_reqs = calloc(nr_ops, sizeof(struct peer_req));
	if (!peer->peer_reqs){
malloc_fail:
		perror("malloc");
		return NULL;
	}

	if (!xq_alloc_seq(&peer->free_reqs, nr_ops, nr_ops))
		goto malloc_fail;

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
		printf("cannot bind to port %ld\n", peer->portno_start);
		return NULL;
	}

	xport p;
	for (p = peer->portno_start + 1; p <= peer->portno_end; p++) {
		struct xseg_port *tmp;
		tmp = xseg_bind_port(peer->xseg, p, (void *)xseg_get_signal_desc(peer->xseg, port));
		if (!tmp){
			printf("cannot bind to port %ld\n", p);
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
	}
	return peer;
}


int main(int argc, char *argv[])
{
	struct peerd *peer = NULL;
	//parse args
	char *spec = "";
	int i, r;
	long portno_start = -1, portno_end = -1, portno = -1;;
	//set defaults here
	uint32_t nr_ops = 16;
	unsigned int debug_level = 0;
	uint32_t defer_portno = NoPort;
	char *logfile = NULL;

	//capture here -g spec, -n nr_ops, -p portno, -v verbose level
	// -dp xseg_portno to defer blocking requests
	// -l log file ?
	//TODO print messages on arg parsing error
	
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-g") && i + 1 < argc) {
			spec = argv[i+1];
			i += 1;
			continue;
		}

		if (!strcmp(argv[i], "-sp") && i + 1 < argc) {
			portno_start = strtoul(argv[i+1], NULL, 10);
			i += 1;
			continue;
		}
		
		if (!strcmp(argv[i], "-ep") && i + 1 < argc) {
			portno_end = strtoul(argv[i+1], NULL, 10);
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
		if (!strcmp(argv[i], "-dp") && i + 1 < argc ) {
			defer_portno = strtoul(argv[i+1], NULL, 10);
			i += 1;
			continue;
		}
		if (!strcmp(argv[i], "-l") && i + 1 < argc ) {
			logfile = argv[i+1];
			i += 1;
			continue;
		}

	}
	init_logctx(&lc, argv[0], debug_level, logfile);
	//TODO perform argument sanity checks
	verbose = debug_level;

	if (portno != -1) {
		portno_start = portno;
		portno_end = portno;
	}

	//TODO err check
	peer = peerd_init(nr_ops, spec, portno_start, portno_end, defer_portno);
	if (!peer)
		return -1;
	r = custom_peer_init(peer, argc, argv);
	if (r < 0)
		return -1;
	return peerd_loop(peer);
}
