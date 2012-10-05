#include <stddef.h>
#include <xseg/xseg.h>
/* main mpeer structs */
struct peer_req {
	struct peerd *peer;
	struct xseg_request *req;
	ssize_t retval;
	xport portno;
	void *priv;
};

struct peerd {
	struct xseg *xseg;
	struct xseg_port *port;
	xport portno_start;
	xport portno_end;
	long nr_ops;
	uint32_t nr_threads;
	uint32_t defer_portno;
	struct thread *thread;
	struct peer_req *peer_reqs;
	struct xq free_reqs;
	struct xq threads;
	void *priv;
	void (*interactive_func)(void);
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
int thread_execute(struct peerd *peer, void (*func)(void *arg), void *arg);
void get_submits_stats();
void get_responds_stats();

static inline struct peerd * __get_peerd(void * custom_peerd)
{
	return (struct peerd *) ((unsigned long) custom_peerd  - offsetof(struct peerd, priv));
}

/********************************
 *   mandatory peer functions   *
 ********************************/

/* peer main function */
int custom_peer_init(struct peerd *peer, int argc, char *argv[]);

/* dispatch function that cannot block
 * defers blocking calls to helper threads
 */
int dispatch(struct peerd *peer, struct peer_req *pr, struct xseg_request *xseg);

void usage();
