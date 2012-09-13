#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>
#include <xseg/xseg.h>
#include <mpeer.h>
#include <time.h>

struct timespec delay = {0, 4000000};
int custom_peer_init(struct peerd *peer, int argc, const char *argv[])
{
	return 0;
}

int dispatch(struct peerd *peer, struct peer_req *pr, struct xseg_request *req)
{
	if (canDefer(peer))
		defer_request(peer, pr);
	else {
//		printf("completing req id: %u (remote %u)\n", (unsigned int) (pr - peer->peer_reqs), (unsigned int) pr->req->priv);
//		nanosleep(&delay,NULL);
		complete(peer, pr);
	}
	return 0;
}
