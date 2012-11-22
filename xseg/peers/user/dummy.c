#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>
#include <xseg/xseg.h>
#include <peer.h>
#include <time.h>
#include <sys/util.h>

struct timespec delay = {0, 4000000};

void custom_peer_usage()
{
	fprintf(stderr, "Custom peer options: \n"
			"none \n\n");
}
int custom_peer_init(struct peerd *peer, int argc, char *argv[])
{
	return 0;
}

int dispatch(struct peerd *peer, struct peer_req *pr, struct xseg_request *req,
		enum dispatch_reason reason)
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
