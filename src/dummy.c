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

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>
#include <xseg/xseg.h>
#include <peer.h>
#include <time.h>
#include <xseg/util.h>

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

void custom_peer_finalize(struct peerd *peer)
{
	return;
}

int dispatch(struct peerd *peer, struct peer_req *pr, struct xseg_request *req,
		enum dispatch_reason reason)
{
	if (canDefer(peer))
		defer_request(peer, pr);
	else {
//		printf("completing req id: %u (remote %u)\n", (unsigned int) (pr - peer->peer_reqs), (unsigned int) pr->req->priv);
//		nanosleep(&delay,NULL);
		//print_req(peer->xseg, pr->req);
		complete(peer, pr);
	}
	return 0;
}
