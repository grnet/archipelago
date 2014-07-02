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
#include <sys/time.h>

#define INPUT_BUF_SIZE 256
#define MAX_NR_ARGS 100

struct monitord {
	uint32_t mon_portno;
};

struct monitor_io {
	uint32_t src_portno;
	void *src_priv;
};

void custom_peer_usage()
{
	return;
}

static int forward(struct peerd *peer, struct peer_req *pr)
{
	int r;
	r = submit_peer_req(peer, pr);
	if (r < 0) {
		printf("couldn't forward request");
		return -1;
	}
	return 0;
}

static int complete_forwarded(struct peerd *peer, struct peer_req *pr)
{
	struct xseg_request *req = pr->req;

	// assert mio->src_portno != NoPort
	if (req->state & XS_SERVED)
		complete(peer, pr);
	else if (req->state & XS_FAILED)
		fail (peer, pr);
	else {
		printf("invalid state\n");
		return -1;
	}
	return 0;
}

int dispatch(struct peerd *peer, struct peer_req *pr, struct xseg_request *xreq,
		enum dispatch_reason reason)
{
	struct xseg_request *req = pr->req;
	if (req->state & (XS_SERVED | XS_FAILED)){
		log_pr("completing", pr);
		complete_forwarded(peer, pr);
	}
	else {
		log_pr("forwarding", pr);
		forward(peer,pr);
	}
	return 0;
}

int mpause(struct peerd *peer)
{
	struct xseg *xseg = peer->xseg;
	struct xseg_port *port = xseg_get_port(xseg, peer->portno_start);
	if (!port)
		return -1;
	
	xlock_acquire(&port->rq_lock, peer->portno_start);
	xlock_acquire(&port->pq_lock, peer->portno_start);
	return 0;
}

int munpause(struct peerd *peer)
{
	struct xseg *xseg = peer->xseg;
	struct xseg_port *port = xseg_get_port(xseg, peer->portno_start);
	if (!port)
		return -1;
	
	xlock_release(&port->rq_lock);
	xlock_release(&port->pq_lock);
	return 0;
}

struct peerd *main_peer;

void main_loop(void)
{
	int ret;
	struct peerd * peer = main_peer;
	char buf[INPUT_BUF_SIZE];
	char *nl;

	unsigned int portno = NoPort, dstgw, srcgw;

	for (;;){
		printf("waitin next line\n");
		if (fgets(buf, INPUT_BUF_SIZE, stdin)) {
			nl = strchr(buf, '\n');
			if (nl)
				*nl = 0;
			buf[INPUT_BUF_SIZE -1] = 0;
			printf("got line input\n");
			ret = sscanf(buf, "set srcgw %u %u", &portno, &srcgw);
			if (ret == 2){
				printf("found setsrcgw\n");
				xseg_set_srcgw(peer->xseg, (uint32_t) portno, (uint32_t) srcgw);
				continue;
			};
			ret = sscanf(buf, "set dstgw %u %u", &portno, &dstgw);
			if (ret == 2){
				printf("found set dstgw\n");
				xseg_set_dstgw(peer->xseg, (uint32_t) portno, (uint32_t) dstgw);
				continue;
			};
			ret = sscanf(buf, "getandset srcgw %u %u", &portno, &srcgw);
			if (ret == 2){
				printf("found getand set srcgw\n");
				xseg_getandset_srcgw(peer->xseg, (uint32_t) portno, (uint32_t) srcgw);
				continue;
			};
			ret = sscanf(buf, "getandset dstgw %u %u", &portno, &dstgw);
			if (ret == 2){
				printf("found getandset dstgw\n");
				xseg_getandset_dstgw(peer->xseg, (uint32_t) portno, (uint32_t) dstgw);
				continue;
			};
			ret = sscanf(buf, "pause %u", &portno);
			if (ret == 1){
				printf("found pause\n");
				mpause(peer);
				continue;
			};
			ret = sscanf(buf, "unpause %u", &portno);
			if (ret == 1){
				printf("found unpause\n");
				munpause(peer);
				continue;
			};
		}
		else
			exit(0);
	}
}

int custom_peer_init(struct peerd *peer, int argc, char *argv[])
{
	int i;
	struct monitor_io *mio;
	struct monitord *monitor;

	monitor = malloc(sizeof(struct monitord));
	if (!monitor)
		return -1;
	peer->priv = monitor;
	monitor->mon_portno = NoPort;
	
	
	for (i = 0; i < peer->nr_ops; i++) {
		mio = malloc(sizeof(struct monitor_io));
		if (!mio)
			return -1;
		peer->peer_reqs[i].priv = mio;
		mio->src_portno = NoPort;
	}
	
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-mp") && (i + 1 < argc)) {
			monitor->mon_portno = atoi(argv[i+1]);
			i+=1;
			continue;
		}
	}
	main_peer = peer;

	peer->interactive_func = main_loop;

	return 0;
}

void custom_peer_finalize(struct peerd *peer)
{
	return;
}
