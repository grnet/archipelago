#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#include <xseg/xseg.h>
#include <xseg/protocol.h>

#define MAX_ARG_LEN 255
int safe_strlen(char *s)
{
	int i;
	if (!s)
		return -1;

	for (i = 0; i < MAX_ARG_LEN; i++) {
		if (!*s) 
			return i;
		s++;
	}
	return -1;
}

int validate_alphanumeric(char *s)
{
	int i;
	int len = safe_strlen(s);
	if (len <= 0){
		return 0;
	}

	for (i = 0; i < len; i++) {
		if (!isalnum(*s)&&*s!='-'&&*s!='.')
			return 0;
		s++;
	}
	return 1;
}

int validate_numeric(char *s)
{
	int i;
	int len = safe_strlen(s);
	if (len <= 0)
		return 0;

	for (i = 0; i < len; i++) {
		if (!isdigit(*s))
			return 0;
		s++;
	}
	return 1;
}

char *spec = "segdev:xsegbd:16:1024:12";
struct xseg *xseg;
struct xseg_config cfg;
xport srcport = NoPort;
xport sport = NoPort;
struct xseg_port *port;
xport mportno;

static void init_local_signal() 
{
	if (xseg && sport != srcport){
		xseg_init_local_signal(xseg, srcport);
		sport = srcport;
	}
}

int wait_reply(struct xseg_request *expected_req)
{
	struct xseg_request *rec;
	xseg_prepare_wait(xseg, srcport);
	while(1) {
		rec = xseg_receive(xseg, srcport, 0);
		if (rec) {
			if (rec != expected_req) {
				fprintf(stderr, "Unknown received req. Putting req.\n");
				xseg_put_request(xseg, rec, srcport);
			} else	if (!(rec->state & XS_SERVED)) {
				fprintf(stderr, "Failed req\n");
				return -1;
			} else {
				break;
			}
		}
		xseg_wait_signal(xseg, 1000000UL);
	}
	xseg_cancel_wait(xseg, srcport);

	return 0;
}

int vlmc_create(char *name, uint64_t size, char *snap)
{
	int ret;
	int targetlen = safe_strlen(name);
	int snaplen = safe_strlen(snap);
	if (targetlen <= 0) {
		fprintf(stderr, "Invalid name\n");
		return -1;
	}
	if (snaplen <= 0 && size == -1) {
		fprintf(stderr, "Size or snap must be provided in create\n");
		return -1;
	}
	XSEGLOG("Name: %s", name);
	XSEGLOG("Snap: %s", snap);

	struct xseg_request *req = xseg_get_request(xseg, srcport, mportno, X_ALLOC);
	if (!req) {
		fprintf(stderr, "Couldn't allocate xseg request\n");
		return -1;
	}
	int r = xseg_prep_request(xseg, req, targetlen, sizeof(struct xseg_request_clone));
	if (r < 0){
		fprintf(stderr, "Couldn't prep xseg request\n");
		xseg_put_request(xseg, req, srcport);
		return -1;
	}
	//FIXME what to do if no snap ? how do i send mapper to create a non copy up volume?
	char *target = xseg_get_target(xseg, req);
	strncpy(target, name, targetlen);
	struct xseg_request_clone *xclone = (struct xseg_request_clone *) xseg_get_data(xseg, req);
	if (snaplen <= 0){
		memset(xclone->target, 0, XSEG_MAX_TARGETLEN);
		xclone->targetlen = 0;
	}
	else {
		strncpy(xclone->target, snap, snaplen);
		xclone->targetlen = snaplen;
	}
	xclone->size = size;
	req->offset = 0;
	req->size = req->datalen;
	req->op = X_CLONE;

	xport p = xseg_submit(xseg, req, srcport, X_ALLOC);
	if (p == NoPort){
		fprintf(stderr, "couldn't submit req\n");
		xseg_put_request(xseg, req, srcport);
		return -1;
	}
	xseg_signal(xseg, p);

	ret = wait_reply(req);
	
	xseg_put_request(xseg, req, srcport);

	return ret;
}

int vlmc_snapshot(char *name)
{
	return -1;
}

int vlmc_remove(char *name)
{
	int targetlen = safe_strlen(name);
	if (targetlen <= 0) {
		fprintf(stderr, "Invalid name\n");
		return -1;
	}

	struct xseg_request *req = xseg_get_request(xseg, srcport, mportno, X_ALLOC);
	if (!req) {
		fprintf(stderr, "Couldn't allocate xseg request\n");
		return -1;
	}
	int r = xseg_prep_request(xseg, req, targetlen, 0);
	if (r < 0){
		fprintf(stderr, "Couldn't prep xseg request\n");
		xseg_put_request(xseg, req, srcport);
		return -1;
	}
	char *target = xseg_get_target(xseg, req);
	strncpy(target, name, targetlen);
	req->offset = 0;
	req->size = req->datalen;
	req->op = X_DELETE;
	
	xport p = xseg_submit(xseg, req, srcport, X_ALLOC);
	if (p == NoPort){
		fprintf(stderr, "couldn't submit req\n");
		xseg_put_request(xseg, req, srcport);
		return -1;
	}
	xseg_signal(xseg, p);
	
	wait_reply(req);
	
	xseg_put_request(xseg, req, srcport);

	return 0;
}

int vlmc_resize(char *name, uint64_t size)
{
	return 0;
}

int vlmc_map(char *name)
{
	/*
	char cmd[1024];
	char buf[1024];
	int fd;
	xport p;


	for (p = 2; p < cfg.nr_ports; p++) {
		sprintf(buf, "%sdevices/%u/srcport", XSEGBD_SYSFS, p);
		fd = open(buf, O_RDONLY);
		if (fd < 0 && errno == ENOENT)
			break;
	}
	if (p == cfg.nr_ports){
		fprintf(stderr, "No available port\n");
		return -1;
	}

	sprintf(cmd, "%s %u:%u:%u", name, p, VPORT, REQS);	
	sprintf(buf, "%sadd", XSEGBD_SYSFS);
	fd = open(add, O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "Cannot open sysfs add\n");
		return -1;
	}
	r = write(fd, cmd, strlen(cmd));
	if (r < 0){
		fprintf(stderr, "write error\n");
		return -1;
	}
	*/

	return 0;
}

int vlmc_unmap(char *name)
{
	return 0;
}

int vlmc_list()
{
	return 0;
}

#define err_in_arg(__i, __arg) do {					\
	fprintf(stderr, "Error in argument %d (%s)\n", __i, __arg);	\
	exit(-1);							\
	} while(0)

int main(int argc, char *argv[])
{
	int i;
	if (argc < 6){
		fprintf(stderr, "insufficient arguments\n");
		return -1;
	}

	spec = argv[1];
	if (xseg_parse_spec(spec, &cfg)) {
		fprintf(stderr, "Cannot parse spec\n");
		return -1;
	}

	if (xseg_initialize()) {
		fprintf(stderr, "cannot initialize!\n");
		return -1;
	}

	xseg = xseg_join(cfg.type, cfg.name, "posix", NULL);
	if (!xseg) {
		fprintf(stderr, "cannot join segment!\n");
		return -1;
	}
	init_local_signal();

	char *name = NULL;
	char *snap = NULL;
	uint64_t size = -1;
	//char *pool = NULL;
	char *config = NULL;

	for (i = 3; i < argc; i++) {
		if ((!strcmp(argv[i], "-s") || !strcmp(argv[i], "--size")) && i+1 < argc){
			if (!validate_numeric(argv[i+1])){
				err_in_arg(i, argv[i]);
			} else {
				size = atol(argv[i+1]);
				i++;
			}
		}else if ((!strcmp(argv[i], "-c") || !strcmp(argv[i], "--config")) && i+1 < argc){
			if (!validate_alphanumeric(argv[i+1])){
				err_in_arg(i, argv[i]);
			} else {
				config = argv[i+1];
				i++;
			}
		} else if (!strcmp(argv[i], "--snap") && i+1 < argc){
			if (!validate_alphanumeric(argv[i+1])){
				err_in_arg(i, argv[i]);
			} else {
				snap = argv[i+1];
				i++;
			}
		} else if (!strcmp(argv[i], "-mp") && i+1 < argc){
			if (!validate_numeric(argv[i+1])){
				err_in_arg(i, argv[i]);
			} else {
				mportno = atol(argv[i+1]);
				i++;
			}
		} else if (!strcmp(argv[i], "-p") && i+1 < argc){
			if (!validate_alphanumeric(argv[i+1])){
				err_in_arg(i, argv[i]);
			} else {
				srcport = atol(argv[i+1]);
				i++;
			}
		} else if (!strcmp(argv[i], "--name") && i+1 < argc){
			if (!validate_alphanumeric(argv[i+1])){
				err_in_arg(i, argv[i]);
			} else {
				name = argv[i+1];
				i++;
			}
		} else {
			err_in_arg(i, argv[i]);
		}
	}

	if (srcport > cfg.nr_ports || mportno > cfg.nr_ports) {
		fprintf(stderr, "Invalid port\n");
		return -1;
	}

	port = xseg_bind_port(xseg, srcport, NULL);
	if (!port) {
		fprintf(stderr, "Error binding port %u\n", srcport);
		exit(-1);
	}

	int ret = -1;

	if (!strcmp(argv[2], "create")) 
		ret = vlmc_create(name, size, snap);
	else if (!strcmp(argv[2], "remove"))
		ret = vlmc_remove(name);
/*
	else if (!strcmp(argv[2], "map"))
		ret = vlmc_map(name);
	else if (!strcmp(argv[2], "unmap"))
		ret = vlmc_unmap(name);
	else if (!strcmp(argv[2], "showmapped"))
		ret = vlmc_showmapped();
	else if (!strcmp(argv[2], "list") || !(strcmp(argv[2], "ls"))
		ret = vlmc_list();
*/
	else if (!strcmp(argv[2], "resize"))
		ret = vlmc_resize(name, size);
	else
		fprintf(stderr, "unknown action (%s)\n", argv[2]);

	return ret;
}

