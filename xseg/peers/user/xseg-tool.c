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

int help(void)
{
	printf("xseg <spec> [[[<src_port>]:[<dst_port>]] [<command> <arg>*] ]*\n"
		"spec:\n"
		"    <type:name:nr_ports:nr_requests:request_size:extra_size:page_shift>\n"
		"global commands:\n"
		"    reportall\n"
		"    create\n"
		"    destroy\n"
		"    bind <portno>\n"
		"    signal <portno>\n"
		"    bridge <portno1> <portno2> <logfile> {full|summary|stats}\n"
		"port commands:\n"
		"    report\n"
		"    alloc_requests (to source) <nr>\n"
		"    free_requests (from source) <nr>\n"
		"    put_requests (all from dest)\n"
		"    put_replies (all from dest)\n"
		"    wait     <nr_replies>\n"
		"    complete <nr_requests>\n"
		"    fail     <nr_requests>\n"
		"    rndwrite <nr_loops> <seed> <namesize> <datasize> <objectsize>\n"
		"    rndread  <nr_loops> <seed> <namesize> <datasize> <objectsize>\n"
		"    info     <name>\n"
		"    read     <name> <offset> <size>\n"
		"    write    <name> <offset> < data\n"
		"    truncate <name> <size>\n"
		"    delete   <name>\n"
		"    acquire  <name>\n"
		"    release  <name>\n"
		"    copy     <src>  <dst>\n"
		"    clone    <src>  <dst>\n"
	);
	return 1;
}

char *namebuf;
char *chunk;
struct xseg_config cfg;
struct xseg *xseg;
uint32_t srcport, dstport;


#define mkname mkname_heavy
/* heavy distributes duplicates much more widely than light
 * ./xseg-tool random 100000 | cut -d' ' -f2- | sort | uniq -d -c |wc -l
 */

void mkname_heavy(char *name, uint32_t namesize, uint32_t seed)
{
	int i;
	char c;
	for (i = 0; i < namesize; i += 1) {
		c = seed + (seed >> 8) + (seed >> 16) + (seed >> 24);
		c = '0' + ((c + (c >> 4)) & 0xf);
		if (c > '9')
			c += 'a'-'0'-10;
		name[i] = c;
		seed *= ((seed % 137911) | 1) * 137911;
	}
}

void mkname_light(char *name, uint32_t namesize, uint32_t seed)
{
	int i;
	char c;
	for (i = 0; i < namesize; i += 1) {
		c = seed;
		name[i] = 'A' + (c & 0xf);
		seed += 1;
	}
}

uint64_t pick(uint64_t size)
{
	return (uint64_t)((double)(RAND_MAX) / random());
}

void mkchunk(	char *chunk, uint32_t datasize,
		char *name, uint32_t namesize, uint64_t offset)
{
	long i, r, bufsize = namesize + 16;
	char buf[bufsize];
	r = datasize % bufsize;
	snprintf(buf, bufsize, "%016llx%s", (unsigned long long)offset, name);

	for (i = 0; i <= (long)datasize - bufsize; i += bufsize)
		memcpy(chunk + i, buf, bufsize);

	memcpy(chunk + datasize - r, buf, r);
}

int chkchunk(	char *chunk, uint32_t datasize,
		char *name, uint32_t namesize, uint64_t offset)
{
	long i, r;
	int bufsize = namesize + 16;
	char buf[bufsize];
	r = datasize % namesize;
	snprintf(buf, bufsize, "%016llx%s", (unsigned long long)offset, name);

	for (i = 0; i <= (long)datasize - bufsize; i += bufsize)
		if (memcmp(chunk + i, buf, bufsize)) {
			/*printf("mismatch: '%*s'* vs '%*s'\n",
				bufsize, buf, datasize, chunk);
			*/
			return 0;
		}

	if (memcmp(chunk + datasize - r, buf, r))
		return 0;

	return 1;
}


#define ALLOC_MIN 4096
#define ALLOC_MAX 1048576

void inputbuf(FILE *fp, char **retbuf, uint64_t *retsize)
{
	static uint64_t alloc_size;
	static char *buf;
	uint64_t size = 0;
	char *p;
	size_t r;

	if (alloc_size < ALLOC_MIN)
		alloc_size = ALLOC_MIN;

	if (alloc_size > ALLOC_MAX)
		alloc_size = ALLOC_MAX;

	p = realloc(buf, alloc_size);
	if (!p) {
		if (buf)
			free(buf);
		buf = NULL;
		goto out;
	}

	buf = p;

	while (!feof(fp)) {
		r = fread(buf + size, 1, alloc_size - size, fp);
		if (!r)
			break;
		size += r;
		if (size >= alloc_size) {
			p = realloc(buf, alloc_size * 2);
			if (!p) {
				if (buf)
					free(buf);
				buf = NULL;
				size = 0;
				goto out;
			}
			buf = p;
			alloc_size *= 2;
		}
	}

out:
	*retbuf = buf;
	*retsize = size;
}

void report_request(struct xseg_request *req)
{
	uint32_t max = req->datasize;
	if (max > 128)
		max = 128;
	req->data[max-1] = 0;
	fprintf(stderr, "request %llu state %u\n", (unsigned long long)req->serial, req->state);
	fprintf(stderr, "data: %s\n", req->data);
}

int cmd_info(char *name)
{
	uint32_t namesize = strlen(name);
	size_t size = sizeof(uint64_t);
	int r;
	xserial srl;
	struct xseg_request *req;

	req = xseg_get_request(xseg, srcport);
	if (!req) {
		fprintf(stderr, "No request!\n");
		return -1;
	}

	r = xseg_prep_request(req, namesize, size);
	if (r < 0) {
		fprintf(stderr, "Cannot prepare request! (%lu, %lu)\n",
			(unsigned long) namesize, (unsigned long) size);
		xseg_put_request(xseg, srcport, req);
		return -1;
	}

	strncpy(req->name, name, namesize);
	req->offset = 0;
	req->size = size;
	req->op = X_INFO;

	srl = xseg_submit(xseg, dstport, req);
	if (srl == None)
		return -1;

	xseg_signal(xseg, dstport);

	return 0;
}

int cmd_read(char *name, uint64_t offset, uint64_t size)
{
	uint32_t namesize = strlen(name);
	int r;
	xserial srl;
	struct xseg_request *req = xseg_get_request(xseg, srcport);
	if (!req) {
		fprintf(stderr, "No request\n");
		return -1;
	}

	r = xseg_prep_request(req, namesize, size);
	if (r < 0) {
		fprintf(stderr, "Cannot prepare request! (%lu, %llu)\n",
			(unsigned long)namesize, (unsigned long long)size);
		xseg_put_request(xseg, srcport, req);
		return -1;
	}

	strncpy(req->name, name, namesize);
	req->offset = offset;
	req->size = size;
	req->op = X_READ;

	srl = xseg_submit(xseg, dstport, req);
	if (srl == None)
		return -1;

	xseg_signal(xseg, dstport);
	return 0;
}

int cmd_write(char *name, uint64_t offset)
{
	char *buf = NULL;
	int r;
	xserial srl;
	uint64_t size = 0;
	uint32_t namesize = strlen(name);
	struct xseg_request *req;

	inputbuf(stdin, &buf, &size);
	if (!size) {
		fprintf(stderr, "No input\n");
		return -1;
	}

	req = xseg_get_request(xseg, srcport);
	if (!req) {
		fprintf(stderr, "No request\n");
		return -1;
	}

	r = xseg_prep_request(req, namesize, size);
	if (r < 0) {
		fprintf(stderr, "Cannot prepare request! (%lu, %llu)\n",
			(unsigned long)namesize, (unsigned long long)size);
		xseg_put_request(xseg, srcport, req);
		return -1;
	}

	strncpy(req->name, name, namesize);
	memcpy(req->buffer, buf, size);
	req->offset = offset;
	req->size = size;
	req->op = X_WRITE;

	srl = xseg_submit(xseg, dstport, req);
	if (srl == None) {
		fprintf(stderr, "Cannot submit\n");
		return -1;
	}

	return 0;
}

int cmd_truncate(char *name, uint64_t offset)
{
	return 0;
}

int cmd_delete(char *name)
{
	return 0;
}

int cmd_acquire(char *name)
{
	return 0;
}

int cmd_release(char *name)
{
	return 0;
}

int cmd_copy(char *src, char *dst)
{
	return 0;
}

int cmd_clone(char *src, char *dst)
{
	return 0;
}

void log_req(	uint32_t portno2, uint32_t portno1, int op, int method,
		struct xseg_request *req)
{
	return;
}

#define LOG_ACCEPT  0
#define LOG_RECEIVE 1

int cmd_bridge(uint32_t portno1, uint32_t portno2, char *logfile, char *how)
{
	struct xseg_request *req;
	int logfd, method;
	if (!strcmp(logfile, "-"))
		logfd = 1;
	else {
		logfd = open(logfile, O_WRONLY|O_APPEND|O_CREAT, 0600);
		if (logfd < 0) {
			perror(logfile);
			return -1;
		}
	}

	if (!strcmp(how, "full"))
		method = 0;
	else if (!strcmp(how, "full"))
		method = 1;
	else
		method = 2;

	for (;;) {
		int reloop = 0, active;
		xseg_prepare_wait(xseg, portno1);
		xseg_prepare_wait(xseg, portno2);
		req = NULL;

		for (;;) {
			active = 0;

			req = xseg_accept(xseg, portno1);
			if (req) {
				xseg_submit(xseg, portno2, req);
				log_req(portno1, portno2, LOG_ACCEPT, method, req);
				active += 1;
			}

			req = xseg_accept(xseg, portno2);
			if (req) {
				xseg_submit(xseg, portno1, req);
				log_req(portno2, portno1, LOG_ACCEPT, method, req);
				active += 1;
			}

			req = xseg_receive(xseg, portno1);
			if (req) {
				xseg_respond(xseg, portno2, req);
				log_req(portno1, portno2, LOG_RECEIVE, method, req);
				active += 1;
			}

			req = xseg_receive(xseg, portno2);
			if (req) {
				xseg_respond(xseg, portno1, req);
				log_req(portno2, portno1, LOG_RECEIVE, method, req);
				active += 1;
			}

			if (active == 0) {
				if (reloop)
					break;
				/* wait on multiple queues? */
				xseg_wait_signal(xseg, 100000);
				break;
			} else {
				xseg_cancel_wait(xseg, portno1);	
				xseg_cancel_wait(xseg, portno2);	
				reloop = 1;
			}
		}
	}

	return 0;
}

int cmd_rndwrite(long loops, int32_t seed, uint32_t namesize, uint32_t chunksize, uint64_t size)
{
	if (loops < 0)
		return help();

	if (namesize >= chunksize) {
		fprintf(stderr, "namesize >= chunksize\n");
		return -1;
	}

	char *p = realloc(namebuf, namesize+1);
	if (!p) {
		fprintf(stderr, "Cannot allocate memory\n");
		return -1;
	}
	namebuf = p;

	p = realloc(chunk, chunksize);
	if (!p) {
		fprintf(stderr, "Cannot allocate memory\n");
		return -1;
	}
	chunk = p;
	memset(chunk, 0, chunksize);

	srandom(seed);

	struct xseg_request *submitted = NULL, *received;
	long nr_submitted = 0, nr_received = 0, nr_failed = 0;
	int reported = 0, r;
	uint64_t offset;
	xserial srl;

	for (;;) {
		xseg_prepare_wait(xseg, srcport);
		if (nr_submitted < loops &&
		    (submitted = xseg_get_request(xseg, srcport))) {
			xseg_cancel_wait(xseg, srcport);
			r = xseg_prep_request(submitted, namesize, chunksize);
			if (r < 0) {
				fprintf(stderr, "Cannot prepare request! (%u, %u)\n",
					namesize, chunksize);
				xseg_put_request(xseg, submitted->portno, submitted);
				return -1;
			}

			nr_submitted += 1;
			reported = 0;
			seed = random();
			mkname(namebuf, namesize, seed);
			namebuf[namesize] = 0;
			//printf("%ld: %s\n", nr_submitted, namebuf);
			strncpy(submitted->name, namebuf, namesize);
			offset = 0;// pick(size);
			mkchunk(submitted->buffer, chunksize, namebuf, namesize, offset);

			submitted->offset = offset;
			submitted->size = chunksize;
			submitted->op = X_WRITE;
			submitted->flags |= XF_NOSYNC;

			srl = xseg_submit(xseg, dstport, submitted);
			(void)srl;
			xseg_signal(xseg, dstport);
		}

		received = xseg_receive(xseg, srcport);
		if (received) {
			xseg_cancel_wait(xseg, srcport);
			nr_received += 1;
			if (!(received->state & XS_SERVED)) {
				nr_failed += 1;
				report_request(received);
			}
			if (xseg_put_request(xseg, received->portno, received))
				fprintf(stderr, "Cannot put request at port %u\n", received->portno);
		}

		if (!submitted && !received)
			xseg_wait_signal(xseg, 1000000);

			if (nr_submitted % 1000 == 0 && !reported) {
				reported = 1;
				fprintf(stderr, "submitted %ld, received %ld, failed %ld\n",
					nr_submitted, nr_received, nr_failed);
			}

			if (nr_received >= loops)
				break;
	}

	fprintf(stderr, "submitted %ld, received %ld, failed %ld\n",
		nr_submitted, nr_received, nr_failed);
	return 0;
}

/* note:
 * prepare/wait rhythm,
 * files are converted to independent chunk access patterns,
*/

int cmd_rndread(long loops, int32_t seed, uint32_t namesize, uint32_t chunksize, uint64_t size)
{
	if (loops < 0)
		return help();

	if (namesize >= chunksize) {
		fprintf(stderr, "namesize >= chunksize\n");
		return -1;
	}

	char *p = realloc(namebuf, namesize+1);
	if (!p) {
		fprintf(stderr, "Cannot allocate memory\n");
		return -1;
	}
	namebuf = p;

	p = realloc(chunk, chunksize);
	if (!p) {
		fprintf(stderr, "Cannot allocate memory\n");
		return -1;
	}
	chunk = p;
	memset(chunk, 0, chunksize);

	srandom(seed);

	struct xseg_request *submitted = NULL, *received;
	long nr_submitted = 0, nr_received = 0, nr_failed = 0, nr_mismatch = 0;
	int reported = 0, r;
	uint64_t offset;
	xserial srl;

	for (;;) {
		submitted = NULL;
		xseg_prepare_wait(xseg, srcport);
		if (nr_submitted < loops &&
		    (submitted = xseg_get_request(xseg, srcport))) {
			xseg_cancel_wait(xseg, srcport);
			r = xseg_prep_request(submitted, namesize, chunksize);
			if (r < 0) {
				fprintf(stderr, "Cannot prepare request! (%u, %u)\n",
					namesize, chunksize);
				xseg_put_request(xseg, submitted->portno, submitted);
				return -1;
			}

			nr_submitted += 1;
			reported = 0;
			seed = random();
			mkname(namebuf, namesize, seed);
			namebuf[namesize] = 0;
			//printf("%ld: %s\n", nr_submitted, namebuf);
			offset = 0;//pick(size);

			strncpy(submitted->name, namebuf, namesize);
			submitted->offset = offset;
			submitted->size = chunksize;
			submitted->op = X_READ;

			srl = xseg_submit(xseg, dstport, submitted);
			(void)srl;
			xseg_signal(xseg, dstport);
		}

		received = xseg_receive(xseg, srcport);
		if (received) {
			xseg_cancel_wait(xseg, srcport);
			nr_received += 1;
			if (!(received->state & XS_SERVED)) {
				nr_failed += 1;
				report_request(received);
			} else if (!chkchunk(received->data, received->datasize,
					received->name, received->namesize, received->offset)) {
				nr_mismatch += 1;
			}

			if (xseg_put_request(xseg, received->portno, received))
				fprintf(stderr, "Cannot put request at port %u\n", received->portno);
		}

		if (!submitted && !received)
			xseg_wait_signal(xseg, 1000000);

		if (nr_submitted % 1000 == 0 && !reported) {
			reported = 1;
			fprintf(stderr, "submitted %ld, received %ld, failed %ld, mismatched %ld\n",
			nr_submitted, nr_received, nr_failed, nr_mismatch);
		}

		if (nr_received >= loops)
			break;
	}

	fprintf(stderr, "submitted %ld, received %ld, failed %ld, mismatched %ld\n",
		nr_submitted, nr_received, nr_failed, nr_mismatch);
	return 0;
}

int cmd_report(uint32_t port)
{
	struct xq *fq, *rq, *pq;
	fq = &xseg->ports[port].free_queue;
	rq = &xseg->ports[port].request_queue;
	pq = &xseg->ports[port].reply_queue;
	fprintf(stderr, "port %u:\n"
		"       free_queue [%p] count : %u\n"
		"    request_queue [%p] count : %u\n"
		"      reply_queue [%p] count : %u\n",
		port,
		(void *)fq, xq_count(fq),
		(void *)rq, xq_count(rq),
		(void *)pq, xq_count(pq));
	return 0;
}

int cmd_join(void)
{
	if (xseg)
		return 0;

	xseg = xseg_join(cfg.type, cfg.name, "posix", NULL);
	if (!xseg) {
		fprintf(stderr, "cannot join segment!\n");
		return -1;
	}
	return 0;
}

int cmd_reportall(void)
{
	uint32_t t;

	if (cmd_join())
		return -1;

	fprintf(stderr, "global free requests: %u\n", xq_count(xseg->free_requests));
	for (t = 0; t < xseg->config.nr_ports; t++)
		cmd_report(t);

	return 0;
}

int cmd_create(void)
{
	int r = xseg_create(&cfg);
	if (r) {
		fprintf(stderr, "cannot create segment!\n");
		return -1;
	}

	fprintf(stderr, "Segment initialized.\n");
	return 0;
}

int cmd_destroy(void)
{
	if (!xseg && cmd_join())
		return -1;
	xseg_leave(xseg);
	xseg_destroy(xseg);
	xseg = NULL;
	fprintf(stderr, "Segment destroyed.\n");
	return 0;
}

int cmd_alloc_requests(unsigned long nr)
{
	return xseg_alloc_requests(xseg, srcport, nr);
}

int cmd_free_requests(unsigned long nr)
{
	return xseg_free_requests(xseg, srcport, nr);
}

int cmd_put_requests(void)
{
	struct xseg_request *req;

	for (;;) {
		req = xseg_accept(xseg, dstport);
		if (!req)
			break;
		if (xseg_put_request(xseg, req->portno, req))
			fprintf(stderr, "Cannot put request at port %u\n", req->portno);
	}

	return 0;
}

int cmd_finish(unsigned long nr, int fail)
{
	struct xseg_request *req;

	for (; nr--;) {
		req = xseg_accept(xseg, srcport);
		if (!req)
			break;
		if (fail)
			req->state &= ~XS_SERVED;
		else
			req->state |= XS_SERVED;
		xseg_respond(xseg, dstport, req);
		xseg_signal(xseg, dstport);
	}

	return 0;
}

void handle_reply(struct xseg_request *req)
{
	if (!(req->state & XS_SERVED)) {
		report_request(req);
		goto put;
	}

	switch (req->op) {
	case X_READ:
		fwrite(req->data, 1, req->datasize, stdout);
		break;

	case X_WRITE:
	case X_SYNC:
	case X_DELETE:
	case X_TRUNCATE:
	case X_COMMIT:
	case X_CLONE:
	case X_INFO:
		fprintf(stderr, "size: %llu\n", (unsigned long long)*((uint64_t *)req->data));
		break;

	default:
		break;
	}

put:
	if (xseg_put_request(xseg, req->portno, req))
		fprintf(stderr, "Cannot put reply at port %u\n", req->portno);
}

int cmd_wait(uint32_t nr)
{
	struct xseg_request *req;
	long ret;

	for (;;) {
		req = xseg_receive(xseg, srcport);
		if (req) {
			handle_reply(req);
			nr--;
			if (nr == 0)
				break;
			continue;
		}

		ret = xseg_prepare_wait(xseg, srcport);
		if (ret)
			return -1;

		ret = xseg_wait_signal(xseg, 1000000);
		ret = xseg_cancel_wait(xseg, srcport);
		if (ret)
			return -1;
	}

	return 0;
}

int cmd_put_replies(void)
{
	struct xseg_request *req;

	for (;;) {
		req = xseg_receive(xseg, dstport);
		if (!req)
			break;
		fprintf(stderr, "request: %08llx%08llx\n"
			"     op: %u\n"
			"  state: %u\n",
			0LL, (unsigned long long)req->serial,
			req->op,
			req->state);
		report_request(req);

		//fwrite(req->buffer, 1, req->buffersize, stdout);

		if (xseg_put_request(xseg, req->portno, req))
			fprintf(stderr, "Cannot put reply\n");
	}

	return 0;
}

int cmd_bind(long portno)
{
	struct xseg_port *port = xseg_bind_port(xseg, portno);
	if (!port) {
		fprintf(stderr, "failed to bind port %ld\n", portno);
		return 1;
	}

	fprintf(stderr, "bound port %u\n", xseg_portno(xseg, port));
	return 0;
}

int cmd_signal(uint32_t portno)
{
	return xseg_signal(xseg, portno);
}

int parse_ports(char *str)
{
	int ret = 0;
	char *s = str;

	for (;;) {
		if (*s == 0)
			return 0;

		if (*s == ':') {
			*s = 0;
			if ((s > str) && isdigit(str[0])) {
				srcport = atol(str);
				ret ++;
			}
			break;
		}
		s ++;
	}

	s += 1;
	str = s;

	for (;;) {
		if (*s == 0) {
			if ((s > str) && isdigit(str[0])) {
				dstport = atol(str);
				ret ++;
			}
			break;
		}
		s ++;
	}

	return ret;
}

int main(int argc, char **argv)
{
	int i, ret = 0;
	char *spec;

	if (argc < 3)
		return help();

	srcport = -1;
	dstport = -1;
	spec = argv[1];

	if (xseg_parse_spec(spec, &cfg)) {
		fprintf(stderr, "Cannot parse spec\n");
		return -1;
	}

	if (xseg_initialize()) {
		fprintf(stderr, "cannot initialize!\n");
		return -1;
	}

	for (i = 2; i < argc; i++) {

		if (!strcmp(argv[i], "create")) {
			ret = cmd_create();
			continue;
		}

		if (!strcmp(argv[i], "join")) {
			ret = cmd_join();
			if (!ret)
				fprintf(stderr, "Segment joined.\n");
			continue;
		}

		if (!strcmp(argv[i], "destroy")) {
			ret = cmd_destroy();
			continue;
		}

		if (cmd_join())
			return -1;

		if (!strcmp(argv[i], "reportall")) {
			ret = cmd_reportall();
			continue;
		}

		if (!strcmp(argv[i], "bind") && (i + 1 < argc)) {
			ret = cmd_bind(atol(argv[i+1]));
			i += 1;
			continue;
		}

		if (!strcmp(argv[i], "signal") && (i + 1 < argc)) {
			ret = cmd_signal(atol(argv[i+1]));
			i += 1;
			continue;
		}

		if (!strcmp(argv[i], "bridge") && (i + 4 < argc)) {
			ret = cmd_bridge(atol(argv[i+1]),
					 atol(argv[i+2]),
					 argv[i+3],
					 argv[i+4]);
			i += 4;
			continue;
		}

		if (srcport == -1) {
			if (!parse_ports(argv[i]))
				fprintf(stderr, "source port undefined: %s\n", argv[i]);
			continue;
		}

		if (dstport == -1) {
			if (!parse_ports(argv[i]))
				fprintf(stderr, "destination port undefined: %s\n", argv[i]);
			continue;
		}

		if (!strcmp(argv[i], "report")) {
			ret = cmd_report(dstport);
			continue;
		}

		if (!strcmp(argv[i], "alloc_requests") && (i + 1 < argc)) {
			ret = cmd_alloc_requests(atol(argv[i+1]));
			i += 1;
			continue;
		}

		if (!strcmp(argv[i], "free_requests") && (i + 1 < argc)) {
			ret = cmd_free_requests(atol(argv[i+1]));
			i += 1;
			continue;
		}

		if (!strcmp(argv[i], "put_requests")) {
			ret = cmd_put_requests();
			continue;
		}

		if (!strcmp(argv[i], "put_replies")) {
			ret = cmd_put_replies();
			continue;
		}

		if (!strcmp(argv[i], "complete") && (i + 1 < argc)) {
			ret = cmd_finish(atol(argv[i+1]), 0);
			i += 1;
			continue;
		}

		if (!strcmp(argv[i], "fail") && (i + 1 < argc)) {
			ret = cmd_finish(atol(argv[i+1]), 1);
			i += 1;
			continue;
		}

		if (!strcmp(argv[i], "wait") && (i + 1 < argc)) {
			ret = cmd_wait(atol(argv[i+1]));
			i += 1;
			continue;
		}

		if (!strcmp(argv[i], "rndwrite") && (i + 5 < argc)) {
			long nr_loops = atol(argv[i+1]);
			unsigned int seed = atoi(argv[i+2]);
			unsigned int namesize = atoi(argv[i+3]);
			unsigned int chunksize = atoi(argv[i+4]);
			unsigned long objectsize = atol(argv[i+5]);
			ret = cmd_rndwrite(nr_loops, seed, namesize, chunksize, objectsize);
			i += 5;
			continue;
		}

		if (!strcmp(argv[i], "rndread") && (i + 5 < argc)) {
			long nr_loops = atol(argv[i+1]);
			unsigned int seed = atoi(argv[i+2]);
			unsigned int namesize = atoi(argv[i+3]);
			unsigned int chunksize = atoi(argv[i+4]);
			unsigned long objectsize = atol(argv[i+5]);
			ret = cmd_rndread(nr_loops, seed, namesize, chunksize, objectsize);
			i += 5;
			continue;
		}

		if (!strcmp(argv[i], "read") && (i + 3 < argc)) {
			char *name = argv[i+1];
			uint64_t offset = atol(argv[i+2]);
			uint64_t size   = atol(argv[i+3]);
			ret = cmd_read(name, offset, size);
			i += 3;
			continue;
		}

		if (!strcmp(argv[i], "write") && (i + 2 < argc)) {
			char *name = argv[i+1];
			uint64_t offset = atol(argv[i+2]);
			ret = cmd_write(name, offset);
			i += 2;
			continue;
		}

		if (!strcmp(argv[i], "truncate") && (i + 2 < argc)) {
			char *name = argv[i+1];
			uint64_t offset = atol(argv[i+2]);
			ret = cmd_truncate(name, offset);
			i += 2;
			continue;
		}

		if (!strcmp(argv[i], "delete") && (i + 1 < argc)) {
			char *name = argv[i+1];
			ret = cmd_delete(name);
			i += 1;
			continue;
		}

		if (!strcmp(argv[i], "acquire") && (i + 1 < argc)) {
			char *name = argv[i+1];
			ret = cmd_acquire(name);
			i += 1;
			continue;
		}

		if (!strcmp(argv[i], "release") && (i + 1 < argc)) {
			char *name = argv[i+1];
			ret = cmd_release(name);
			i += 1;
			continue;
		}

		if (!strcmp(argv[i], "copy") && (i + 2) < argc) {
			char *src = argv[i+1];
			char *dst = argv[i+2];
			ret = cmd_copy(src, dst);
			i += 2;
			continue;
		}

		if (!strcmp(argv[i], "clone") && (i + 2 < argc)) {
			char *src = argv[i+1];
			char *dst = argv[i+2];
			ret = cmd_clone(src, dst);
			i += 2;
			continue;
		}

		if (!strcmp(argv[i], "info") && (i + 1 < argc)) {
			char *name = argv[i+1];
			ret = cmd_info(name);
			i += 1;
			continue;
		}


		if (!parse_ports(argv[i]))
			fprintf(stderr, "invalid argument: %s\n", argv[i]);
	}

	/* xseg_leave(); */
	return ret;
}
