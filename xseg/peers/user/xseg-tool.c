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
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#include <xtypes/xhash.h>
#include <xtypes/xobj.h>
#include <xseg/xseg.h>
#include <xseg/protocol.h>
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
		"    wait        <nr_replies>\n"
		"    complete    <nr_requests>\n"
		"    fail        <nr_requests>\n"
		"    rndwrite    <nr_loops> <seed> <targetlen> <datalen> <objectsize>\n"
		"    rndread     <nr_loops> <seed> <targetlen> <datalen> <objectsize>\n"
		"    submit_reqs <nr_loops> <concurrent_reqs>\n"
		"    info        <target>\n"
		"    read        <target> <offset> <size>\n"
		"    write       <target> <offset> < data\n"
		"    truncate    <target> <size>\n"
		"    delete      <target>\n"
		"    acquire     <target>\n"
		"    release     <target>\n"
		"    copy        <src>  <dst>\n"
		"    clone       <src>  <dst>\n"
	);
	return 1;
}


enum req_action {
	REPORT = 1,
	FAIL = 2,
	COMPLETE = 3
};

enum queue {
	FREE_QUEUE = 0,
	REQUEST_QUEUE = 1,
	REPLY_QUEUE = 2
};

char *namebuf;
char *chunk;
struct xseg_config cfg;
struct xseg *xseg;
uint32_t srcport, dstport;
uint64_t reqs;
#define mkname mkname_heavy
/* heavy distributes duplicates much more widely than light
 * ./xseg-tool random 100000 | cut -d' ' -f2- | sort | uniq -d -c |wc -l
 */

xport sport = NoPort;
static void init_local_signal() 
{
	if (xseg && sport != srcport){
		xseg_init_local_signal(xseg, srcport);
		sport = srcport;
	}
}

void mkname_heavy(char *name, uint32_t namelen, uint32_t seed)
{
	int i;
	char c;
	for (i = 0; i < namelen; i += 1) {
		c = seed + (seed >> 8) + (seed >> 16) + (seed >> 24);
		c = '0' + ((c + (c >> 4)) & 0xf);
		if (c > '9')
			c += 'a'-'0'-10;
		name[i] = c;
		seed *= ((seed % 137911) | 1) * 137911;
	}
}

void mkname_light(char *name, uint32_t namelen, uint32_t seed)
{
	int i;
	char c;
	for (i = 0; i < namelen; i += 1) {
		c = seed;
		name[i] = 'A' + (c & 0xf);
		seed += 1;
	}
}

uint64_t pick(uint64_t size)
{
	return (uint64_t)((double)(RAND_MAX) / random());
}

void mkchunk(	char *chunk, uint32_t datalen,
		char *target, uint32_t targetlen, uint64_t offset)
{
	long i, r, bufsize = targetlen + 16;
	char buf[bufsize];
	r = datalen % bufsize;
	snprintf(buf, bufsize, "%016llx%s", (unsigned long long)offset, target);

	for (i = 0; i <= (long)datalen - bufsize; i += bufsize)
		memcpy(chunk + i, buf, bufsize);

	memcpy(chunk + datalen - r, buf, r);
}

int chkchunk(	char *chunk, uint32_t datalen,
		char *target, uint32_t targetlen, uint64_t offset)
{
	long i, r;
	int bufsize = targetlen + 16;
	char buf[bufsize];
	r = datalen % targetlen;
	snprintf(buf, bufsize, "%016llx%s", (unsigned long long)offset, target);

	for (i = 0; i <= (long)datalen - bufsize; i += bufsize)
		if (memcmp(chunk + i, buf, bufsize)) {
			/*printf("mismatch: '%*s'* vs '%*s'\n",
				bufsize, buf, datalen, chunk);
			*/
			return 0;
		}

	if (memcmp(chunk + datalen - r, buf, r))
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
	char target[64], data[64];
	char *req_target, *req_data;
	unsigned int end = (req->targetlen> 63) ? 63 : req->targetlen;
	req_target = xseg_get_target(xseg, req);
	req_data = xseg_get_data(xseg, req);

	strncpy(target, req_target, end);
	target[end] = 0;
	strncpy(data, req_data, 63);
	data[63] = 0;
	fprintf(stderr,
		"Request %lx: target[%u](xptr: %llu): %s, data[%llu](xptr: %llu): %s \n\t"
		"offset: %llu, size: %llu, serviced; %llu, op: %u, state: %u, flags: %u \n\t"
		"src: %u, transit: %u, dst: %u, effective dst: %u\n",
		(unsigned long) req, req->targetlen, (unsigned long long)req->target,
		target,
		(unsigned long long) req->datalen, (unsigned long long) req->data,
		data,
		(unsigned long long) req->offset, (unsigned long long) req->size,
		(unsigned long long) req->serviced, req->op, req->state, req->flags,
		(unsigned int) req->src_portno, (unsigned int) req->transit_portno,
		(unsigned int) req->dst_portno, (unsigned int) req->effective_dst_portno);


}

int cmd_info(char *target)
{
	uint32_t targetlen = strlen(target);
	size_t size = sizeof(uint64_t);
	int r;
	xport p;
	struct xseg_request *req;
	char *req_target;

	req = xseg_get_request(xseg, srcport, dstport, X_ALLOC);
	if (!req) {
		fprintf(stderr, "No request!\n");
		return -1;
	}

	r = xseg_prep_request(xseg, req, targetlen, size);
	if (r < 0) {
		fprintf(stderr, "Cannot prepare request! (%lu, %lu)\n",
			(unsigned long) targetlen, (unsigned long) size);
		xseg_put_request(xseg, req, srcport);
		return -1;
	}

	req_target = xseg_get_target(xseg, req);
	strncpy(req_target, target, targetlen);
	req->offset = 0;
	req->size = size;
	req->op = X_INFO;

	p = xseg_submit(xseg, req, srcport, X_ALLOC);
	if (p == NoPort)
		return -1;

	xseg_signal(xseg, p);

	return 0;
}

int cmd_read(char *target, uint64_t offset, uint64_t size)
{
	uint32_t targetlen = strlen(target);
	int r;
	xport p;
	char *req_target;
	struct xseg_request *req = xseg_get_request(xseg, srcport, dstport, X_ALLOC);
	if (!req) {
		fprintf(stderr, "No request\n");
		return -1;
	}

	r = xseg_prep_request(xseg, req, targetlen, size);
	if (r < 0) {
		fprintf(stderr, "Cannot prepare request! (%lu, %llu)\n",
			(unsigned long)targetlen, (unsigned long long)size);
		xseg_put_request(xseg, req, srcport);
		return -1;
	}

	req_target = xseg_get_target(xseg, req);
	strncpy(req_target, target, targetlen);
	req->offset = offset;
	req->size = size;
	req->op = X_READ;
	report_request(req);
	p = xseg_submit(xseg, req, srcport, X_ALLOC);
	if (p == NoPort)
		return -1;

	xseg_signal(xseg, p);
	return 0;
}

int cmd_write(char *target, uint64_t offset)
{
	char *buf = NULL;
	int r;
	xport p;
	uint64_t size = 0;
	char *req_target, *req_data;
	uint32_t targetlen = strlen(target);
	struct xseg_request *req;

	inputbuf(stdin, &buf, &size);
	if (!size) {
		fprintf(stderr, "No input\n");
		return -1;
	}

	req = xseg_get_request(xseg, srcport, dstport, X_ALLOC);
	if (!req) {
		fprintf(stderr, "No request\n");
		return -1;
	}

	r = xseg_prep_request(xseg, req, targetlen, size);
	if (r < 0) {
		fprintf(stderr, "Cannot prepare request! (%lu, %llu)\n",
			(unsigned long)targetlen, (unsigned long long)size);
		xseg_put_request(xseg, req, srcport);
		return -1;
	}

	req_target = xseg_get_target(xseg, req);
	strncpy(req_target, target, targetlen);
	
	req_data = xseg_get_data(xseg, req);
	memcpy(req_data, buf, size);
	req->offset = offset;
	req->size = size;
	req->op = X_WRITE;

	p = xseg_submit(xseg, req, srcport, X_ALLOC);
	if (p == NoPort) {
		fprintf(stderr, "Cannot submit\n");
		return -1;
	}
	xseg_signal(xseg, p);

	return 0;
}

int cmd_truncate(char *target, uint64_t offset)
{
	return 0;
}

int cmd_delete(char *target)
{
        uint32_t targetlen = strlen(target);
        int r;
        struct xseg_request *req;
	init_local_signal();
        xseg_bind_port(xseg, srcport, NULL);

        req = xseg_get_request(xseg, srcport, dstport, X_ALLOC);
        if (!req) {
                fprintf(stderr, "No request!\n");
                return -1;
        }

        r = xseg_prep_request(xseg, req, targetlen, 0);
        if (r < 0) {
                fprintf(stderr, "Cannot prepare request! (%lu, %lu)\n",
                        (unsigned long) targetlen, (unsigned long) req->bufferlen - targetlen);
                xseg_put_request(xseg, req, srcport);
                return -1;
        }

	char *reqtarget = xseg_get_target(xseg, req);
        strncpy(reqtarget, target, targetlen);
        req->op = X_DELETE;

        xport p = xseg_submit(xseg, req, srcport, X_ALLOC);
        if (p == NoPort){
		fprintf(stderr, "Couldn't submit request\n");
                xseg_put_request(xseg, req, srcport);
                return -1;
	}

        xseg_signal(xseg, p);

	return 0;
}

int cmd_acquire(char *target)
{
	uint32_t targetlen = strlen(target);
	int r;
	xport p;
	char *req_target;
	struct xseg_request *req = xseg_get_request(xseg, srcport, dstport, X_ALLOC);
	if (!req) {
		fprintf(stderr, "No request\n");
		return -1;
	}

	r = xseg_prep_request(xseg, req, targetlen, 0);
	if (r < 0) {
		fprintf(stderr, "Cannot prepare request! (%lu, 0)\n",
			(unsigned long)targetlen);
		xseg_put_request(xseg, req, srcport);
		return -1;
	}

	req_target = xseg_get_target(xseg, req);
	strncpy(req_target, target, targetlen);
	req->offset = 0;
	req->size = 0;
	req->op = X_ACQUIRE;
	req->flags = XF_NOSYNC;
	p = xseg_submit(xseg, req, srcport, X_ALLOC);
	if (p == NoPort)
		return -1;

	xseg_signal(xseg, p);
	return 0;
}

int cmd_release(char *target)
{
	uint32_t targetlen = strlen(target);
	int r;
	xport p;
	char *req_target;
	struct xseg_request *req = xseg_get_request(xseg, srcport, dstport, X_ALLOC);
	if (!req) {
		fprintf(stderr, "No request\n");
		return -1;
	}

	r = xseg_prep_request(xseg, req, targetlen, 0);
	if (r < 0) {
		fprintf(stderr, "Cannot prepare request! (%lu, 0)\n",
			(unsigned long)targetlen);
		xseg_put_request(xseg, req, srcport);
		return -1;
	}

	req_target = xseg_get_target(xseg, req);
	strncpy(req_target, target, targetlen);
	req->offset = 0;
	req->size = 0;
	req->op = X_RELEASE;
	//req->flags = XF_FORCE;
	req->flags = 0;
	p = xseg_submit(xseg, req, srcport, X_ALLOC);
	if (p == NoPort)
		return -1;

	xseg_signal(xseg, p);
	return 0;
	return 0;
}

int cmd_open(char *target)
{
	uint32_t targetlen = strlen(target);
	int r;
	xport p;
	char *req_target;
	struct xseg_request *req = xseg_get_request(xseg, srcport, dstport, X_ALLOC);
	if (!req) {
		fprintf(stderr, "No request\n");
		return -1;
	}

	r = xseg_prep_request(xseg, req, targetlen, 0);
	if (r < 0) {
		fprintf(stderr, "Cannot prepare request! (%lu, 0)\n",
			(unsigned long)targetlen);
		xseg_put_request(xseg, req, srcport);
		return -1;
	}

	req_target = xseg_get_target(xseg, req);
	strncpy(req_target, target, targetlen);
	req->offset = 0;
	req->size = 0;
	req->op = X_OPEN;
	p = xseg_submit(xseg, req, srcport, X_ALLOC);
	if (p == NoPort)
		return -1;

	xseg_signal(xseg, p);
	return 0;
}

int cmd_close(char *target)
{
	uint32_t targetlen = strlen(target);
	int r;
	xport p;
	char *req_target;
	struct xseg_request *req = xseg_get_request(xseg, srcport, dstport, X_ALLOC);
	if (!req) {
		fprintf(stderr, "No request\n");
		return -1;
	}

	r = xseg_prep_request(xseg, req, targetlen, 0);
	if (r < 0) {
		fprintf(stderr, "Cannot prepare request! (%lu, 0)\n",
			(unsigned long)targetlen);
		xseg_put_request(xseg, req, srcport);
		return -1;
	}

	req_target = xseg_get_target(xseg, req);
	strncpy(req_target, target, targetlen);
	req->offset = 0;
	req->size = 0;
	req->op = X_CLOSE;
	req->flags = XF_FORCE;
	p = xseg_submit(xseg, req, srcport, X_ALLOC);
	if (p == NoPort)
		return -1;

	xseg_signal(xseg, p);
	return 0;
	return 0;
}

int cmd_copy(char *src, char *dst)
{
        uint32_t targetlen = strlen(dst);
	uint32_t parentlen = strlen(src);
        struct xseg_request *req;
        struct xseg_request_copy *xcopy;
	req = xseg_get_request(xseg, srcport, dstport, X_ALLOC);
        if (!req) {
                fprintf(stderr, "No request\n");
                return -1;
        }

	int r = xseg_prep_request(xseg, req, targetlen,
			sizeof(struct xseg_request_copy));
        if (r < 0) {
                fprintf(stderr, "Cannot prepare request!\n");
                xseg_put_request(xseg, req, srcport);
                return -1;
        }

	char *target = xseg_get_target(xseg, req);
	char *data = xseg_get_data(xseg, req);

	strncpy(target, dst, targetlen);
        xcopy = (struct xseg_request_copy *) data;
        strncpy(xcopy->target, src, parentlen);
	xcopy->targetlen = parentlen;
        req->offset = 0;
        req->size = sizeof(struct xseg_request_copy);
        req->op = X_COPY;

	xport p = xseg_submit(xseg, req, srcport, X_ALLOC);
	if (p == NoPort){
		fprintf(stderr, "Cannot submit request\n");
		return -1;
	}
	xseg_signal(xseg, p);

	return 0;
	return 0;
}

int cmd_clone(char *src, char *dst, long size)
{

        uint32_t targetlen = strlen(dst);
	uint32_t parentlen = strlen(src);
        struct xseg_request *req;
        struct xseg_request_clone *xclone;
	xseg_bind_port(xseg, srcport, NULL);
	req = xseg_get_request(xseg, srcport, dstport, X_ALLOC);
        if (!req) {
                fprintf(stderr, "No request\n");
                return -1;
        }

	int r = xseg_prep_request(xseg, req, targetlen, sizeof(struct xseg_request_clone));
        if (r < 0) {
                fprintf(stderr, "Cannot prepare request!\n");
                xseg_put_request(xseg, req, srcport);
                return -1;
        }

	char *target = xseg_get_target(xseg, req);
	char *data = xseg_get_data(xseg, req);

	strncpy(target, dst, targetlen);
        xclone = (struct xseg_request_clone *) data;
        strncpy(xclone->target, src, parentlen);
	xclone->targetlen = parentlen;
	if (size) {
		xclone->size = (uint64_t)size;
		xclone->size *= 1024*1024;
	} else {
		xclone->size = -1;
	}
        req->offset = 0;
        req->size = sizeof(struct xseg_request_clone);
        req->op = X_CLONE;

	xport p = xseg_submit(xseg, req, srcport, X_ALLOC);
	if (p == NoPort){
		fprintf(stderr, "Cannot submit request\n");
		return -1;
	}
	xseg_signal(xseg, p);

	return 0;
}

int cmd_snapshot(char *src, char *dst, long block_size)
{

        uint32_t targetlen = strlen(src);
	uint32_t parentlen = strlen(dst);
        struct xseg_request *req;
        struct xseg_request_snapshot *xsnapshot;
	xseg_bind_port(xseg, srcport, NULL);
	req = xseg_get_request(xseg, srcport, dstport, X_ALLOC);
        if (!req) {
                fprintf(stderr, "No request\n");
                return -1;
        }

	int r = xseg_prep_request(xseg, req, targetlen, sizeof(struct xseg_request_snapshot));
        if (r < 0) {
                fprintf(stderr, "Cannot prepare request!\n");
                xseg_put_request(xseg, req, srcport);
                return -1;
        }

	char *target = xseg_get_target(xseg, req);
	char *data = xseg_get_data(xseg, req);

	fprintf(stdout, "Snapshotting %s(%u) to %s(%u)\n", src, targetlen, dst, parentlen);
	strncpy(target, src, targetlen);
        xsnapshot = (struct xseg_request_snapshot *) data;
        strncpy(xsnapshot->target, dst, parentlen);
	xsnapshot->targetlen = parentlen;
        req->offset = 0;
        req->size = (uint64_t) block_size;
        req->op = X_SNAPSHOT;

	xport p = xseg_submit(xseg, req, srcport, X_ALLOC);
	if (p == NoPort){
		fprintf(stderr, "Cannot submit request\n");
		return -1;
	}
	xseg_signal(xseg, p);

	return 0;
}

void log_req(int logfd, uint32_t portno2, uint32_t portno1, int op, int method,
		struct xseg_request *req)
{
	FILE *logfp;
	char target[64], data[64];
	char *req_target, *req_data;
	/* null terminate name in case of req->target is less than 63 characters,
	 * and next character after name (aka first byte of next buffer) is not
	 * null
	 */
	unsigned int end = (req->targetlen > 63) ? 63 : req->targetlen;
	
	req_target = xseg_get_target(xseg, req);
	req_data = xseg_get_data(xseg, req);

	logfp = fdopen(logfd, "a");
	if (!logfp)
		return;

	switch(method) {
	case 0:
		strncpy(target, req_target, end);
		target[end] = 0;
		strncpy(data, req_data, 63);
		data[63] = 0;

		fprintf(logfp,
			"src port: %u, dst port: %u,  op:%u offset: %llu size: %lu, reqstate: %u\n"
			"target[%u]: '%s', data[%llu]:\n%s------------------\n\n",
			(unsigned int)portno1,
			(unsigned int)portno2,
			(unsigned int)req->op,
			(unsigned long long)req->offset,
			(unsigned long)req->size,
			(unsigned int)req->state,
			(unsigned int)req->targetlen, target,
			(unsigned long long)req->datalen, data);
		break;
	case 1:
		fprintf(logfp,
			"src port: %u, dst port: %u, op: %u\n",
			(unsigned int)portno1,
			(unsigned int)portno2,
			(unsigned int)req->op);
		break;
	case 2:
		fprintf(logfp, "src port: %u, dst port: %u, reqs: %llu\n",
			(unsigned int)portno1,
			(unsigned int)portno2,
			(unsigned long long)++reqs);
	}

	fclose(logfp);
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
	else if (!strcmp(how, "summary"))
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

			//FIXME
			req = xseg_accept(xseg, portno1, 0);
			if (req) {
				xseg_submit(xseg, req, portno2, X_ALLOC);
				log_req(logfd, portno1, portno2, LOG_ACCEPT, method, req);
				active += 1;
			}

			req = xseg_accept(xseg, portno2, 0);
			if (req) {
				xseg_submit(xseg, req, portno1, X_ALLOC);
				log_req(logfd, portno2, portno1, LOG_ACCEPT, method, req);
				active += 1;
			}

			req = xseg_receive(xseg, portno1, 0);
			if (req) {
				xseg_respond(xseg, req, portno2, X_ALLOC);
				log_req(logfd, portno1, portno2, LOG_RECEIVE, method, req);
				active += 1;
			}

			req = xseg_receive(xseg, portno2, 0);
			if (req) {
				xseg_respond(xseg, req, portno1, X_ALLOC);
				log_req(logfd, portno2, portno1, LOG_RECEIVE, method, req);
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

	close(logfd);

	return 0;
}

int cmd_rndwrite(long loops, int32_t seed, uint32_t targetlen, uint32_t chunksize, uint64_t size)
{
	if (loops < 0)
		return help();

	if (targetlen >= chunksize) {
		fprintf(stderr, "targetlen >= chunksize\n");
		return -1;
	}

	char *p = realloc(namebuf, targetlen+1);
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
	xport port;
	char *req_data, *req_target;
	seed = random();
	init_local_signal();

	for (;;) {
		xseg_prepare_wait(xseg, srcport);
		if (nr_submitted < loops &&
		    (submitted = xseg_get_request(xseg, srcport, dstport, X_ALLOC))) {
			xseg_cancel_wait(xseg, srcport);
			r = xseg_prep_request(xseg, submitted, targetlen, chunksize);
			if (r < 0) {
				fprintf(stderr, "Cannot prepare request! (%u, %u)\n",
					targetlen, chunksize);
				xseg_put_request(xseg, submitted, srcport);
				return -1;
			}
			
			req_target = xseg_get_target(xseg, submitted);
			req_data = xseg_get_data(xseg, submitted);

			reported = 0;
			mkname(namebuf, targetlen, seed);
			namebuf[targetlen] = 0;
			//printf("%ld: %s\n", nr_submitted, namebuf);
			strncpy(req_target, namebuf, targetlen);
			offset = 0;// pick(size);
			mkchunk(req_data, chunksize, namebuf, targetlen, offset);

			submitted->offset = offset;
			submitted->size = chunksize;
			submitted->op = X_WRITE;
			submitted->flags |= XF_NOSYNC;

			port =  xseg_submit(xseg, submitted, srcport, X_ALLOC);
			if (port == NoPort) {
				xseg_put_request(xseg, submitted, srcport);
			} else {
				seed = random();
				nr_submitted += 1;
				xseg_signal(xseg, port);
			}
		}

		received = xseg_receive(xseg, srcport, 0);
		if (received) {
			xseg_cancel_wait(xseg, srcport);
			nr_received += 1;
			if (!(received->state & XS_SERVED)) {
				nr_failed += 1;
				report_request(received);
			}
			if (xseg_put_request(xseg, received, srcport))
				fprintf(stderr, "Cannot put request at port %u\n", received->src_portno);
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

int cmd_rnddelete(long loops, int32_t seed, uint32_t targetlen)
{
	if (loops < 0)
		return help();
	char *p = realloc(namebuf, targetlen+1);
	if (!p) {
		fprintf(stderr, "Cannot allocate memory\n");
		return -1;
	}
	namebuf = p;

	srandom(seed);

	struct xseg_request *submitted = NULL, *received;
	long nr_submitted = 0, nr_received = 0, nr_failed = 0;
	int reported = 0, r;
	xport port;
	char *req_target;
	seed = random();
	init_local_signal();

	for (;;) {
		xseg_prepare_wait(xseg, srcport);
		if (nr_submitted < loops &&
		    (submitted = xseg_get_request(xseg, srcport, dstport, X_ALLOC))) {
			xseg_cancel_wait(xseg, srcport);
			r = xseg_prep_request(xseg, submitted, targetlen, 0);
			if (r < 0) {
				fprintf(stderr, "Cannot prepare request! (%u, %u)\n",
					targetlen, 0);
				xseg_put_request(xseg, submitted, srcport);
				return -1;
			}
			
			req_target = xseg_get_target(xseg, submitted);

			reported = 0;
			mkname(namebuf, targetlen, seed);
			namebuf[targetlen] = 0;
			//printf("%ld: %s\n", nr_submitted, namebuf);
			strncpy(req_target, namebuf, targetlen);
			submitted->offset = 0;
			submitted->size = 0;
			submitted->op = X_DELETE;
			submitted->flags = 0;

			port =  xseg_submit(xseg, submitted, srcport, X_ALLOC);
			if (port == NoPort) {
				xseg_put_request(xseg, submitted, srcport);
			} else {
				seed = random();
				nr_submitted += 1;
				xseg_signal(xseg, port);
			}
		}

		received = xseg_receive(xseg, srcport, 0);
		if (received) {
			xseg_cancel_wait(xseg, srcport);
			nr_received += 1;
			if (!(received->state & XS_SERVED)) {
				nr_failed += 1;
				report_request(received);
			}
			if (xseg_put_request(xseg, received, srcport))
				fprintf(stderr, "Cannot put request at port %u\n", received->src_portno);
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

int cmd_rndread(long loops, int32_t seed, uint32_t targetlen, uint32_t chunksize, uint64_t size)
{
	if (loops < 0)
		return help();

	if (targetlen >= chunksize) {
		fprintf(stderr, "targetlen >= chunksize\n");
		return -1;
	}

	char *p = realloc(namebuf, targetlen+1);
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
	xport port;
	char *req_data, *req_target;
	init_local_signal();

	seed = random();
	for (;;) {
		submitted = NULL;
		xseg_prepare_wait(xseg, srcport);
		if (nr_submitted < loops &&
		    (submitted = xseg_get_request(xseg, srcport, dstport, X_ALLOC))) {
			xseg_cancel_wait(xseg, srcport);
			r = xseg_prep_request(xseg, submitted, targetlen, chunksize);
			if (r < 0) {
				fprintf(stderr, "Cannot prepare request! (%u, %u)\n",
					targetlen, chunksize);
				xseg_put_request(xseg, submitted, srcport);
				return -1;
			}

			req_target = xseg_get_target(xseg, submitted);
			reported = 0;
			mkname(namebuf, targetlen, seed);
			namebuf[targetlen] = 0;
			//printf("%ld: %s\n", nr_submitted, namebuf);
			offset = 0;//pick(size);

			strncpy(req_target, namebuf, targetlen);
			submitted->offset = offset;
			submitted->size = chunksize;
			submitted->op = X_READ;
			port = xseg_submit(xseg, submitted, srcport, X_ALLOC);
			if (port == NoPort) {
				xseg_put_request(xseg, submitted, srcport);
			} else {
				seed = random();
				nr_submitted += 1;
				xseg_signal(xseg, port);
			}
		}

		received = xseg_receive(xseg, srcport, 0);
		if (received) {
			xseg_cancel_wait(xseg, srcport);
			nr_received += 1;
			req_target = xseg_get_target(xseg, received);
			req_data = xseg_get_data(xseg, received);
			if (!(received->state & XS_SERVED)) {
				nr_failed += 1;
				report_request(received);
			} else if (!chkchunk(req_data, received->datalen,
					req_target, received->targetlen, received->offset)) {
	//			report_request(received);
				nr_mismatch += 1;
			}

			if (xseg_put_request(xseg, received, srcport))
				fprintf(stderr, "Cannot put request at port %u\n", received->src_portno);
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

int cmd_submit_reqs(long loops, long concurrent_reqs, int op)
{
	if (loops < 0)
		return help();

	struct xseg_request *submitted = NULL, *received;
	long nr_submitted = 0, nr_received = 0, nr_failed = 0, nr_mismatch = 0, nr_flying = 0;
	int r;
	uint64_t offset;
	uint32_t targetlen = 10, chunksize = 4096;
	struct timeval tv1, tv2;
	xport p;
	char *req_data, *req_target;

	xseg_bind_port(xseg, srcport, NULL);

	gettimeofday(&tv1, NULL);
	for (;;) {
		submitted = NULL;
		xseg_prepare_wait(xseg, srcport);
		if (nr_submitted < loops &&  nr_flying < concurrent_reqs &&
		    (submitted = xseg_get_request(xseg, srcport, dstport, X_ALLOC))) {
			xseg_cancel_wait(xseg, srcport);
			r = xseg_prep_request(xseg, submitted, targetlen, chunksize);
			if (r < 0) {
				fprintf(stderr, "Cannot prepare request! (%u, %u)\n",
					targetlen, chunksize);
				xseg_put_request(xseg, submitted, srcport);
				return -1;
			}
			
			//FIXME
			++nr_flying;
			nr_submitted += 1;
			offset = 0;//pick(size);

			submitted->offset = offset;
			submitted->size = chunksize;
			req_target = xseg_get_target(xseg, submitted);
			req_data = xseg_get_data(xseg, submitted);

			if (op == 0)
				submitted->op = X_INFO;
			else if (op == 1)
				submitted->op = X_READ;
			else if (op == 2) {
				submitted->op = X_WRITE;
				mkchunk(req_data, submitted->datalen, req_target, submitted->targetlen, submitted->offset);
			}

			p = xseg_submit(xseg, submitted, srcport, X_ALLOC);
			if ( p != NoPort){
				if (xseg_signal(xseg, p) < 0)
					perror("Cannot signal peer");
			}
		}
		received = xseg_receive(xseg, srcport, 0);
		if (received) {
			xseg_cancel_wait(xseg, srcport);
			--nr_flying;
			if (nr_received == 0)
				fprintf(stderr, "latency (time for the first req to complete): %llu usecs\n",
					(unsigned long long)received->elapsed);
			nr_received += 1;
			if (!(received->state & XS_SERVED)) {
				nr_failed += 1;
				//report_request(received);
			}

			if (xseg_put_request(xseg, received, srcport))
				fprintf(stderr, "Cannot put request at port %u\n", received->src_portno);
		}

		if (!submitted && !received)
			xseg_wait_signal(xseg, 10000000L);

		if (nr_received >= loops)
			break;
	}
	gettimeofday(&tv2, NULL);

	fprintf(stderr, "submitted %ld, received %ld, failed %ld, mismatched %ld\n",
		nr_submitted, nr_received, nr_failed, nr_mismatch);
	long t = (tv2.tv_sec - tv1.tv_sec)*1000000 + (tv2.tv_usec - tv1.tv_usec);
	fprintf(stderr, "elpased time: %lf secs, throughput: %lf reqs/sec\n", (double) t / 1000000.0, (double) nr_submitted / (t / 1000000.0));

	return 0;
}

static void lock_status(struct xlock *lock, char *buf, int len)
{
	int r;
	if (lock->owner == Noone)
		r = snprintf(buf, len, "Locked: No");
	else
		r = snprintf(buf, len, "Locked: Yes (Owner: %lu)", lock->owner);
	if (r >= len)
		buf[len-1] = 0;
}

int cmd_report(uint32_t portno)
{
	char fls[64], rls[64], pls[64]; // buffer to store lock status
	struct xseg_port *port = xseg_get_port(xseg, portno);
	if (!port) {
		printf("port %u is not assigned\n", portno);
		return 0;
	}
	struct xq *fq, *rq, *pq;
	fq = xseg_get_queue(xseg, port, free_queue);
	rq = xseg_get_queue(xseg, port, request_queue);
	pq = xseg_get_queue(xseg, port, reply_queue);
	lock_status(&port->fq_lock, fls, 64);
	lock_status(&port->rq_lock, rls, 64);
	lock_status(&port->pq_lock, pls, 64);
	fprintf(stderr, "port %u:\n"
		"   requests: %llu/%llu  next: %u  dst gw: %u\n"
		"       free_queue [%p] count : %4llu | %s\n"
		"    request_queue [%p] count : %4llu | %s\n"
		"      reply_queue [%p] count : %4llu | %s\n",
		portno, (unsigned long long)port->alloc_reqs, 
		(unsigned long long)port->max_alloc_reqs,
		xseg->path_next[portno],
		xseg->dst_gw[portno],
		(void *)fq, (unsigned long long)xq_count(fq), fls,
		(void *)rq, (unsigned long long)xq_count(rq), rls,
		(void *)pq, (unsigned long long)xq_count(pq), pls);
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
static void print_hanlder(char *name, struct xobject_h *obj_h)
{
	char ls[64];
	lock_status(&obj_h->lock, ls, 64);
	fprintf(stderr, "%20s: free: %4llu, allocated: %4llu, allocated space: %7llu (object size: %llu), Lock %s\n",
			name,
			(unsigned long long) obj_h->nr_free,
			(unsigned long long) obj_h->nr_allocated,
			(unsigned long long) obj_h->allocated_space,
			(unsigned long long) obj_h->obj_size, ls);
}

//FIXME ugly
static void print_heap(struct xseg *xseg)
{
	char *UNIT[4];
	UNIT[0] = "B";
	UNIT[1] = "KiB";
	UNIT[2] = "MiB";
	UNIT[3] = "GiB";
	uint64_t MULT[4];
	MULT[0] = 1;
	MULT[1] = 1024;
	MULT[2] = 1024*1024;
	MULT[3] = 1024*1024*1024;

	int u;
	uint64_t t;
	fprintf(stderr, "Heap usage: ");
	u = 0;
	t = xseg->heap->cur;
	while (t > 0) {
		t /= 1024;
		u++;
	}
	if (!t)
		u--;
	t = xseg->heap->cur / MULT[u];
	if (t < 10){
		float tf = ((float)(xseg->heap->cur))/((float)MULT[u]);
		fprintf(stderr, "%2.1f %s/", tf, UNIT[u]);
	}
	else {
		unsigned int tu = xseg->heap->cur / MULT[u];
		fprintf(stderr, "%3u %s/", tu, UNIT[u]);
	}

	u = 0;
	t = xseg->config.heap_size;
	while (t > 0) {
		t /= 1024;
		u++;
	}
	if (!t)
		u--;
	t = xseg->config.heap_size/MULT[u];
	if (t < 10){
		float tf = ((float)(xseg->config.heap_size))/(float)MULT[u];
		fprintf(stderr, "%2.1f %s ", tf, UNIT[u]);
	}
	else {
		unsigned int tu = xseg->config.heap_size / MULT[u];
		fprintf(stderr, "%3u %s ", tu, UNIT[u]);
	}
	char ls[64];
	lock_status(&xseg->heap->lock, ls, 64);
	fprintf(stderr, "(%llu / %llu), %s\n",
			(unsigned long long)xseg->heap->cur,
			(unsigned long long)xseg->config.heap_size,
			ls);
}

int cmd_reportall(void)
{
	uint32_t t;

	if (cmd_join())
		return -1;

	fprintf(stderr, "Segment lock: %s\n",
		(xseg->shared->flags & XSEG_F_LOCK) ? "Locked" : "Unlocked");
	print_heap(xseg);
	/* fprintf(stderr, "Heap usage: %llu / %llu\n", */
	/* 		(unsigned long long)xseg->heap->cur, */
	/* 		(unsigned long long)xseg->config.heap_size); */
	fprintf(stderr, "Handlers: \n");
	print_hanlder("Requests handler", xseg->request_h);
	print_hanlder("Ports handler", xseg->port_h);
	print_hanlder("Objects handler", xseg->object_handlers);
	fprintf(stderr, "\n");

	for (t = 0; t < xseg->config.nr_ports; t++)
		cmd_report(t);

	return 0;
}


int finish_req(struct xseg_request *req, enum req_action action)
{
	if (action == COMPLETE){
		req->state &= ~XS_FAILED;
		req->state |= XS_SERVED;
	} else {
		req->state |= XS_FAILED;
		req->state &= ~XS_SERVED;
	}
	req->serviced = 0;
	xport p = xseg_respond(xseg, req, srcport, X_ALLOC);
	if (p == NoPort)
		xseg_put_request(xseg, req, srcport);
	else
		xseg_signal(xseg, p);
	return 0;
}

//FIXME this should be in xseg lib?
static int isDangling(struct xseg_request *req)
{
	xport i;
	struct xseg_port *port;
	for (i = 0; i < xseg->config.nr_ports; i++) {
		if (xseg->ports[i]){
			port = xseg_get_port(xseg, i);
			if (!port){
				fprintf(stderr, "Inconsisten port <-> portno mapping %u", i);
				continue;
			}
			struct xq *fq, *rq, *pq;
			fq = xseg_get_queue(xseg, port, free_queue);
			rq = xseg_get_queue(xseg, port, request_queue);
			pq = xseg_get_queue(xseg, port, reply_queue);
			xlock_acquire(&port->fq_lock, srcport);
			if (__xq_check(fq, XPTR_MAKE(req, xseg->segment))){
					xlock_release(&port->fq_lock);
					return 0;
			}
			xlock_release(&port->fq_lock);
			xlock_acquire(&port->rq_lock, srcport);
			if (__xq_check(rq, XPTR_MAKE(req, xseg->segment))){
					xlock_release(&port->rq_lock);
					return 0;
			}
			xlock_release(&port->rq_lock);
			xlock_acquire(&port->pq_lock, srcport);
			if (__xq_check(pq, XPTR_MAKE(req, xseg->segment))){
					xlock_release(&port->pq_lock);
					return 0;
			}
			xlock_release(&port->pq_lock);
		}
	}
	return 1;
}

int prompt_user(char *msg)
{
	int c = 0, r = -1;
	printf("%s [y/n]: ", msg);
	while (1) {
		c = fgetc(stdin);
		if (c == 'y' || c == 'Y')
			r = 1;
		else if (c == 'n' || c == 'N')
			r = 0;
		else if (c == '\n'){
			if (r == -1)
				printf("%s [y/n]: ", msg);
			else
				break;
		}
	}
	return r;
}

//FIXME this should be in xseg lib?
int cmd_verify(int fix)
{
	if (cmd_join())
		return -1;
	//segment lock
	if (xseg->shared->flags & XSEG_F_LOCK){
		fprintf(stderr, "Segment lock: Locked\n");
		if (fix && prompt_user("Unlock it ?"))
			xseg->shared->flags &= ~XSEG_F_LOCK;
	}
	//heap lock
	if (xseg->heap->lock.owner != Noone){
		fprintf(stderr, "Heap lock: Locked (Owner: %llu)\n",
			(unsigned long long)xseg->heap->lock.owner);
		if (fix && prompt_user("Unlock it ?"))
			xlock_release(&xseg->heap->lock);
	}
	//obj_h locks
	if (xseg->request_h->lock.owner != Noone){
		fprintf(stderr, "Requests handler lock: Locked (Owner: %llu)\n",
			(unsigned long long)xseg->request_h->lock.owner);
		if (fix && prompt_user("Unlock it ?"))
			xlock_release(&xseg->request_h->lock);
	}
	if (xseg->port_h->lock.owner != Noone){
		fprintf(stderr, "Ports handler lock: Locked (Owner: %llu)\n",
			(unsigned long long)xseg->port_h->lock.owner);
		if (fix && prompt_user("Unlock it ?"))
			xlock_release(&xseg->port_h->lock);
	}
	if (xseg->object_handlers->lock.owner != Noone){
		fprintf(stderr, "Objects handler lock: Locked (Owner: %llu)\n",
			(unsigned long long)xseg->object_handlers->lock.owner);
		if (fix && prompt_user("Unlock it ?"))
			xlock_release(&xseg->object_handlers->lock);
	}
	//take segment lock?
	xport i;
	struct xseg_port *port;
	for (i = 0; i < xseg->config.nr_ports; i++) {
		if (xseg->ports[i]){
			port = xseg_get_port(xseg, i);
			if (!port){
				fprintf(stderr, "Inconsisten port <-> portno mapping %u", i);
				continue;
			}
			if (port->fq_lock.owner != Noone) {
				fprintf(stderr, "Free queue lock of port %u locked (Owner %llu)\n",
						i, (unsigned long long)port->fq_lock.owner);
				if (fix && prompt_user("Unlock it ?"))
					xlock_release(&port->fq_lock);
			}
			if (port->rq_lock.owner != Noone) {
				fprintf(stderr, "Request queue lock of port %u locked (Owner %llu)\n",
						i, (unsigned long long)port->rq_lock.owner);
				if (fix && prompt_user("Unlock it ?"))
					xlock_release(&port->rq_lock);
			}
			if (port->pq_lock.owner != Noone) {
				fprintf(stderr, "Reply queue lock of port %u locked (Owner %llu)\n",
						i, (unsigned long long)port->pq_lock.owner);
				if (fix && prompt_user("Unlock it ?"))
					xlock_release(&port->pq_lock);
			}
		}
	}

	struct xobject_h *obj_h = xseg->request_h;
	struct xobject_iter it;

	struct xseg_request *req;
	xlock_acquire(&obj_h->lock, srcport);
	xobj_iter_init(obj_h, &it);
	while (xobj_iterate(obj_h, &it, (void **)&req)){
		//FIXME this will not work cause obj->magic - req->serial is not
		//touched when a request is get
		/* if (obj->magic != MAGIC_REQ && t->src_portno == portno){ */
		if (isDangling(req) && !__xobj_isFree(obj_h, req)){
			report_request(req);
			if (fix && prompt_user("Fail it ?")){
				printf("Finishing ...\n");
				finish_req(req, FAIL);
			}
		}
	}
	xlock_release(&obj_h->lock);
	return 0;
}

int cmd_inspectq(xport portno, enum queue qt)
{
	if (cmd_join())
		return -1;

	struct xq *q;
	struct xlock *l;
	struct xseg_port *port = xseg_get_port(xseg, portno);
	if (!port)
		return -1;
	if (qt == FREE_QUEUE){
		q = xseg_get_queue(xseg, port, free_queue);
		l = &port->fq_lock;
	}
	else if (qt == REQUEST_QUEUE){
		q = xseg_get_queue(xseg, port, request_queue);
		l = &port->rq_lock;
	}
	else if (qt == REPLY_QUEUE) {
		q = xseg_get_queue(xseg, port, reply_queue);
		l = &port->rq_lock;
	}
	else
		return -1;
	xlock_acquire(l, srcport);
	xqindex i,c = xq_count(q);
	if (c) {
		struct xseg_request *req;
		xptr xqi;
		for (i = 0; i < c; i++) {
			xqi = __xq_pop_head(q);
			req = XPTR_TAKE(xqi, xseg->segment);
			report_request(req);
			__xq_append_tail(q, xqi);
		}
	}
	else {
		fprintf(stderr, "Queue is empty\n\n");
	}
	xlock_release(l);
	return 0;
}


int cmd_request(struct xseg_request *req, enum req_action action)
{
	if (cmd_join())
		return -1;

	struct xobject_h *obj_h = xseg->request_h;
	if (!xobj_check(obj_h, req))
		return -1;

	if (action == REPORT)
		report_request(req);
	else if (action == FAIL){
		report_request(req);
		if (prompt_user("fail it ?")){
			printf("Finishing ...\n");
			finish_req(req, FAIL);
		}
	}
	else if (action == COMPLETE){
		report_request(req);
		if (prompt_user("Complete it ?")){
			printf("Finishing ...\n");
			finish_req(req, COMPLETE);
		}
	}
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
		req = xseg_accept(xseg, dstport, 0);
		if (!req)
			break;
		if (xseg_put_request(xseg, req, srcport))
			fprintf(stderr, "Cannot put request at port %u\n", req->src_portno);
	}

	return 0;
}

int cmd_finish(unsigned long nr, int fail)
{
	struct xseg_request *req;
	char *buf = malloc(sizeof(char) * 8128);
	char *req_target, *req_data;
	xseg_bind_port(xseg, srcport, NULL);
	xport p;

	for (; nr--;) {
		xseg_prepare_wait(xseg, srcport);
		req = xseg_accept(xseg, srcport, 0);
		if (req) {
			req_target = xseg_get_target(xseg, req);
			req_data = xseg_get_data(xseg, req);
			xseg_cancel_wait(xseg, srcport);
			if (fail == 1)
				req->state &= ~XS_SERVED;
			else {
				if (req->op == X_READ)
					mkchunk(req_data, req->datalen, req_target, req->targetlen, req->offset);
				else if (req->op == X_WRITE) 
					memcpy(buf, req_data, (sizeof(*buf) > req->datalen) ? req->datalen : sizeof(*buf));
				else if (req->op == X_INFO)
					*((uint64_t *) req->data) = 4294967296;
				
				req->state |= XS_SERVED;
				req->serviced = req->size;
			}

			p = xseg_respond(xseg, req, srcport, X_ALLOC);
			xseg_signal(xseg, p);
			continue;
		}
		++nr;
		xseg_wait_signal(xseg, 10000000L);
	}

	free(buf);

	return 0;
}

void handle_reply(struct xseg_request *req)
{
	char *req_data = xseg_get_data(xseg, req);
	char *req_target = xseg_get_target(xseg, req);
	if (!(req->state & XS_SERVED)) {
		report_request(req);
		goto put;
	}

	switch (req->op) {
	case X_READ:
		fwrite(req_data, 1, req->datalen, stdout);
		break;

	case X_WRITE:
		fprintf(stdout, "wrote: ");
		fwrite(req_data, 1, req->datalen, stdout);
		break;
	case X_SYNC:
	case X_DELETE:
		fprintf(stderr, "deleted %s\n", req_target);
		break;
	case X_TRUNCATE:
	case X_COMMIT:
	case X_CLONE:
		fprintf(stderr, "cloned %s\n", ((struct xseg_request_clone *)req_data)->target);
		break;
	case X_INFO:
		fprintf(stderr, "size: %llu\n", (unsigned long long)*((uint64_t *)req_data));
		break;
	case X_COPY:
		fprintf(stderr, "copied %s\n", ((struct xseg_request_copy *)req_data)->target);
		break;
	case X_CLOSE:
		fprintf(stderr, "Closed %s\n", req_target);
		break;
	case X_OPEN:
		fprintf(stderr, "Opened %s\n", req_target);
		break;
	case X_SNAPSHOT:
		fprintf(stderr, "Snapshotted %s\n", req_target);
		break;
	default:
		break;
	}

put:
	if (xseg_put_request(xseg, req, srcport))
		fprintf(stderr, "Cannot put reply at port %u\n", req->src_portno);
}

int cmd_wait(uint32_t nr)
{
	struct xseg_request *req;
	long ret;
	init_local_signal(); 

	for (;;) {
		req = xseg_receive(xseg, srcport, 0);
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
		req = xseg_receive(xseg, dstport, 0);
		if (!req)
			break;
		fprintf(stderr, "request: %08llx%08llx\n"
			"     op: %u\n"
			"  state: %u\n",
			0LL, (unsigned long long)req->serial,
			req->op,
			req->state);
		report_request(req);

		//fwrite(req->buffer, 1, req->bufferlen, stdout);

		if (xseg_put_request(xseg, req, srcport))
			fprintf(stderr, "Cannot put reply\n");
	}

	return 0;
}

int cmd_bind(long portno)
{
	struct xseg_port *port = xseg_bind_port(xseg, portno, NULL);
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

int cmd_set_next(xport portno, xport next)
{
	xseg->path_next[portno] = next;
	return 0;
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

		if (!strcmp(argv[i], "set-next") && (i + 2 < argc)) {
			ret = cmd_set_next(atol(argv[i+1]), atol(argv[i+2]));
			i += 2;
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

		if (!strcmp(argv[i], "verify")) {
			ret = cmd_verify(0);
			continue;
		}

		if (!strcmp(argv[i], "verify-fix")) {
			ret = cmd_verify(1);
			continue;
		}

		if (!strcmp(argv[i], "failreq") && (i + 1 < argc)) {
			struct xseg_request *req;
			sscanf(argv[i+1], "%lx", (unsigned long *)&req);
			ret = cmd_request(req, FAIL);
			i += 1;
			continue;
		}

		if (!strcmp(argv[i], "inspect-freeq") && (i + 1 < argc)) {
			ret = cmd_inspectq(atol(argv[i+1]), FREE_QUEUE);
			i += 1;
			continue;
		}

		if (!strcmp(argv[i], "inspect-requestq") && (i + 1 < argc)) {
			ret = cmd_inspectq(atol(argv[i+1]), REQUEST_QUEUE);
			i += 1;
			continue;
		}

		if (!strcmp(argv[i], "inspect-replyq") && (i + 1 < argc)) {
			ret = cmd_inspectq(atol(argv[i+1]), REPLY_QUEUE);
			i += 1;
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
			unsigned int targetlen = atoi(argv[i+3]);
			unsigned int chunksize = atoi(argv[i+4]);
			unsigned long objectsize = atol(argv[i+5]);
			ret = cmd_rndwrite(nr_loops, seed, targetlen, chunksize, objectsize);
			i += 5;
			continue;
		}
		
		if (!strcmp(argv[i], "rnddelete") && (i + 3 < argc)) {
			long nr_loops = atol(argv[i+1]);
			unsigned int seed = atoi(argv[i+2]);
			unsigned int targetlen = atoi(argv[i+3]);
			ret = cmd_rnddelete(nr_loops, seed, targetlen);
			i += 3;
			continue;
		}

		if (!strcmp(argv[i], "rndread") && (i + 5 < argc)) {
			long nr_loops = atol(argv[i+1]);
			unsigned int seed = atoi(argv[i+2]);
			unsigned int targetlen = atoi(argv[i+3]);
			unsigned int chunksize = atoi(argv[i+4]);
			unsigned long objectsize = atol(argv[i+5]);
			ret = cmd_rndread(nr_loops, seed, targetlen, chunksize, objectsize);
			i += 5;
			continue;
		}

		if (!strcmp(argv[i], "submit_reqs") && (i + 3 < argc)) {
			long nr_loops = atol(argv[i+1]);
			long concurrent_reqs = atol(argv[i+2]);
			int op = atoi(argv[i+3]);
			ret = cmd_submit_reqs(nr_loops, concurrent_reqs, op);
			i += 3;
			continue;
		}

		if (!strcmp(argv[i], "read") && (i + 3 < argc)) {
			char *target = argv[i+1];
			uint64_t offset = atol(argv[i+2]);
			uint64_t size   = atol(argv[i+3]);
			ret = cmd_read(target, offset, size);
			i += 3;
			continue;
		}

		if (!strcmp(argv[i], "write") && (i + 2 < argc)) {
			char *target = argv[i+1];
			uint64_t offset = atol(argv[i+2]);
			ret = cmd_write(target, offset);
			i += 2;
			continue;
		}

		if (!strcmp(argv[i], "truncate") && (i + 2 < argc)) {
			char *target = argv[i+1];
			uint64_t offset = atol(argv[i+2]);
			ret = cmd_truncate(target, offset);
			i += 2;
			continue;
		}

		if (!strcmp(argv[i], "delete") && (i + 1 < argc)) {
			char *target = argv[i+1];
			ret = cmd_delete(target);
			i += 1;
			continue;
		}

		if (!strcmp(argv[i], "acquire") && (i + 1 < argc)) {
			char *target = argv[i+1];
			ret = cmd_acquire(target);
			i += 1;
			continue;
		}

		if (!strcmp(argv[i], "release") && (i + 1 < argc)) {
			char *target = argv[i+1];
			ret = cmd_release(target);
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

		if (!strcmp(argv[i], "clone") && (i + 3 < argc)) {
			char *src = argv[i+1];
			char *dst = argv[i+2];
			long size = atol(argv[i+3]);
			ret = cmd_clone(src, dst, size);
			i += 3;
			continue;
		}
		if (!strcmp(argv[i], "snapshot") && (i + 2 < argc)) {
			char *src = argv[i+1];
			char *dst = argv[i+2];
			ret = cmd_snapshot(src, dst, 4096*1024*1024UL);
			i += 2;
			continue;
		}

		if (!strcmp(argv[i], "info") && (i + 1 < argc)) {
			char *target = argv[i+1];
			ret = cmd_info(target);
			i += 1;
			continue;
		}


		if (!parse_ports(argv[i]))
			fprintf(stderr, "invalid argument: %s\n", argv[i]);
	}

	/* xseg_leave(); */
	return ret;
}
