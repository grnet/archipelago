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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/util.h>
#include <xseg/xseg.h>
#include <xtypes/xobj.h>
#include <drivers/xseg_posix.h>
#define ERRSIZE 512
char errbuf[ERRSIZE];

static long posix_allocate(const char *name, uint64_t size)
{
	int fd, r;
	fd = shm_open(name, O_RDWR | O_CREAT | O_EXCL, 0770);
	if (fd < 0) {
		XSEGLOG("Cannot create shared segment: %s\n",
			strerror_r(errno, errbuf, ERRSIZE));
		return fd;
	}

	r = lseek(fd, size -1, SEEK_SET);
	if (r < 0) {
		close(fd);
		XSEGLOG("Cannot seek into segment file: %s\n",
			strerror_r(errno, errbuf, ERRSIZE));
		return r;
	}

	errbuf[0] = 0;
	r = write(fd, errbuf, 1);
	if (r != 1) {
		close(fd);
		XSEGLOG("Failed to set segment size: %s\n",
			strerror_r(errno, errbuf, ERRSIZE));
		return r;
	}

	close(fd);
	return 0;
}

static long posix_deallocate(const char *name)
{
	return shm_unlink(name);
}

static void *posix_map(const char *name, uint64_t size, struct xseg *seg)
{
	struct xseg *xseg;
	int fd;

//	if (seg)
//		XSEGLOG("struct xseg * is not NULL. Ignoring...\n");

	fd = shm_open(name, O_RDWR, 0000);
	if (fd < 0) {
		XSEGLOG("Failed to open '%s' for mapping: %s\n",
			name, strerror_r(errno, errbuf, ERRSIZE));
		return NULL;
	}

	xseg = mmap (	XSEG_BASE_AS_PTR,
			size,
			PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_FIXED /* | MAP_LOCKED */,
			fd, 0	);

	if (xseg == MAP_FAILED) {
		XSEGLOG("Could not map segment: %s\n",
			strerror_r(errno, errbuf, ERRSIZE));
		return NULL;
	}

	close(fd);
	return xseg;
}

static void posix_unmap(void *ptr, uint64_t size)
{
	struct xseg *xseg = ptr;
	(void)munmap(xseg, xseg->segment_size);
}


static void handler(int signum)
{
	static unsigned long counter;
	printf("%lu: signal %d: this shouldn't have happened.\n", counter, signum);
	counter ++;
}

static sigset_t savedset, set;
static pid_t pid;

static int posix_local_signal_init(struct xseg *xseg, xport portno)
{
	void (*h)(int);
	int r;
	h = signal(SIGIO, handler);
	if (h == SIG_ERR)
		return -1;

	sigemptyset(&set);
	sigaddset(&set, SIGIO);

	r = sigprocmask(SIG_BLOCK, &set, &savedset);
	if (r < 0)
		return -1;

	pid = syscall(SYS_gettid);
	return 0;
}

static void posix_local_signal_quit(struct xseg *xseg, xport portno)
{
	pid = 0;
	signal(SIGIO, SIG_DFL);
	sigprocmask(SIG_SETMASK, &savedset, NULL);
}

static int posix_remote_signal_init(void)
{
	return 0;
}

static void posix_remote_signal_quit(void)
{
	return;
}

static int posix_prepare_wait(struct xseg *xseg, uint32_t portno)
{
	struct xseg_port *port = xseg_get_port(xseg, portno);
	if (!port)
		return -1;
	struct posix_signal_desc *psd = xseg_get_signal_desc(xseg, port);
	if (!psd)
		return -1;
	psd->waitcue = pid;
	return 0;
}

static int posix_cancel_wait(struct xseg *xseg, uint32_t portno)
{
	struct xseg_port *port = xseg_get_port(xseg, portno);
	if (!port)
		return -1;
	struct posix_signal_desc *psd = xseg_get_signal_desc(xseg, port);
	if (!psd)
		return -1;
	psd->waitcue = 0;
	return 0;
}

static int posix_wait_signal(struct xseg *xseg, uint32_t usec_timeout)
{
	int r;
	siginfo_t siginfo;
	struct timespec ts;

	ts.tv_sec = usec_timeout / 1000000;
	ts.tv_nsec = 1000 * (usec_timeout - ts.tv_sec * 1000000);

	/* FIXME: Now that posix signaling is fixed, we could get rid of the timeout
	 * and use a NULL timespec linux-specific)
	 */
	r = sigtimedwait(&set, &siginfo, &ts);
	if (r < 0)
		return r;

	return siginfo.si_signo;
}

static int posix_signal(struct xseg *xseg, uint32_t portno)
{
	struct xseg_port *port = xseg_get_port(xseg, portno);
	if (!port)
		return -1;
	struct posix_signal_desc *psd = xseg_get_signal_desc(xseg, port);
	if (!psd)
		return -1;
	pid_t cue = (pid_t)psd->waitcue;
	if (!cue)
		//HACKY!
		return -2;

	/* FIXME: Make calls to xseg_signal() check for errors */
	return syscall(SYS_tkill, cue, SIGIO);
}

static void *posix_malloc(uint64_t size)
{
	return malloc((size_t)size);
}

static void *posix_realloc(void *mem, uint64_t size)
{
	return realloc(mem, (size_t)size);
}

static void posix_mfree(void *mem)
{
	free(mem);
}


int posix_init_signal_desc(struct xseg *xseg, void *sd)
{
	struct posix_signal_desc *psd = sd;
	if (!psd)
		return -1;
	psd->waitcue = 0;
	return 0;
}

void posix_quit_signal_desc(struct xseg *xseg, void *sd)
{
	return;
}

void * posix_alloc_data(struct xseg *xseg)
{
	struct xobject_h *sd_h = xseg_get_objh(xseg, MAGIC_POSIX_SD,
			sizeof(struct posix_signal_desc));
	return sd_h;
}

void posix_free_data(struct xseg *xseg, void *data)
{
	if (data)
		xseg_put_objh(xseg, (struct xobject_h *)data);
}

void *posix_alloc_signal_desc(struct xseg *xseg, void *data)
{
	struct xobject_h *sd_h = (struct xobject_h *) data;
	if (!sd_h)
		return NULL;
	struct posix_signal_desc *psd = xobj_get_obj(sd_h, X_ALLOC);
	if (!psd)
		return NULL;
	psd->waitcue = 0;
	return psd;

}

void posix_free_signal_desc(struct xseg *xseg, void *data, void *sd)
{
	struct xobject_h *sd_h = (struct xobject_h *) data;
	if (!sd_h)
		return;
	if (sd)
		xobj_put_obj(sd_h, sd);
	return;
}

static struct xseg_type xseg_posix = {
	/* xseg_operations */
	{
		.mfree		= posix_mfree,
		.allocate	= posix_allocate,
		.deallocate	= posix_deallocate,
		.map		= posix_map,
		.unmap		= posix_unmap,
	},
	/* name */
	"posix"
};

static struct xseg_peer xseg_peer_posix = {
	/* xseg_peer_operations */
	{
		.init_signal_desc   = posix_init_signal_desc,
		.quit_signal_desc   = posix_quit_signal_desc,
		.alloc_data         = posix_alloc_data,
		.free_data          = posix_free_data,
		.alloc_signal_desc  = posix_alloc_signal_desc,
		.free_signal_desc   = posix_free_signal_desc,
		.local_signal_init  = posix_local_signal_init,
		.local_signal_quit  = posix_local_signal_quit,
		.remote_signal_init = posix_remote_signal_init,
		.remote_signal_quit = posix_remote_signal_quit,
		.prepare_wait	    = posix_prepare_wait,
		.cancel_wait	    = posix_cancel_wait,
		.wait_signal	    = posix_wait_signal,
		.signal		    = posix_signal,
		.malloc		    = posix_malloc,
		.realloc 	    = posix_realloc,
		.mfree		    = posix_mfree,
	},
	/* name */
	"posix"
};

void xseg_posix_init(void)
{
	xseg_register_type(&xseg_posix);
	xseg_register_peer(&xseg_peer_posix);
}

