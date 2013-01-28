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
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <xseg/xseg.h>
#include <sys/util.h>
#include <sys/kernel/segdev.h>
#include <drivers/xseg_segdev.h>

#define ERRSIZE 512
static char errbuf[ERRSIZE];

#define SEGDEV_DEVICE "/dev/segdev"
static int fdev = -1;

static int opendev(void)
{
	if (fdev >= 0)
		return fdev;

	fdev = open(SEGDEV_DEVICE, O_RDWR);
	if (fdev < 0) {
		XSEGLOG("Cannot open %s: %s\n", SEGDEV_DEVICE,
			strerror_r(errno, errbuf, ERRSIZE));
		fdev = -1;
	}
	return fdev;
}

static int closedev(void)
{
	int r;
	if (fdev < 0)
		return 0;

	r = close(fdev);
	if (r < 0) {
		XSEGLOG("Cannot close %s: %s\n", SEGDEV_DEVICE,
			strerror_r(errno, errbuf, ERRSIZE));
		return -1;
	} else
		fdev = -1;

	return 0;
}

static long segdev_allocate(const char *name, uint64_t size)
{
	int fd;
	long oldsize;

	fd = opendev();
	if (fd < 0)
		return fd;

	oldsize = ioctl(fd, SEGDEV_IOC_SEGSIZE, 0);
	if (oldsize >= 0) {
		XSEGLOG("Destroying old segment\n");
		if (ioctl(fd, SEGDEV_IOC_DESTROYSEG, 0)) {
			XSEGLOG("Failed to destroy old segment");
			closedev();
			return -2;
		}
	}

	XSEGLOG("creating segment of size %llu\n", size);

	if (ioctl(fd, SEGDEV_IOC_CREATESEG, size)) {
		XSEGLOG("Failed to create segment");
		closedev();
		return -3;
	}

	return 0;
}

static long segdev_deallocate(const char *name)
{
	int fd;
	fd = open(SEGDEV_DEVICE, O_RDWR);
	if (fd < 0) {
		XSEGLOG("Cannot open %s: %s\n", SEGDEV_DEVICE,
			strerror_r(errno, errbuf, ERRSIZE));
		return -1;
	}

	if (ioctl(fd, SEGDEV_IOC_DESTROYSEG, 0)) {
		XSEGLOG("Failed to destroy old segment");
		return -2;
	}

	closedev();
	return 0;
}

static void *segdev_map(const char *name, uint64_t size, struct xseg *seg)
{
	struct xseg *xseg;
	int fd;

	if (seg)
		XSEGLOG("struct xseg * not NULL. Ignoring...\n");

	fd = opendev();
	if (fd < 0)
		return NULL;

	xseg = mmap (	XSEG_BASE_AS_PTR,
			size,
			PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_FIXED /* | MAP_LOCKED */,
			fd, 0	);

	if (xseg == MAP_FAILED) {
		XSEGLOG("Could not map segment: %s\n",
			strerror_r(errno, errbuf, ERRSIZE));
		closedev();
		return NULL;
	}

	return xseg;
}

static void segdev_unmap(void *ptr, uint64_t size)
{
	struct xseg *xseg = ptr;
	(void)munmap(xseg, xseg->segment_size);
}


static struct xseg_type xseg_segdev = {
	/* xseg_operations */
	{
		.allocate	= segdev_allocate,
		.deallocate	= segdev_deallocate,
		.map		= segdev_map,
		.unmap		= segdev_unmap
	},
	/* name */
	"segdev"
};

static int segdev_local_signal_init(struct xseg *xseg, xport portno)
{
	return -1;
}

static void segdev_local_signal_quit(struct xseg *xseg, xport portno)
{
	return;
}

static int segdev_remote_signal_init(void)
{
	return 0;
}

static void segdev_remote_signal_quit(void)
{
	return;
}

static int segdev_prepare_wait(struct xseg *xseg, uint32_t portno)
{
	return -1;
}

static int segdev_cancel_wait(struct xseg *xseg, uint32_t portno)
{
	return -1;
}

static int segdev_wait_signal(struct xseg *xseg, uint32_t timeout)
{
	return -1;
}

static int segdev_signal(struct xseg *xseg, uint32_t portno)
{
	struct xseg_port *port = xseg_get_port(xseg, portno);
	if (!port)
		return -1;
	struct segdev_signal_desc *ssd = xseg_get_signal_desc(xseg, port);
	if (!ssd)
		return -1;

	if (!ssd->waitcue){
		return 0;
	}
	else
		return write(opendev(), &portno, sizeof(portno));
}

static void *segdev_malloc(uint64_t size)
{
	return NULL;
}

static void *segdev_realloc(void *mem, uint64_t size)
{
	return NULL;
}

static void segdev_mfree(void *mem) { }

static int segdev_init_signal_desc(struct xseg *xseg, void *sd)
{
	return -1;
}

static void segdev_quit_signal_desc(struct xseg *xseg, void *sd)
{
	return;
}

static void *segdev_alloc_data(struct xseg *xseg)
{
	return NULL;
}

static void segdev_free_data(struct xseg *xseg, void *data)
{
	return;
}

static void *segdev_alloc_signal_desc(struct xseg *xseg, void *data)
{
	return NULL;
}

static void segdev_free_signal_desc(struct xseg *xseg, void *data, void *sd)
{
	return;
}

static struct xseg_peer xseg_peer_segdev = {
	/* xseg signal operations */
	{
		.init_signal_desc   = segdev_init_signal_desc,
		.quit_signal_desc   = segdev_quit_signal_desc,
		.alloc_data         = segdev_alloc_data,
		.free_data          = segdev_free_data,
		.alloc_signal_desc  = segdev_alloc_signal_desc,
		.free_signal_desc   = segdev_free_signal_desc,
		.local_signal_init  = segdev_local_signal_init,
		.local_signal_quit  = segdev_local_signal_quit,
		.remote_signal_init = segdev_remote_signal_init,
		.remote_signal_quit = segdev_remote_signal_quit,
		.prepare_wait = segdev_prepare_wait,
		.cancel_wait = segdev_cancel_wait,
		.wait_signal = segdev_wait_signal,
		.signal = segdev_signal,
		.malloc = segdev_malloc,
		.realloc = segdev_realloc,
		.mfree = segdev_mfree
	},
	/* name */
	"segdev"
};

void xseg_segdev_init(void)
{
	xseg_register_type(&xseg_segdev);
	xseg_register_peer(&xseg_peer_segdev);
}

