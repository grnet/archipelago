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
#include <xsegdev.h>

#define ERRSIZE 512
static char errbuf[ERRSIZE];

#define XSEG_DEVICE "/dev/xsegdev"
static int fdev = -1;

static int opendev(void)
{
	if (fdev >= 0)
		return fdev;

	fdev = open(XSEG_DEVICE, O_RDWR);
	if (fdev < 0) {
		LOGMSG("Cannot open %s: %s\n", XSEG_DEVICE,
			strerror_r(errno, errbuf, ERRSIZE));
		close(fdev);
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
		LOGMSG("Cannot close %s: %s\n", XSEG_DEVICE,
			strerror_r(errno, errbuf, ERRSIZE));
		return -1;
	} else
		fdev = -1;

	return 0;
}

static long xsegdev_allocate(const char *name, uint64_t size)
{
	int fd;
	long oldsize;

	fd = opendev();
	if (fd < 0)
		return fd;

	oldsize = ioctl(fd, XSEGDEV_IOC_SEGSIZE, 0);
	if (oldsize >= 0) {
		LOGMSG("Destroying old segment\n");
		if (ioctl(fd, XSEGDEV_IOC_DESTROYSEG, 0)) {
			LOGMSG("Failed to destroy old segment");
			closedev();
			return -2;
		}
	}

	if (ioctl(fd, XSEGDEV_IOC_CREATESEG, size)) {
		LOGMSG("Failed to create segment");
		closedev();
		return -3;
	}

	return 0;
}

static long xsegdev_deallocate(const char *name)
{
	int fd;
	fd = open(XSEG_DEVICE, O_RDWR);
	if (fd < 0) {
		LOGMSG("Cannot open %s: %s\n", XSEG_DEVICE,
			strerror_r(errno, errbuf, ERRSIZE));
		return -1;
	}

	if (ioctl(fd, XSEGDEV_IOC_DESTROYSEG, 0)) {
		LOGMSG("Failed to destroy old segment");
		return -2;
	}

	closedev();
	return 0;
}

static void *xsegdev_map(const char *name, uint64_t size)
{
	struct xseg *xseg;
	int fd;
	fd = opendev();
	if (fd < 0)
		return NULL;

	xseg = mmap (	XSEG_BASE_AS_PTR,
			size,
			PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_FIXED /* | MAP_LOCKED */,
			fd, 0	);

	if (xseg == MAP_FAILED) {
		LOGMSG("Could not map segment: %s\n",
			strerror_r(errno, errbuf, ERRSIZE));
		closedev();
		return NULL;
	}

	return xseg;
}

static void xsegdev_unmap(void *ptr, uint64_t size)
{
	struct xseg *xseg = ptr;
	(void)munmap(xseg, xseg->segment_size);
}


static struct xseg_type xseg_xsegdev = {
	/* xseg_operations */
	{
		.malloc		= malloc,
		.mfree		= free,
		.allocate	= xsegdev_allocate,
		.deallocate	= xsegdev_deallocate,
		.map		= xsegdev_map,
		.unmap		= xsegdev_unmap
	},
	/* name */
	"xsegdev"
};

static int xsegdev_signal_init(void)
{
	return 0;
}

static void xsegdev_signal_quit(void) { }

static int xsegdev_prepare_wait(struct xseg_port *port)
{
	return -1;
}

static int xsegdev_cancel_wait(struct xseg_port *port)
{
	return -1;
}

static int xsegdev_wait_signal(struct xseg_port *port, uint32_t timeout)
{
	return -1;
}

static int xsegdev_signal(struct xseg_port *port)
{
	return write(opendev(), NULL, 0);
}

static void *xsegdev_malloc(uint64_t size)
{
	return NULL;
}

static void *xsegdev_realloc(void *mem, uint64_t size)
{
	return NULL;
}

static void xsegdev_mfree(void *mem) { }

static struct xseg_peer xseg_peer_xsegdev = {
	/* xseg signal operations */
	{
		.signal_init = xsegdev_signal_init,
		.signal_quit = xsegdev_signal_quit,
		.prepare_wait = xsegdev_prepare_wait,
		.cancel_wait = xsegdev_cancel_wait,
		.wait_signal = xsegdev_wait_signal,
		.signal = xsegdev_signal,
		.malloc = xsegdev_malloc,
		.realloc = xsegdev_realloc,
		.mfree = xsegdev_mfree
	},
	/* name */
	"xsegdev"
};

void xseg_xsegdev_init(void)
{
	xseg_register_type(&xseg_xsegdev);
	xseg_register_peer(&xseg_peer_xsegdev);
}

