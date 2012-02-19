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

#define ERRSIZE 512
char errbuf[ERRSIZE];

static long posix_allocate(const char *name, uint64_t size)
{
	int fd, r;
	fd = shm_open(name, O_RDWR | O_CREAT, 0770);
	if (fd < 0) {
		LOGMSG("Cannot create shared segment: %s\n",
			strerror_r(errno, errbuf, ERRSIZE));
		return fd;
	}

	r = lseek(fd, size -1, SEEK_SET);
	if (r < 0) {
		close(fd);
		LOGMSG("Cannot seek into segment file: %s\n",
			strerror_r(errno, errbuf, ERRSIZE));
		return r;
	}

	errbuf[0] = 0;
	r = write(fd, errbuf, 1);
	if (r != 1) {
		close(fd);
		LOGMSG("Failed to set segment size: %s\n",
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

static void *posix_map(const char *name, uint64_t size)
{
	struct xseg *xseg;
	int fd;
	fd = shm_open(name, O_RDWR, 0000);
	if (fd < 0) {
		LOGMSG("Failed to open '%s' for mapping: %s\n",
			name, strerror_r(errno, errbuf, ERRSIZE));
		return NULL;
	}

	xseg = mmap (	XSEG_BASE_AS_PTR,
			size,
			PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_FIXED /* | MAP_LOCKED */,
			fd, 0	);

	if (xseg == MAP_FAILED) {
		LOGMSG("Could not map segment: %s\n",
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

static int posix_signal_init(void)
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

static void posix_signal_quit(void)
{
	signal(SIGIO, SIG_DFL);
	sigprocmask(SIG_SETMASK, &savedset, NULL);
}

static int posix_prepare_wait(struct xseg_port *port)
{
	port->waitcue = pid;
	return 0;
}

static int posix_cancel_wait(struct xseg_port *port)
{
	port->waitcue = 0;
	return 0;
}

static int posix_wait_signal(struct xseg_port *port, uint32_t usec_timeout)
{
	int r;
	siginfo_t siginfo;
	struct timespec ts;

	ts.tv_sec = usec_timeout / 1000000;
	ts.tv_nsec = 1000 * (usec_timeout - ts.tv_sec * 1000000);

	r = sigtimedwait(&set, &siginfo, &ts);
	if (r < 0)
		return r;

	return siginfo.si_signo;
}

static int posix_signal(struct xseg_port *port)
{
	union sigval sigval = {0};
	pid_t cue = (pid_t)port->waitcue;
	if (!cue)
		return 0;
	sigqueue(cue, SIGIO, sigval);
	/* XXX: on error what? */
	return 1;
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

static struct xseg_type xseg_posix = {
	/* xseg_operations */
	{
		.malloc		= posix_malloc,
		.realloc	= posix_realloc,
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
		.signal_init	= posix_signal_init,
		.signal_quit	= posix_signal_quit,
		.prepare_wait	= posix_prepare_wait,
		.cancel_wait	= posix_cancel_wait,
		.wait_signal	= posix_wait_signal,
		.signal		= posix_signal,
		.malloc		= posix_malloc,
		.realloc	= posix_realloc,
		.mfree		= posix_mfree,
	},
	/* name */
	"posix"
};

void xseg_posix_init(void)
{
	xseg_register_type(&xseg_posix);
	xseg_register_peer(&xseg_peer_posix);
}

