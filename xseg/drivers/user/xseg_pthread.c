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
#include <pthread.h>

#define ERRSIZE 512
char errbuf[ERRSIZE];

static long pthread_allocate(const char *name, uint64_t size)
{
	int fd, r;
	fd = shm_open(name, O_RDWR | O_CREAT, 0770);
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

static long pthread_deallocate(const char *name)
{
	return shm_unlink(name);
}

static void *pthread_map(const char *name, uint64_t size, struct xseg *seg)
{
	struct xseg *xseg;
	int fd;

	if (seg)
		XSEGLOG("struct xseg * is not NULL. Ignoring...\n");

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

static void pthread_unmap(void *ptr, uint64_t size)
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
static pthread_key_t pid_key, xpidx_key;
static pthread_once_t once_init = PTHREAD_ONCE_INIT;
static pthread_once_t once_quit = PTHREAD_ONCE_INIT;
static int isInit;

static void signal_init(void) 
{
	void (*h)(int);
	int r;
	h = signal(SIGIO, handler);
	if (h == SIG_ERR){
		isInit = 0;
		return;
	}

	sigemptyset(&set);
	sigaddset(&set, SIGIO);

	r = pthread_sigmask(SIG_BLOCK, &set, &savedset);
	if (r < 0) {
		isInit = 0;
		return;
	}
	
	r = pthread_key_create(&pid_key, NULL);
	if (r < 0) {
		isInit = 0;
		return;
	}
	
	r = pthread_key_create(&xpidx_key, NULL);
	if (r < 0) {
		isInit = 0;
		return;
	}
	isInit = 1;
	once_quit = PTHREAD_ONCE_INIT;
}

static void signal_quit(void) 
{
	pthread_key_delete(pid_key);
	pthread_key_delete(xpidx_key);
	signal(SIGIO, SIG_DFL);
	pthread_sigmask(SIG_SETMASK, &savedset, NULL);
	isInit = 0;
	once_init = PTHREAD_ONCE_INIT;
}

#define INT_TO_POINTER(__myptr, __myint) \
	do {\
		unsigned long __foo__ = (unsigned long) __myint; \
		__myptr = (void *) __foo__ ; \
	} while (0)

#define POINTER_TO_INT(__myint, __myptr)\
	do { \
		unsigned long __foo__ = (unsigned long) __myptr; \
		__myint = (int) __foo__ ; \
	} while (0)

/* must be called by each thread */
static int pthread_signal_init(void)
{
	int r;
	pid_t pid;
	void *tmp;
	pthread_once(&once_init, signal_init);
	if (!isInit)
		return -1;
	pid = syscall(SYS_gettid);
	INT_TO_POINTER(tmp, pid);
	r = pthread_setspecific(pid_key, tmp);
	return r;
}

/* can be called by each thread */
static void pthread_signal_quit(void)
{
	pthread_once(&once_quit, signal_quit);
}

static int pthread_prepare_wait(struct xseg *xseg, uint32_t portno)
{
	void * tmp;
	pid_t pid;
	xpool_index r;
	struct xseg_port *port = xseg_get_port(xseg, portno);
	if (!port) 
		return -1;

	tmp = pthread_getspecific(pid_key);
	POINTER_TO_INT(pid, tmp);
	if (!pid)
		return -1;

	r = xpool_add(&port->waiters, (xpool_index) pid, portno); 
	if (r == NoIndex)
		return -1;
	pthread_setspecific(xpidx_key, r);
	return 0;
}

static int pthread_cancel_wait(struct xseg *xseg, uint32_t portno)
{
	void * tmp;
	pid_t pid;
	xpool_data data;
	xpool_index xpidx, r;
	struct xseg_port *port = xseg_get_port(xseg, portno);
	if (!port) 
		return -1;
	
	tmp = pthread_getspecific(pid_key);
	POINTER_TO_INT(pid, tmp);
	if (!pid)
		return -1;

	xpidx = (xpool_index) pthread_getspecific(xpidx_key);

	r = xpool_remove(&port->waiters, xpidx, &data, portno);
	if (r == NoIndex)
		return -1;
	
	return 0;
}

static int pthread_wait_signal(struct xseg *xseg, uint32_t usec_timeout)
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

static int pthread_signal(struct xseg *xseg, uint32_t portno)
{
	xpool_data data;
	xpool_index idx;

	struct xseg_port *port = xseg_get_port(xseg, portno);
	if (!port) 
		return -1;

	idx = xpool_peek(&port->waiters, &data, portno); //FIXME portno is not the caller but the callee
	if (idx == NoIndex) 
		return -1;

	pid_t cue = (pid_t) data;
	if (!cue)
		return 0;

	return syscall(SYS_tkill, cue, SIGIO);
}

static void *pthread_malloc(uint64_t size)
{
	return malloc((size_t)size);
}

static void *pthread_realloc(void *mem, uint64_t size)
{
	return realloc(mem, (size_t)size);
}

static void pthread_mfree(void *mem)
{
	free(mem);
}

static struct xseg_type xseg_pthread = {
	/* xseg_operations */
	{
		.mfree		= pthread_mfree,
		.allocate	= pthread_allocate,
		.deallocate	= pthread_deallocate,
		.map		= pthread_map,
		.unmap		= pthread_unmap,
	},
	/* name */
	"pthread"
};

static struct xseg_peer xseg_peer_pthread = {
	/* xseg_peer_operations */
	{
		.signal_init	= pthread_signal_init,
		.signal_quit	= pthread_signal_quit,
		.prepare_wait	= pthread_prepare_wait,
		.cancel_wait	= pthread_cancel_wait,
		.wait_signal	= pthread_wait_signal,
		.signal		= pthread_signal,
		.malloc		= pthread_malloc,
		.realloc	= pthread_realloc,
		.mfree		= pthread_mfree,
	},
	/* name */
	"pthread"
};

void xseg_pthread_init(void)
{
	xseg_register_type(&xseg_pthread);
	xseg_register_peer(&xseg_peer_pthread);
}

