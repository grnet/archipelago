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
#include <pthread.h>
#include <drivers/xseg_pthread.h>
#define ERRSIZE 512
char errbuf[ERRSIZE];

static void *pthread_malloc(uint64_t size);
static void pthread_mfree(void *mem);

static long pthread_allocate(const char *name, uint64_t size)
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

static pthread_key_t pid_key, xpidx_key;
static pthread_key_t mask_key, act_key;
static pthread_key_t id_key;
static pthread_once_t once_init = PTHREAD_ONCE_INIT;
static pthread_once_t once_quit = PTHREAD_ONCE_INIT;
static int isInit;
static volatile int id = 0;

static void keys_init(void)
{
	int r;

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
	r = pthread_key_create(&mask_key, NULL);
	if (r < 0) {
		isInit = 0;
		return;
	}

	r = pthread_key_create(&act_key, NULL);
	if (r < 0) {
		isInit = 0;
		return;
	}
	r = pthread_key_create(&id_key, NULL);
	if (r < 0) {
		isInit = 0;
		return;
	}
	isInit = 1;
	once_quit = PTHREAD_ONCE_INIT;
}

#define INT_TO_POINTER(__myptr, __myint) \
	do {\
		unsigned long __foo____myptr = (unsigned long) __myint; \
		__myptr = (void *) __foo____myptr ; \
	} while (0)

#define POINTER_TO_INT(__myint, __myptr)\
	do { \
		unsigned long __foo____myint = (unsigned long) __myptr; \
		__myint = (int) __foo____myint ; \
	} while (0)

/* must be called by each thread */
static int pthread_local_signal_init(struct xseg *xseg, xport portno)
{
	int r, my_id;
	pid_t pid;
	void *tmp, *tmp2;
	sigset_t *savedset, *set;
	struct sigaction *act, *old_act;

	savedset = pthread_malloc(sizeof(sigset_t));
	if (!savedset)
		goto err1;
	set = pthread_malloc(sizeof(sigset_t));
	if (!set)
		goto err2;

	act = pthread_malloc(sizeof(struct sigaction));
	if (!act)
		goto err3;
	old_act = pthread_malloc(sizeof(struct sigaction));
	if (!old_act)
		goto err4;

	pthread_once(&once_init, keys_init);
	if (!isInit)
		goto err5;

	sigemptyset(set);
	act->sa_handler = handler;
	act->sa_mask = *set;
	act->sa_flags = 0;
	if(sigaction(SIGIO, act, old_act) < 0)
		goto err5;

	
	sigaddset(set, SIGIO);

	r = pthread_sigmask(SIG_BLOCK, set, savedset);
	if (r < 0) 
		goto err6;


	my_id = *(volatile int *) &id;
	while (!__sync_bool_compare_and_swap(&id, my_id, my_id+1)){
		my_id = *(volatile int *) &id;
	}
	pid = syscall(SYS_gettid);
	INT_TO_POINTER(tmp, pid);
	INT_TO_POINTER(tmp2, my_id);
	if (pthread_setspecific(pid_key, tmp) ||
			pthread_setspecific(mask_key, savedset) ||
			pthread_setspecific(act_key, old_act) ||
			pthread_setspecific(id_key, tmp2))
		goto err7;

	return 0;

err7:
	pthread_sigmask(SIG_BLOCK, savedset, NULL);
err6:
	sigaction(SIGIO, old_act, NULL);
err5:
	pthread_mfree(old_act);
err4:
	pthread_mfree(act);
err3:
	pthread_mfree(set);
err2:
	pthread_mfree(savedset);
err1:
	return -1;
}

/* should be called by each thread which had initialized signals */
static void pthread_local_signal_quit(struct xseg *xseg, xport portno)
{
	sigset_t *savedset;
	struct sigaction *old_act;

	savedset = pthread_getspecific(act_key);
	old_act = pthread_getspecific(mask_key);
	if (old_act)
		sigaction(SIGIO, old_act, NULL);
	if (savedset)
		pthread_sigmask(SIG_SETMASK, savedset, NULL);
}

static int pthread_remote_signal_init(void)
{
	return 0;
}

static void pthread_remote_signal_quit(void)
{
	return;
}

static int pthread_prepare_wait(struct xseg *xseg, uint32_t portno)
{
	void * tmp;
	pid_t pid;
	int my_id;
	struct xseg_port *port = xseg_get_port(xseg, portno);
	if (!port) 
		return -1;
	struct pthread_signal_desc *psd = xseg_get_signal_desc(xseg, port);
	if (!psd)
		return -1;

	tmp = pthread_getspecific(pid_key);
	POINTER_TO_INT(pid, tmp);
	if (!pid)
		return -1;
	tmp = pthread_getspecific(id_key);
	POINTER_TO_INT(my_id, tmp);
	psd->pids[my_id] = pid;
	return 0;
}

static int pthread_cancel_wait(struct xseg *xseg, uint32_t portno)
{
	void * tmp;
	int my_id;
	pid_t pid;
	struct xseg_port *port = xseg_get_port(xseg, portno);
	if (!port)
		return -1;
	struct pthread_signal_desc *psd = xseg_get_signal_desc(xseg, port);
	if (!psd)
		return -1;

	tmp = pthread_getspecific(pid_key);
	POINTER_TO_INT(pid, tmp);
	if (!pid)
		return -1;

	tmp = pthread_getspecific(id_key);
	POINTER_TO_INT(my_id, tmp);
	psd->pids[my_id] = 0;

	return 0;
}

static int pthread_wait_signal(struct xseg *xseg, void *sd, uint32_t usec_timeout)
{
	int r;
	siginfo_t siginfo;
	struct timespec ts;
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGIO);

	ts.tv_sec = usec_timeout / 1000000;
	ts.tv_nsec = 1000 * (usec_timeout - ts.tv_sec * 1000000);

	r = sigtimedwait(&set, &siginfo, &ts);
	if (r < 0)
		return r;

	return siginfo.si_signo;
}

static int pthread_signal(struct xseg *xseg, uint32_t portno)
{
	int i;

	struct xseg_port *port = xseg_get_port(xseg, portno);
	if (!port) 
		return -1;
	struct pthread_signal_desc *psd = xseg_get_signal_desc(xseg, port);
	if (!psd)
		return -1;

	pid_t cue;
	for (i = 0; i < MAX_WAITERS; i++) {
		cue = psd->pids[i];
		if (cue)
			return syscall(SYS_tkill, cue, SIGIO);
	}

	/* no waiter found */
	return 0;
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

int pthread_init_signal_desc(struct xseg *xseg, void *sd)
{
	int i;
	struct pthread_signal_desc *psd = (struct pthread_signal_desc *)sd;
	for (i = 0; i < MAX_WAITERS; i++) {
		psd->pids[i]=0;
	}
	return 0;
}

void pthread_quit_signal_desc(struct xseg *xseg, void *sd)
{
	int i;
	struct pthread_signal_desc *psd = (struct pthread_signal_desc *)sd;
	for (i = 0; i < MAX_WAITERS; i++) {
		psd->pids[i]=0;
	}
	return;
}

void * pthread_alloc_data(struct xseg *xseg)
{
	struct xobject_h *sd_h = xseg_get_objh(xseg, MAGIC_PTHREAD_SD,
				sizeof(struct pthread_signal_desc));
	return sd_h;
}

void pthread_free_data(struct xseg *xseg, void *data)
{
	if (data)
		xseg_put_objh(xseg, (struct xobject_h *)data);
}

void *pthread_alloc_signal_desc(struct xseg *xseg, void *data)
{
	struct xobject_h *sd_h = (struct xobject_h *) data;
	if (!sd_h)
		return NULL;
	struct pthread_signal_desc *psd = xobj_get_obj(sd_h, X_ALLOC);
	if (!psd)
		return NULL;
	return psd;

}

void pthread_free_signal_desc(struct xseg *xseg, void *data, void *sd)
{
	struct xobject_h *sd_h = (struct xobject_h *) data;
	if (!sd_h)
		return;
	if (sd)
		xobj_put_obj(sd_h, sd);
	return;
}


static struct xseg_peer xseg_peer_pthread = {
	/* xseg_peer_operations */
	{
		.init_signal_desc   = pthread_init_signal_desc,
		.quit_signal_desc   = pthread_quit_signal_desc,
		.alloc_data         = pthread_alloc_data,
		.free_data          = pthread_free_data,
		.alloc_signal_desc  = pthread_alloc_signal_desc,
		.free_signal_desc   = pthread_free_signal_desc,
		.local_signal_init  = pthread_local_signal_init,
		.local_signal_quit  = pthread_local_signal_quit,
		.remote_signal_init = pthread_remote_signal_init,
		.remote_signal_quit = pthread_remote_signal_quit,
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

