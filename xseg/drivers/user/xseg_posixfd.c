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
#include <sys/time.h>
#include <sys/select.h>
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
#include <drivers/xseg_posixfd.h>
#define ERRSIZE 512
char errbuf[ERRSIZE];

static long posixfd_allocate(const char *name, uint64_t size)
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

static long posixfd_deallocate(const char *name)
{
	return shm_unlink(name);
}

static void *posixfd_map(const char *name, uint64_t size, struct xseg *seg)
{
	struct xseg *xseg;
	int fd;

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

static void posixfd_unmap(void *ptr, uint64_t size)
{
	struct xseg *xseg = ptr;
	(void)munmap(xseg, xseg->segment_size);
}

static struct posixfd_signal_desc * __get_signal_desc(struct xseg *xseg, xport portno)
{
	struct xseg_port *port = xseg_get_port(xseg, portno);
	if (!port)
		return NULL;
	struct posixfd_signal_desc *psd = xseg_get_signal_desc(xseg, port);
	if (!psd)
		return NULL;
	return psd;
}

static void __get_filename(struct posixfd_signal_desc *psd, char *filename)
{
	int pos = 0;
	strncpy(filename+pos, POSIXFD_DIR, POSIXFD_DIR_LEN);
	pos += POSIXFD_DIR_LEN;
	strncpy(filename + pos, psd->signal_file, POSIXFD_FILENAME_LEN);
	pos += POSIXFD_FILENAME_LEN;
	filename[pos] = 0;
}

/*
 * In order to be able to accept signals we must:
 *
 * a) Create the name piped for our signal descriptor.
 * b) Open the named pipe and get an fd.
 */
static int posixfd_local_signal_init(struct xseg *xseg, xport portno)
{
	/* create or truncate POSIXFD+portno file */
	int r, fd;
	char filename[POSIXFD_DIR_LEN + POSIXFD_FILENAME_LEN + 1];

	struct posixfd_signal_desc *psd = __get_signal_desc(xseg, portno);
	if (!psd) {
		return -1;
	}
	__get_filename(psd, filename);

retry:
	r = mkfifo(filename, S_IRUSR|S_IWUSR);
	if (r < 0) {
		if (errno == EEXIST) {
			unlink(filename);
			goto retry;
		}
		return -1;
	}

	fd = open(filename, O_RDONLY | O_NONBLOCK);
	if (fd < 0) {
		unlink(filename);
		return -1;
	}
	psd->fd = fd;
	open(filename, O_WRONLY | O_NONBLOCK);

	return 0;
}

/*
 * To clean up after our signal initialiazation, we should:
 *
 * a) close the open fd for our named pipe
 * b) unlink the named pipe from the file system.
 */
static void posixfd_local_signal_quit(struct xseg *xseg, xport portno)
{
	char filename[POSIXFD_DIR_LEN + POSIXFD_FILENAME_LEN + 1];
	struct posixfd_signal_desc *psd = __get_signal_desc(xseg, portno);
	if (psd->fd >=0) {
		close(psd->fd);
		psd->fd = -1;
	}
	__get_filename(psd, filename);
	unlink(filename);
	return;
}

/*
 * When this peer type is initialized, we must make sure the directory where the
 * named pipes will be created, exist.
 */
static int posixfd_remote_signal_init(void)
{
	int r;
	r = mkdir(POSIXFD_DIR, 01755);

	if (r < 0) {
		if (errno != EEXIST) // && isdir(POSIXFD_DIR)
			return -1;
	}

	return 0;
}

static void posixfd_remote_signal_quit(void)
{
	return;
}

static int posixfd_prepare_wait(struct xseg *xseg, uint32_t portno)
{
	char buf[512];
	int buf_size = 512;
	struct posixfd_signal_desc *psd = __get_signal_desc(xseg, portno);
	if (!psd)
		return -1;
	psd->flag = 1;
	while (read(psd->fd, buf, buf_size) > 0);

	return 0;
}

static int posixfd_cancel_wait(struct xseg *xseg, uint32_t portno)
{
	char buf[512];
	int buf_size = 512;
	struct posixfd_signal_desc *psd = __get_signal_desc(xseg, portno);
	if (!psd)
		return -1;
	psd->flag = 0;
	while (read(psd->fd, buf, buf_size) > 0);

	return 0;
}

/*
 * To wait a signal, the posixfd peer must use select on the fd of its named
 * pipe.
 *
 * When the peer wakes up from the select, if it wasn't waked up because of a
 * timeout, it should read as much as it can from the named pipe to clean it and
 * prepare it for the next select.
 */
static int posixfd_wait_signal(struct xseg *xseg, void *sd, uint32_t usec_timeout)
{
	int r;
	struct timeval tv;
	char buf[512];
	int buf_size = 512;
	fd_set fds;

	struct posixfd_signal_desc *psd = (struct posixfd_signal_desc *)sd;
	if (!psd)
		return -1;

	tv.tv_sec = usec_timeout / 1000000;
	tv.tv_usec = usec_timeout - tv.tv_sec * 1000000;

	FD_ZERO(&fds);
	FD_SET(psd->fd, &fds);

	r = select(psd->fd + 1, &fds, NULL, NULL, &tv);
	//XSEGLOG("Tv sec: %ld, tv_usec: %ld", tv.tv_sec, tv.tv_usec);

	if (r < 0) {
		if (errno != EINTR) {
			return -1;
		} else {
			return 0;
		}
	}

	if (r != 0) {
		/* clean up pipe */
		while (read(psd->fd, buf, buf_size) > 0);
	}

	return 0;
}

/*
 * To signal a posixfd peer, we must:
 *
 * a) Check if the peer wants to be signaled.
 * b) Open the named pipe, it provides.
 * c) Write some data to the named pipe, so the peer's fd will be selectable for
 *    writing.
 * d) Close the named pipe.
 */
static int posixfd_signal(struct xseg *xseg, uint32_t portno)
{
	int r, fd;
	/* NULL terminated */
	char filename[POSIXFD_DIR_LEN + POSIXFD_FILENAME_LEN + 1] = POSIXFD_DIR;

	struct posixfd_signal_desc *psd = __get_signal_desc(xseg, portno);
	if (!psd)
		return -1;

	if (!psd->flag) {
		/* If the peer advises not to signal, we respect it. */
		return 0;
	}
	__get_filename(psd, filename);

	fd = open(filename, O_WRONLY|O_NONBLOCK);
	if (fd < 0) {
		return -1;
	}
	r = write(fd, "a", 1);
	if (r < 0) {
		close(fd);
		return -1;
	}
	/* FIXME what here? */
	r = close(fd);

	return 0;
}

static void *posixfd_malloc(uint64_t size)
{
	return malloc((size_t)size);
}

static void *posixfd_realloc(void *mem, uint64_t size)
{
	return realloc(mem, (size_t)size);
}

static void posixfd_mfree(void *mem)
{
	free(mem);
}

/* taken from user/hash.c */
static char get_hex(unsigned int h)
{
	switch (h)
	{
		case 0:
		case 1:
		case 2:
		case 3:
		case 4:
		case 5:
		case 6:
		case 7:
		case 8:
		case 9:
			return h + '0';
		case 10:
			return 'a';
		case 11:
			return 'b';
		case 12:
			return 'c';
		case 13:
			return 'd';
		case 14:
			return 'e';
		case 15:
			return 'f';
	}
	/* not reachable */
	return '0';
}

static void hexlify(unsigned char *data, long datalen, char *hex)
{
	long i;
	for (i=0; i<datalen; i++){
		hex[2*i] = get_hex((data[i] & 0xF0) >> 4);
		hex[2*i + 1] = get_hex(data[i] & 0x0F);
	}
}



int posixfd_init_signal_desc(struct xseg *xseg, void *sd)
{
	struct posixfd_signal_desc *psd = sd;
	if (!psd)
		return -1;
	psd->flag = 0;
	psd->signal_file[0] = 0;
	hexlify(&sd, POSIXFD_FILENAME_LEN, psd->signal_file);
	psd->fd = -1;

	return 0;
}

void posixfd_quit_signal_desc(struct xseg *xseg, void *sd)
{
	return;
}

void * posixfd_alloc_data(struct xseg *xseg)
{
	struct xobject_h *sd_h = xseg_get_objh(xseg, MAGIC_POSIX_SD,
			sizeof(struct posixfd_signal_desc));
	return sd_h;
}

void posixfd_free_data(struct xseg *xseg, void *data)
{
	if (data)
		xseg_put_objh(xseg, (struct xobject_h *)data);
}

void *posixfd_alloc_signal_desc(struct xseg *xseg, void *data)
{
	struct xobject_h *sd_h = (struct xobject_h *) data;
	if (!sd_h)
		return NULL;
	struct posixfd_signal_desc *psd = xobj_get_obj(sd_h, X_ALLOC);
	if (!psd)
		return NULL;
	return psd;

}

void posixfd_free_signal_desc(struct xseg *xseg, void *data, void *sd)
{
	struct xobject_h *sd_h = (struct xobject_h *) data;
	if (!sd_h)
		return;
	if (sd)
		xobj_put_obj(sd_h, sd);
	return;
}

static struct xseg_type xseg_posixfd = {
	/* xseg_operations */
	{
		.mfree		= posixfd_mfree,
		.allocate	= posixfd_allocate,
		.deallocate	= posixfd_deallocate,
		.map		= posixfd_map,
		.unmap		= posixfd_unmap,
	},
	/* name */
	"posixfd"
};

static struct xseg_peer xseg_peer_posixfd = {
	/* xseg_peer_operations */
	{
		.init_signal_desc   = posixfd_init_signal_desc,
		.quit_signal_desc   = posixfd_quit_signal_desc,
		.alloc_data         = posixfd_alloc_data,
		.free_data          = posixfd_free_data,
		.alloc_signal_desc  = posixfd_alloc_signal_desc,
		.free_signal_desc   = posixfd_free_signal_desc,
		.local_signal_init  = posixfd_local_signal_init,
		.local_signal_quit  = posixfd_local_signal_quit,
		.remote_signal_init = posixfd_remote_signal_init,
		.remote_signal_quit = posixfd_remote_signal_quit,
		.prepare_wait	    = posixfd_prepare_wait,
		.cancel_wait	    = posixfd_cancel_wait,
		.wait_signal	    = posixfd_wait_signal,
		.signal		    = posixfd_signal,
		.malloc		    = posixfd_malloc,
		.realloc 	    = posixfd_realloc,
		.mfree		    = posixfd_mfree,
	},
	/* name */
	"posixfd"
};

void xseg_posixfd_init(void)
{
	xseg_register_type(&xseg_posixfd);
	xseg_register_peer(&xseg_peer_posixfd);
}

