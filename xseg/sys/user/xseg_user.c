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
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <errno.h>
#include <sys/util.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <execinfo.h>
#include <sys/domain.h>
#include <xtypes/domain.h>
#include <xseg/domain.h>

#include <xtypes/xlock.h>

int (*xseg_snprintf)(char *str, size_t size, const char *format, ...) = snprintf;

char __xseg_errbuf[4096];

static struct xlock __lock = { .owner = Noone};

void __lock_domain(void)
{
	(void)xlock_acquire(&__lock, 1);
}

void __unlock_domain(void)
{
	xlock_release(&__lock);
}

void __load_plugin(const char *name)
{
	void *dl;
	void (*init)(void);
	char _name[128];
	unsigned int namelen = strlen(name);

	strncpy(_name, "xseg_", 5);
	strncpy(_name + 5, name, 80);
	strncpy(_name + 5 + namelen, ".so", 3);
	_name[5 + namelen + 3 ] = 0;
	dl = dlopen(_name, RTLD_NOW);
	if (!dl) {
		XSEGLOG("Cannot load plugin '%s': %s\n", _name, dlerror());
		return;
	}

	strncpy(_name + 5 + namelen, "_init", 5);
	_name[127] = 0;
	init = (void (*)(void))(long)dlsym(dl, _name);
	if (!init) {
		XSEGLOG("Init function '%s' not found!\n", _name);
		return;
	}

	init();
	//XSEGLOG("Plugin '%s' loaded.\n", name);
}

uint64_t __get_id(void)
{
	return (uint64_t)syscall(SYS_gettid);
}

void __xseg_log(const char *msg)
{
	(void)puts(msg);
	fflush(stdout);
}

void *xtypes_malloc(unsigned long size)
{
	return malloc(size);
}

void xtypes_free(void *ptr)
{
	free(ptr);
}

void __get_current_time(struct timeval *tv) {
	gettimeofday(tv, NULL);
}

int __renew_logctx(struct log_ctx *lc, char *peer_name,
		enum log_level log_level, char *logfile, uint32_t flags)
{
	int fd, tmp_fd;

	if (peer_name){
		strncpy(lc->peer_name, peer_name, MAX_PEER_NAME);
		lc->peer_name[MAX_PEER_NAME -1] = 0;
	}

	lc->log_level = log_level;
	if (logfile && logfile[0]) {
		strncpy(lc->filename, logfile, MAX_LOGFILE_LEN);
		lc->filename[MAX_LOGFILE_LEN - 1] = 0;
	}
	else if (!(flags & REOPEN_FILE) || lc->logfile == STDERR_FILENO)
		return 0;

	fd = open(lc->filename, O_WRONLY|O_CREAT|O_APPEND, S_IRUSR|S_IWUSR);
	if (fd < 1){
		return -1;
	}

	tmp_fd = lc->logfile;
	lc->logfile = fd;
	close(tmp_fd);

	flags &= ~REOPEN_FILE;
	if ((flags|lc->flags) & REDIRECT_STDOUT){
		fd = dup2(lc->logfile, STDOUT_FILENO);
		if (fd < 0)
			return -1;
	}
	if ((flags|lc->flags) & REDIRECT_STDERR){
		fd = dup2(lc->logfile, STDERR_FILENO);
		if (fd < 0)
			return -1;
	}
	lc->flags |= flags;

	return 0;
}
int (*renew_logctx)(struct log_ctx *lc, char *peer_name,
	enum log_level log_level, char *logfile, uint32_t flags) = __renew_logctx;

int __init_logctx(struct log_ctx *lc, char *peer_name,
		enum log_level log_level, char *logfile, uint32_t flags)
{
	int fd;

	if (peer_name){
		strncpy(lc->peer_name, peer_name, MAX_PEER_NAME);
		lc->peer_name[MAX_PEER_NAME -1] = 0;
	}
	else {
		return -1;
	}

	/* set logfile to stderr by default */
	lc->logfile = STDERR_FILENO;
#if 0
	/* duplicate stdout, stderr */
	fd = dup(STDOUT_FILENO);
	if (fd < 0){
		return -1;
	}
	lc->stdout_orig = fd;

	fd = dup(STDERR_FILENO);
	if (fd < 0){
		return -1;
	}
	lc->stderr_orig = fd;
#endif
	lc->log_level = log_level;
	if (!logfile || !logfile[0]) {
//		lc->logfile = lc->stderr_orig;
		return 0;
	}

	strncpy(lc->filename, logfile, MAX_LOGFILE_LEN);
	lc->filename[MAX_LOGFILE_LEN - 1] = 0;
	fd = open(lc->filename, O_WRONLY|O_CREAT|O_APPEND, S_IRUSR|S_IWUSR);
	if (fd < 1){
//		lc->logfile = lc->stderr_orig;
		return -1;
	}
	lc->logfile = fd;

	if (flags & REDIRECT_STDOUT){
		fd = dup2(lc->logfile, STDOUT_FILENO);
		if (fd < 0)
			return -1;
	}
	if (flags & REDIRECT_STDERR){
		fd = dup2(lc->logfile, STDERR_FILENO);
		if (fd < 0)
			return -1;
	}
	lc->flags = flags;

	return 0;
}
int (*init_logctx)(struct log_ctx *lc, char *peer_name,
	enum log_level log_level, char *logfile, uint32_t flags) = __init_logctx;

void __xseg_log2(struct log_ctx *lc, enum log_level level, char *fmt, ...)
{
	va_list ap;
	time_t timeval;	
	char timebuf[1024], buffer[4096];
	char *buf = buffer;
	char *t = NULL, *pn = NULL;
	ssize_t r, sum;
	size_t count;
	int fd;

	va_start(ap, fmt);
	switch (level) {
		case E: t = "XSEG[EE]"; break;
		case W: t = "XSEG[WW]"; break;
		case I: t = "XSEG[II]"; break;
		case D: t = "XSEG[DD]"; break;
		default: t = "XSEG[UNKNONW]"; break;
	}
	pn = lc->peer_name;
	if (!pn)
		pn = "Invalid peer name";

	time(&timeval);
	ctime_r(&timeval, timebuf);
	*strchr(timebuf, '\n') = '\0';

	buf += sprintf(buf, "%s: ", t);
	buf += snprintf(buf, MAX_PEER_NAME + 2, "%s: ", lc->peer_name);
	buf += sprintf(buf, "%s (%ld):\n\t", timebuf, timeval);
	unsigned long rem = sizeof(buffer) - (buf - buffer);
	buf += vsnprintf(buf, rem, fmt, ap);
	if (buf >= buffer + sizeof(buffer))
		buf = buffer + sizeof(buffer) - 2;/* enough to hold \n and \0 */
	buf += sprintf(buf, "\n");

	count = buf-buffer;
	sum = 0;
	r = 0;
	fd = *(volatile int *)&lc->logfile;
	do {
		r = write(fd, buffer + sum, count - sum);
		if (r < 0){
			if (errno == EBADF)
				fd = *(volatile int *)&lc->logfile;
			else {
				//XSEGLOG("Error while writing log");
				break;
			}
		} else {
			sum += r;
		}
	} while (sum < count);
	/* No need to check for error */
	//fsync(fd);
	va_end(ap);

	return;
}

/* FIXME: This is not async safe */
void xseg_printtrace(void)
{
	void *array[20];
	size_t size;

	XSEGLOG("Backtrace:");
	size = backtrace(array, 20);
	/* stderr should be open since we don't close it */
	backtrace_symbols_fd(array, size, 2);
}
