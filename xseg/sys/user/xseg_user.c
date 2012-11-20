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
#include <sys/time.h>

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
	FILE *file;

	if (peer_name){
		strncpy(lc->peer_name, peer_name, MAX_PEER_NAME);
		lc->peer_name[MAX_PEER_NAME -1] = 0;
	}

	lc->log_level = log_level;
	if (logfile) {
		strncpy(lc->filename, logfile, MAX_LOGFILE_LEN);
		lc->filename[MAX_LOGFILE_LEN - 1] = 0;
	}
	else if (!(flags & REOPEN_FILE) || lc->logfile == stderr)
		return 0;

	if (lc->logfile == stderr)
		file = fopen(lc->filename, "a");
	else
		file = freopen(lc->filename, "a", lc->logfile);
	if (!file) {
		return -1;
	}

	flags &= ~REOPEN_FILE;
	if ((flags|lc->flags) & REDIRECT_STDOUT)
		if (!freopen(lc->filename, "a", stdout))
			return -1;
	if ((flags|lc->flags) & REDIRECT_STDERR)
		if (!freopen(lc->filename, "a", stderr))
			return -1;
	lc->flags |= flags;

	return 0;
}
int (*renew_logctx)(struct log_ctx *lc, char *peer_name,
	enum log_level log_level, char *logfile, uint32_t flags) = __renew_logctx;

int __init_logctx(struct log_ctx *lc, char *peer_name,
		enum log_level log_level, char *logfile, uint32_t flags)
{
	FILE *file;

	if (peer_name){
		strncpy(lc->peer_name, peer_name, MAX_PEER_NAME);
		lc->peer_name[MAX_PEER_NAME -1] = 0;
	}
	else {
		return -1;
	}

	lc->log_level = log_level;
	if (!logfile) {
		lc->logfile = stderr;
		return 0;
	}

	strncpy(lc->filename, logfile, MAX_LOGFILE_LEN);
	lc->filename[MAX_LOGFILE_LEN - 1] = 0;
	file = fopen(lc->filename, "a");
	if (!file) {
		lc->logfile = stderr;
		return -1;
	}
	lc->logfile = file;

	if (flags & REDIRECT_STDOUT)
		if (!freopen(lc->filename, "a", stdout))
			return -1;
	if (flags & REDIRECT_STDERR)
		if (!freopen(lc->filename, "a", stderr))
			return -1;
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

	fprintf(lc->logfile, "%s", buffer);
	fflush(lc->logfile);
	va_end(ap);

	return;
}

void xseg_printtrace(void)
{
	void *array[10];
	size_t size;
	char **strings;
	int i;

	size = backtrace (array, 10);
	strings = backtrace_symbols (array, size);

	XSEGLOG("Obtained %zd stack frames.\n", size);

	for (i = 0; i < size; i++)
		XSEGLOG ("%s\n", strings[i]);

	free (strings);
}
