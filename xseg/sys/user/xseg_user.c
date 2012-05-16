#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <errno.h>
#include <sys/util.h>
#include <sys/time.h>

#include <sys/domain.h>
#include <xq/domain.h>
#include <xseg/domain.h>

#include <xq/xq_lock.h>

int (*xseg_snprintf)(char *str, size_t size, const char *format, ...) = snprintf;

char __xseg_errbuf[4096];

static struct xq_lock __lock;

void __lock_domain(void)
{
	(void)xq_acquire(&__lock, 1);
}

void __unlock_domain(void)
{
	xq_release(&__lock);
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
}

void *xq_malloc(unsigned long size)
{
	return malloc(size);
}

void xq_mfree(void *ptr)
{
	free(ptr);
}

void __get_current_time(struct timeval *tv) {
	gettimeofday(tv, NULL);
}

