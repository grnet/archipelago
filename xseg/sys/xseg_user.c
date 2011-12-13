#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <errno.h>
#include <sys/util.h>

int (*xseg_snprintf)(char *str, size_t size, const char *format, ...) = snprintf;

char __xseg_errbuf[4096];

void __load_plugin(const char *name)
{
	void *dl;
	void (*init)(void);
	char _name[128];
        unsigned int namesize = strlen(name);

        strncpy(_name, "xseg_", 5);
	strncpy(_name + 5, name, 80);
        strncpy(_name + 5 + namesize, ".so", 3);
	_name[5 + namesize + 3 ] = 0;
	dl = dlopen(_name, RTLD_NOW);
	if (!dl) {
		LOGMSG("Cannot load plugin '%s': %s\n", _name, dlerror());
		return;
	}

	strncpy(_name + 5 + namesize, "_init", 5);
	_name[127] = 0;
	init = (void (*)(void))(long)dlsym(dl, _name);
	if (!init) {
		LOGMSG("Init function '%s' not found!\n", _name);
		return;
	}

	init();
	//LOGMSG("Plugin '%s' loaded.\n", name);
}

uint32_t __get_id(void)
{
	return syscall(SYS_gettid);
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
