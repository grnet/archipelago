#ifndef _SYSUTIL_H
#define _SYSUTIL_H

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/time.h>

struct log_ctx {
	void *logfile;
	char *peer_name;
	unsigned int log_level; 
};

#endif
