#ifndef _SYSUTIL_H
#define _SYSUTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

struct log_ctx {
	FILE *logfile;
	char *peer_name;
	unsigned int log_level; 
};

#endif
