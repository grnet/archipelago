#ifndef _SYSUTIL_H
#define _SYSUTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <sys/domain.h>

#define REOPEN_FILE     (1 << 1)
#define REDIRECT_STDOUT (1 << 1)
#define REDIRECT_STDERR (1 << 2)


struct log_ctx {
	char filename[MAX_LOGFILE_LEN];
	FILE *logfile;
	char peer_name[MAX_PEER_NAME];
	unsigned int log_level;
	uint32_t flags;
};

#endif
