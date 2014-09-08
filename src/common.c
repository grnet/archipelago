/*
Copyright (C) 2010-2014 GRNET S.A.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* 
 *
 * vkoukis.c
 *
 * Some commonly used functions
 */

#define _GNU_SOURCE

#include "pthread.h"

#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>

#include <sys/time.h>
#include <sys/types.h>

#include "common.h"

static char *perr_prog_name = NULL;

/*
 * perr_func:		Main error reporting function
 */
void perr_func(enum perr_type type, int want_errno, char *fmt, ...)
{
	va_list ap;
	time_t timeval;
	int err_number = errno;		/* We need errno NOW */
	char buf[PERR_BUF_SIZE], errbuf[PERR_BUF_SIZE], timebuf[PERR_BUF_SIZE];
	char *t = NULL, *p = buf;

	va_start(ap, fmt);
	switch (type) {
		case PFE: t = "Fatal error"; break;
		case PE: t = "Error"; break;
		case PW: t = "Warning"; break;
		case PI: t = "Info"; break;
		case PD: t = "Debug"; break;
		default: raise(SIGABRT);
	}
	if (!perr_prog_name) {
		perr_prog_name = "Internal perr error";
		perr(1, 0, "init_perr has not been called");
	}

	time(&timeval);
	ctime_r(&timeval, timebuf);
	*strchr(timebuf, '\n') = '\0';

	p += sprintf(p, "%s: %s: ", perr_prog_name, t);
	p += sprintf(p, "Thread %lu, PID %lu\n\t",
			(unsigned long)pthread_self(), (unsigned long)getpid());

	p += sprintf(p, "%s (%ld):\n\t", timebuf, timeval);

	p += vsprintf(p, fmt, ap);
	p += sprintf(p, "\n");

	if (want_errno == 1)
		/* Print last error returned from system call */
		p += sprintf(p, "\tErrno was: %d - %s\n",
				err_number, strerror_r(err_number, errbuf, PERR_BUF_SIZE));

	/*
	 * Output the buffer to stderr with a single call to fprintf,
	 * which is thread-safe and locks the stderr semaphore
	 */
	fprintf(stderr, "%s", buf);
	fflush(stderr);
	va_end(ap);

	if (type > 0)
		exit(1);
}

void init_perr(char *prog_name)
{
	perr_prog_name = prog_name;
}

/*
 * Adapted from FreeBSD source:
 *
 * Appends src to string dst of size siz (unlike strncat, siz is the
 * full size of dst, not space left).  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz <= strlen(dst)).
 * Returns strlen(src) + MIN(siz, strlen(initial dst)).
 * If retval >= siz, truncation occurred.
 */
size_t strlcat(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;
	size_t dlen;

	/* Find the end of dst and adjust bytes left but don't go past end */
	while (n-- != 0 && *d != '\0')
		d++;
	dlen = d - dst;
	n = siz - dlen;

	if (n == 0)
		return(dlen + strlen(s));
	while (*s != '\0') {
		if (n != 1) {
			*d++ = *s;
			n--;
		}
		s++;
	}
	*d = '\0';

	return (dlen + (s - src));	/* count does not include NUL */
}

/*
 * Adapted from FreeBSD source:
 *
 * Copy src to string dst of size siz.  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz == 0).
 * Returns strlen(src); if retval >= siz, truncation occurred.
 */
size_t strlcpy(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;

	/* Copy as many bytes as will fit */
	if (n != 0 && --n != 0) {
		do {
			if ((*d++ = *s++) == 0)
				break;
		} while (--n != 0);
	}

	/* Not enough room in dst, add NUL and traverse rest of src */
	if (n == 0) {
		if (siz != 0)
			*d = '\0';		/* NUL-terminate dst */
		while (*s++)
			;
	}

	return (s - src - 1);	/* count does not include NUL */
}

