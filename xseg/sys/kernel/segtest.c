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

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "segdev.h"

int fail(const char *msg)
{
	perror(msg);
	return 1;
}

int main(int argc, char **argv)
{
	int fd;
	char *segment;
	unsigned long i;
	long segsize, oldsize;

	if (argc < 2) {
		printf("Usage: ./segtest <segsize in kB>\n");
		return 1;
	}

	segsize = atol(argv[1]) * 1024;
	if (segsize < 0)
		segsize = -segsize;

	fd = open("/dev/segdev", O_RDWR);
	if (fd < 0)
		return fail("/dev/segdev");

	oldsize = ioctl(fd, SEGDEV_IOC_SEGSIZE, 0);
	if (oldsize < 0) {

		printf("No segment found. Creating...\n");
	
		if (ioctl(fd, SEGDEV_IOC_CREATESEG, segsize))
			return fail("CREATESEG");

	} else if (segsize != oldsize) {

		printf("Destroying old segment...\n");

		if (ioctl(fd, SEGDEV_IOC_DESTROYSEG, 0))
			return fail("DESTROYSEG");

		if (ioctl(fd, SEGDEV_IOC_CREATESEG, segsize))
			return fail("CREATESEG");
	}

	segment = mmap( NULL, segsize,
			PROT_READ | PROT_WRITE,
			MAP_SHARED, fd, 0 );
	close(fd);

	if (segment == MAP_FAILED)
		return fail("mmap");

	for (i = 0; i < segsize; i++)
		segment[i] = (char)(i & 0xff);

	for (i = 0; i < segsize; i++)
		if (segment[i] != (char)(i & 0xff))
			printf("%lu: %d vs %ld\n", i, segment[i], (i & 0xff));
	return 0;
}

