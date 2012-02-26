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

