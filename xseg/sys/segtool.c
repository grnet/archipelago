#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "xsegdev.h"

int help(void)
{
	printf("segtool [<command> <arg>]* \n"
		"commands:\n"
		"    create <size_in_bytes>\n"
		"    destroy\n"
		"    info\n"
		"    map <offset> <size_in_bytes>\n"
		"    unmap <size_in_bytes>\n"
		"    dump <offset> <size_in_bytes>\n"
		"    load <offset>\n"
		"    fill <offset> <size_in_bytes> <char_in_hex>\n"
		"    mark\n"
		"    checkmark\n"
		"    wait\n"
	);
	return 1;
}

#define ALLOC_MIN 4096
#define ALLOC_MAX 1048576

void inputbuf(FILE *fp, char **retbuf, uint64_t *retsize)
{
	static uint64_t alloc_size;
	static char *buf;
	uint64_t size = 0;
	char *p;
	size_t r;

	if (alloc_size < ALLOC_MIN)
		alloc_size = ALLOC_MIN;

	if (alloc_size > ALLOC_MAX)
		alloc_size = ALLOC_MAX;

	p = realloc(buf, alloc_size);
	if (!p) {
		if (buf)
			free(buf);
		buf = NULL;
		goto out;
	}

	buf = p;

	while (!feof(fp)) {
		r = fread(buf + size, 1, alloc_size - size, fp);
		if (!r)
			break;
		size += r;
		if (size >= alloc_size) {
			p = realloc(buf, alloc_size * 2);
			if (!p) {
				if (buf)
					free(buf);
				buf = NULL;
				size = 0;
				goto out;
			}
			buf = p;
			alloc_size *= 2;
		}
	}

out:
	*retbuf = buf;
	*retsize = size;
}

static int opendev(void)
{
	int fd = open("/dev/xsegdev", O_RDWR);
	if (fd < 0)
		perror("/dev/xsegdev");
	return fd;
}

static char *segment;
static unsigned long mapped_size;

int cmd_create(uint64_t size)
{
	int r, fd = opendev();
	if (fd < 0)
		return fd;

	r = ioctl(fd, XSEGDEV_IOC_CREATESEG, size);
	if (r < 0)
		perror("CREATESEG");

	close(fd);
	return 0;
}

int cmd_destroy(void)
{
	int r, fd = opendev();
	if (fd < 0)
		return fd;

	r = ioctl(fd, XSEGDEV_IOC_DESTROYSEG, 0);
	if (r < 0)
		perror("DESTROYSEG");

	close(fd);
	return 0;
}

int cmd_info(void)
{
	long r, fd = opendev();
	if (fd < 0)
		return fd;

	r = ioctl(fd, XSEGDEV_IOC_SEGSIZE, 0);
	if (r < 0)
		perror("SEGSIZE");
	else
		printf("Segment size: %lu bytes\n", r);
	close(fd);
	return 0;
}

int cmd_map(uint64_t offset, uint64_t size)
{
	char *seg;
	long r = -1, fd = opendev();
	if (fd < 0)
		goto out;

	r = 0;
	if (segment)
		goto out;

	if (!size) {
		r = ioctl(fd, XSEGDEV_IOC_SEGSIZE, 0);
		if (r < 0) {
			perror("SEGSIZE");
			goto out;
		}
		size = r - offset;
	}

	if (offset + size > r) {
		printf("segment size would be exceeded\n");
		goto out;
	}

	r = -1;
	//seg = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset);
	seg = mmap( (void*) 0x37fd0000, size,
			PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_FIXED,
			fd, offset);
	if (seg == MAP_FAILED) {
		perror("mmap");
		goto out;
	}

	segment = seg;
	mapped_size = size;
out:
	close(fd);
	return r;
}

int cmd_unmap(uint64_t size)
{
	long r = -1, fd = opendev();
	if (fd < 0)
		goto out;

	r = 0;
	if (!segment)
		goto out;

	if (!size)
		size = mapped_size;

	r = munmap(segment, size);
	if (r < 0)
		perror("munmap");
	else {
		segment = NULL;
		mapped_size = 0;
	}

out:
	close(fd);
	return r;
}

int cmd_wait(void)
{
	int c, fd = open("/dev/tty", O_RDONLY);
	c = read(fd, &c, 1);
	close(fd);
	return 0;
}

int cmd_dump(uint64_t offset, uint64_t size)
{
	long r = -1, fd = opendev();
	if (fd < 0)
		goto out;

	if (!segment) {
		printf("segment not mapped\n");
		goto out;
	}

	if (!size)
		size = mapped_size - offset;

	if (offset + size > mapped_size) {
		printf("mapped segment size would be exceeded\n");
		goto out;
	}

	for (r = offset; r < offset + size; r++)
		if (fputc(segment[r], stdout) == EOF)
			break;

	fflush(stdout);
	r = 0;
out:
	close(fd);
	return r;
}

int cmd_load(uint64_t offset)
{
	long r = -1, fd = opendev();
	unsigned long pos;

	if (fd < 0)
		goto out;

	if (!segment) {
		printf("segment not mapped\n");
		goto out;
	}

	for (pos = offset; pos < mapped_size; pos++) {
		int c = fgetc(stdin);
		if (c == EOF)
			break;
		segment[pos] = c;
	}
out:
	close(fd);
	return r;
}

int cmd_fill(uint64_t offset, uint64_t size, int fill)
{
	long r = -1, fd = opendev();
	uint64_t misscount = 0;

	if (fd < 0)
		goto out;

	if (!segment) {
		printf("segment not mapped\n");
		goto out;
	}

	if (size == 0)
		size = mapped_size - offset;

	if (offset + size > mapped_size) {
		printf("mapped segment size would be exceeded\n");
		goto out;
	}

	memset(segment + offset, fill, size);
	for (size += offset; offset < size; offset++)
		if (segment[offset] != (char)fill)
			misscount ++;

	if (misscount)
		printf("fill misscount(!) %lu\n", misscount);
out:
	close(fd);
	return r;
}

int cmd_mark(void)
{
	unsigned long i, count;
	unsigned long *longs;

	if (!segment) {
		printf("segment not mapped\n");
		return -1;
	}

	longs = (void *)segment;
	count = mapped_size / sizeof(long);
	for (i = 0; i < count; i++)
		longs[i] = i;

	return 0;
}

int cmd_checkmark(void)
{
	unsigned long i, count;
	unsigned long *longs;

	if (!segment) {
		printf("segment not mapped\n");
		return -1;
	}

	longs = (void *)segment;
	count = mapped_size / sizeof(long);
	for (i = 0; i < count; i++)
		if (longs[i] != i)
			printf("%lu != %lu\n", i, longs[i]);
	return 0;
}

int main(int argc, char **argv) {

	int i, ret = 0;

	if (argc < 2)
		return help();

	for (i = 1; i < argc; i++) {

		if (!strcmp(argv[i], "info")) {
			ret = cmd_info();
			continue;
		}

		if (!strcmp(argv[i], "create") && (i + 1 < argc)) {
			ret = cmd_create(atol(argv[i+1]));
			i += 1;
			continue;
		}

		if (!strcmp(argv[i], "destroy")) {
			ret = cmd_destroy();
			continue;
		}

		if (!strcmp(argv[i], "wait")) {
			ret = cmd_wait();
			continue;
		}

		if (!strcmp(argv[i], "mark")) {
			ret = cmd_mark();
			continue;
		}

		if (!strcmp(argv[i], "checkmark")) {
			ret = cmd_checkmark();
			continue;
		}

		if (!strcmp(argv[i], "map") && (i + 2 < argc)) {
			ret = cmd_map(atol(argv[i+1]), atol(argv[i+2]));
			i += 2;
			continue;
		}

		if (!strcmp(argv[i], "unmap") && (i + 1 < argc)) {
			ret = cmd_unmap(atol(argv[i+1]));
			i += 1;
			continue;
		}

		if (!strcmp(argv[i], "fill") && (i + 3 < argc)) {
			ret = cmd_fill(	atol(argv[i+1]),
					atol(argv[i+2]),
					strtoul(argv[i+3], NULL, 16));
			i += 3;
			continue;
		}

		if (!strcmp(argv[i], "dump") && (i + 2 < argc)) {
			ret = cmd_dump(atol(argv[i+1]), atol(argv[i+2]));
			i += 2;
			continue;
		}

		if (!strcmp(argv[i], "load") && (i + 1 < argc)) {
			ret = cmd_load(atol(argv[i+1]));
			i += 1;
			continue;
		}

		return help();
	}

	return ret;
}
