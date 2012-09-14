#include <stdio.h>
#include <stdlib.h>

#include "xhash.h"

#define LOOPS 1000000
#define STRINGLEN 63

xhash_t *my_resize(xhash_t *h, xhashidx sizeshift)
{
	ssize_t bytes = xhash_get_alloc_size(sizeshift);
	xhash_t *new = malloc(bytes);
	if (!new) {
		perror("malloc");
		exit(1);
	}
	xhash_resize(h, sizeshift, new);
	free(h);
	return new;
}

void make_chunk(char *string, xhashidx id)
{
	xhashidx i;
	for (i = 0; i < STRINGLEN; i++) {
		string[i] = 'a' + !(!(id & (1 << i)));
	}
	string[STRINGLEN] = 0;

}

int chekck_chunk(char *string, xhashidx s)
{
	xhashidx i;
	for (i = 0; i < STRINGLEN; i++) {
		if (string[i] != s + i)
			return -1;
	}
	if (string[STRINGLEN] != 0)
		return -1;

	return 0;
}

int test_string(xhashidx loops)
{
    xhashidx i, v;
    struct xhash *h;
    int rr;
    char **string = malloc(sizeof(char *) * loops);
    if (!string) {
	    perror("malloc");
	    exit(1);
    }
    for (i = 0; i < loops; i++) {
    	string[i] = malloc(sizeof(char) * STRINGLEN+1);
	if (!string[i]) {
		perror("malloc");
		exit(1);
	}
	make_chunk(string[i], i);
    }
    
    h = malloc(xhash_get_alloc_size(2));
    if (!h){
        perror("malloc");
	exit(1);
    }
    xhash_init(h, 2, STRING);
    for (i = 10; i < loops; i++) {
	int ret;
        xhashidx r;
        //printf("insert(%lx, %lx)\n", i, -i);
        rr = xhash_insert(h, string[i], i);
	if (rr == -XHASH_ERESIZE){
		h = my_resize(h, xhash_grow_size_shift(h));
		rr = xhash_insert(h, string[i], i);
		if (rr != 0)
			printf("resize string insert error in %lx: %lx != %lx\n", i, r, i);
	}
        ret = xhash_lookup(h, string[i], &r);
        if (ret || (r != i)) {
            printf("string insert error in %lx (ret: %d): returned val %lx, expected val %lx\n ", i, ret, r, i);
        }
        //printf(" ->got(%lx, %lx)\n", i, r);
    }
    for (i = 10; i < loops; i++) {
        int ret = xhash_lookup(h, string[i], &v);
        //printf(" ->got(%lu, %lu)\n", i, v);
        if (ret || (i != v)) {
            printf("string error in %lu: %lu != %lu\n", i, i, v);
            getchar();
        }
    }
    for (i = 10; i < loops; i++) {
	int ret;
        xhashidx r;
        //printf("insert(%lx, %lx)\n", i, -i);
        rr = xhash_delete(h, string[i]);
	if (rr == -XHASH_ERESIZE){
		h = my_resize(h, xhash_shrink_size_shift(h));
		rr = xhash_delete(h, string[i]);
		if (rr != 0)
			printf("resize string delele error in %lx: %lx != %lx\n", i, r, i);
	}
        ret = xhash_lookup(h, string[i], &r);
        if (!ret) {
            printf("string delete error in %lx: %lx != %lx\n", i, r, i);
        }
        //printf(" ->got(%lx, %lx)\n", i, r);
    }
    free(h);

    return 0;
}

int main(int argc, char **argv) {
    xhashidx loops, i, v;
    struct xhash *h;
    int rr;

    if (argc > 1) {
        loops = atoi(argv[1]);
    } else {
        loops = LOOPS;
    }

    h = malloc(xhash_get_alloc_size(2));
    if (!h){
        perror("malloc");
	exit(1);
    }
    xhash_init(h, 2, INTEGER);
    for (i = 10; i < loops; i++) {
	int ret;
        xhashidx r;
        //printf("insert(%lx, %lx)\n", i, -i);
        rr = xhash_insert(h, i, -i);
	if (rr == -XHASH_ERESIZE){
		h = my_resize(h, xhash_grow_size_shift(h));
		rr = xhash_insert(h, i, -i);
		if (rr != 0)
			printf("resize insert error in %lx: %lx != %lx\n", i, r, -i);
	}
        ret = xhash_lookup(h, i, &r);
        if (ret || (r != -i)) {
            printf("insert error in %lx: %lx != %lx\n", i, r, -i);
        }
        //printf(" ->got(%lx, %lx)\n", i, r);
    }
    for (i = 10; i < loops; i++) {
        int ret = xhash_lookup(h, i, &v);
        //printf(" ->got(%lu, %lu)\n", i, v);
        if (ret || (i != -v)) {
            printf("error in %lu: %lu != %lu\n", i, i, -v);
            getchar();
        }
    }
    for (i = 10; i < loops; i++) {
	int ret;
        xhashidx r;
        //printf("insert(%lx, %lx)\n", i, -i);
        rr = xhash_delete(h, i);
	if (rr == -XHASH_ERESIZE){
		h = my_resize(h, xhash_shrink_size_shift(h));
		rr = xhash_delete(h, i);
		if (rr != 0)
			printf("resize delele error in %lx: %lx != %lx\n", i, r, -i);
	}
        ret = xhash_lookup(h, i, &r);
        if (!ret) {
            printf("delete error in %lx: %lx != %lx\n", i, r, -i);
        }
        //printf(" ->got(%lx, %lx)\n", i, r);
    }
    free(h);
    test_string(loops);
    printf("test completed successfully\n");
    return 0;
}
