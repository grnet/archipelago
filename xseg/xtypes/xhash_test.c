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

int test_string2()
{
    xhashidx i, v;
    struct xhash *h;
    int rr;
    char *string[4];
    string[0] = "b79111bca0cfd1fa9ff0f435357567bcb016cd4949e55484a9b49b129fc5f757";
    string[1] = "bf508f5b-7bc2-4963-9fd3-5e06ffe1b50e.ext.disk0";
    string[2] = "e5856732-30c4-4f2b-b888-897b9079eddc.ext.disk0";
    string[3] = "11b7e801-ea1a-44ab-9d25-ed675da29747.ext.disk0";

    h = malloc(xhash_get_alloc_size(3));
    if (!h){
        perror("malloc");
	exit(1);
    }
    xhash_init(h, 3, STRING);
    for (i = 0; i < 4; i++) {
	int ret;
        xhashidx r;
        rr = xhash_insert(h, (xhashidx) string[i], (xhashidx) i);
	if (rr == -XHASH_ERESIZE){
		h = my_resize(h, xhash_grow_size_shift(h));
		rr = xhash_insert(h, string[i], (xhashidx) i);
		if (rr != 0)
			printf("resize string insert error in %lx: %lx != %lx\n", i, r, i);
	}
        ret = xhash_lookup(h, (xhashidx)string[i], (xhashidx *) &r);
        if (ret || (r != i)) {
            printf("string insert error in %lx (ret: %d): returned val %lx, expected val %lx\n ", i, ret, r, i);
        }
    }
    for (i = 0; i < 4; i++) {
        int ret = xhash_lookup(h, (xhashidx)string[i], (xhashidx *) &v);
        //printf(" ->got(%lu, %lu)\n", i, v);
        if (ret || (i != v)) {
            printf("string error in %lu: %lu != %lu\n", i, i, v);
            getchar();
        }
    }
    for (i = 00; i < 4; i++) {
	int ret;
        xhashidx r;
        //printf("insert(%lx, %lx)\n", i, -i);
        rr = xhash_delete(h, (xhashidx)string[i]);
	if (rr == -XHASH_ERESIZE){
		h = my_resize(h, xhash_shrink_size_shift(h));
		rr = xhash_delete(h, (xhashidx)string[i]);
		if (rr != 0)
			printf("resize string delele error in %lx: %lx != %lx\n", i, r, i);
	}
        ret = xhash_lookup(h, (xhashidx) string[i], (xhashidx *) &r);
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
    test_string2();
    printf("test completed successfully\n");
    return 0;
}
