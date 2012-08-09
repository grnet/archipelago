#include <stdio.h>
#include <stdlib.h>

#include "xhash.h"

#define LOOPS 1000000

xhash_t *my_resize(xhash_t *h, ul_t sizeshift)
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


int main(int argc, char **argv) {
    ul_t loops, i, v;
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
    xhash_init(h, 2);
    for (i = 10; i < loops; i++) {
	int ret;
        ul_t r;
        //printf("insert(%lx, %lx)\n", i, -i);
        rr = xhash_insert(h, i, -i);
	if (rr == -XHASH_ERESIZE){
		h = my_resize(h, grow_size_shift(h));
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
        ul_t r;
        //printf("insert(%lx, %lx)\n", i, -i);
        rr = xhash_delete(h, i);
	if (rr == -XHASH_ERESIZE){
		h = my_resize(h, shrink_size_shift(h));
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

    printf("test completed successfully\n");
    return 0;
}
