/*
 * Copyright 2013 GRNET S.A. All rights reserved.
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
#include <sys/time.h>
#include "xbinheap.h"

xbinheap_handler *handlers;
int test1(unsigned long n)
{
	struct xbinheap h;
	xbinheapidx i, r;
	long j;
	handlers = malloc(sizeof(xbinheap_handler) * n);
	xbinheap_init(&h, n, XBINHEAP_MAX, NULL);
	for (i = 0; i < n; i++) {
		handlers[i] = xbinheap_insert(&h, i, i);
		if (handlers[i] == NoNode){
			fprintf(stderr, "Error inserting %llu\n", i);
			return -1;
		}
	}
	for (j = n-1; j >=0; j--) {
		i = j;
		r = xbinheap_extract(&h);
		if (r != i){
			fprintf(stderr, "Extracted invalid value %llu != %llu\n", r, i);
			return -1;
		}
	}
	for (i = 0; i < n; i++) {
		handlers[i] = xbinheap_insert(&h, i, i);
	}
	xbinheap_increasekey(&h, handlers[0], n);
	r = xbinheap_extract(&h);
	if (r != 0){
		fprintf(stderr, "Extracted invalid value after increase %llu != 0\n", r);
		return -1;
	}
	handlers[0] = xbinheap_insert(&h, n+1, n+1);
	printf("handler[0]: %llu\n", handlers[0]);
	r = xbinheap_getkey(&h, handlers[0]);
	if (r != n+1){
		fprintf(stderr, "getkey: got %llu, instead of %lu\n", r, n+1);
		return -1;
	}
	r = xbinheap_peak(&h);
	if (r != n+1){
		fprintf(stderr, "peak: got %llu, expected %llu", r, n+1);
		return -1;
	}

	xbinheap_decreasekey(&h, handlers[0], 0);

	r = xbinheap_getkey(&h, handlers[0]);
	if (r != 0){
		fprintf(stderr, "getkey: got %llu, instead of 0\n", r);
		return -1;
	}
	r = xbinheap_peak(&h);
	if (r == n+1){
		fprintf(stderr, "peak: got %llu, expected diffrent", n+1);
		return -1;
	}



	return 0;
}

int main(int argc, const char *argv[])
{
	struct timeval start, end, tv;
	int r;
	int n = atoi(argv[1]);

	fprintf(stderr, "Running test1\n");
	gettimeofday(&start, NULL);
	r = test1(n);
	if (r < 0){
		fprintf(stderr, "Test1: FAILED\n");
		return -1;
	}
	gettimeofday(&end, NULL);
	timersub(&end, &start, &tv);
	fprintf(stderr, "Test1: PASSED\n");
	fprintf(stderr, "Test time: %ds %dusec\n\n", (int)tv.tv_sec, (int)tv.tv_usec);
	return 0;
}
