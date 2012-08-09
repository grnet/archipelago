#include <xpool.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/time.h>
#include <xseg/xseg.h>

uint64_t size = 16;
uint64_t loops = 100000;

struct xpool xp;
struct xq xq;

void test_all_funcs(){
	xpool_index idx1, idx2, ret;
	xpool_data data;
	
	idx1 = xpool_add(&xp, (xpool_data) 5);
	if (idx1 == NoSerial) {
		printf("couldn't add idx1\n");
		return 1;
	}
	printf("added 5 in idx %llu\n", idx1);
	idx2 = xpool_add(&xp, (xpool_data) 6);
	if (idx2 == NoSerial) {
		printf("couldn't add idx2\n");
		return 1;
	}
	printf("added 6 in idx %llu\n", idx2);

	ret = xpool_peek(&xp, &data);
	if (ret == NoSerial) {
		printf("couldn't peek\n");
		return 1;
	}
	printf("peeked xpool (idx %llu) and took data %u\n", ret, data);
	ret = xpool_peek_idx(&xp, idx2, &data);
	if (ret != idx2) {
		printf("couldn't peek\n");
		return 1;
	}
	printf("peeked xpool in idx %llu and took data %u\n", idx2, data);
	ret = xpool_peek_and_fwd(&xp, &data);
	if (ret == NoSerial) {
		printf("couldn't peek\n");
		return 1;
	}
	printf("peeked and fwd xpool (idx %llu) and took data %u\n", ret, data);
	ret = xpool_peek_and_fwd(&xp, &data);
	if (ret == NoSerial) {
		printf("couldn't peek\n");
		return 1;
	}
	printf("peeked and fwd xpool (idx %llu) and took data %u\n", ret, data);

	ret = xpool_remove(&xp, idx1, &data);
	if (ret != idx1) {
		printf("couldn't remove idx1\n");
		return 1;
	}
	if (data != (xpool_data) 5) {
		printf("idx1 returned wrong value (%u)\n", data);
		return -1;
	}
	printf("removed idx1 with data %u\n", data);
	ret = xpool_remove(&xp, idx2, &data);
	if (ret != idx2) {
		printf("couldn't remove idx2\n");
		return 1;
	}
	if (data != (xpool_data) 6) {
		printf("idx2 returned wrong value (%u)\n", data);
		return -1;
	}
	printf("removed idx2 with data %u\n", data);

	printf("test succesfull\n");
}

void *xpool_func(void *arg)
{
	int id = (int) arg;
	xpool_index idx, ret;
	xpool_data data;
	uint64_t i ;
	struct timeval start, end;

	gettimeofday(&start, NULL);
	for (i = 0; i < loops; i++) {
		idx = xpool_add(&xp, (xpool_data) id);
		if (idx == NoSerial) {
			printf("couldn't add idx\n");
			return NULL;
		}
		/*
		ret = xpool_peek_idx(&xp, idx, &data);
		if (ret != idx) {
			printf("couldn't peek\n");
			return NULL;
		}
		if (data != (xpool_data) id){
			printf("peekidx returned wrong value %u instead of %u\n", 
					data, (xpool_data) id);
			return NULL;
		}
		ret = xpool_peek_and_fwd(&xp, &data);
		if (ret == NoSerial) {
			printf("couldn't peek and fwd\n");
			return NULL;
		}
		*/
		ret = xpool_remove(&xp, idx, &data);
//		if (ret != idx) {
//			printf("couldn't remove idx: %llu\n", idx);
//			return NULL;
//		}
//		if (data != (xpool_data) id){
//			printf("remove returned wrong value %u instead of %u\n", 
//					data, (xpool_data) id);
//			return NULL;
//		}
	}
	gettimeofday(&end, NULL);
	timersub(&end, &start, &end);
	printf("%d: test succesfull (%llu loops in %u.%us)\n", id, loops, end.tv_sec, end.tv_usec);

	return NULL;
}

void *xq_func(void *arg)
{
	int id = (int) arg;
	xqindex idx, ret;
	uint64_t i ;
	struct timeval start, end;

	gettimeofday(&start, NULL);
	for (i = 0; i < loops; i++) {
		
		idx = xq_append_tail(&xq, (xqindex) id);
		if (idx == NoSerial) {
			printf("couldn't add idx\n");
			return NULL;
		}
		/*
		ret = xpool_peek_idx(&xp, idx, &data);
		if (ret != idx) {
			printf("couldn't peek\n");
			return NULL;
		}
		if (data != (xpool_data) id){
			printf("peekidx returned wrong value %u instead of %u\n", 
					data, (xpool_data) id);
			return NULL;
		}
		ret = xpool_peek_and_fwd(&xp, &data);
		if (ret == NoSerial) {
			printf("couldn't peek and fwd\n");
			return NULL;
		}
		*/
		ret = xq_pop_head(&xq);
		//if (ret != idx) {
		//	printf("couldn't remove idx: %llu\n", idx);
		//	return NULL;
		//}
		//if (ret != (xqindex) id){
		//	printf("remove returned wrong value %u instead of %u\n", 
		//			ret, (xqindex) id);
		//	return NULL;
		//}
	}
	gettimeofday(&end, NULL);
	timersub(&end, &start, &end);
	printf("%d: test succesfull (%llu loops in %u.%us)\n", id, loops, end.tv_sec, end.tv_usec);

	return NULL;
}


int main(int argc, const char *argv[])
{

	size = atoi(argv[1]);
	loops = atoi(argv[2]);

	struct xpool_node* mem = malloc(sizeof(struct xpool_node) * size);
	xqindex* xqmem = malloc(sizeof(xqindex) * size);
	pthread_t *thread, tid;
	void *ret;
	int i;

	thread = malloc(sizeof(pthread_t)*size);

	printf("Testing xpool\n");
	xpool_init(&xp, size, mem);
	for (i = 0; i < size; i++) {
		pthread_create(thread+i, NULL, xpool_func, (void *) i);
	}

	for (i = 0; i < size; i++) {
		pthread_join(thread[i], &ret);
	}
	
	printf("Testing xq\n");
	xq_init_empty(&xq, size, xqmem);
	for (i = 0; i < size; i++) {
		pthread_create(thread+i, NULL, xq_func, (void *) i);
	}

	for (i = 0; i < size; i++) {
		pthread_join(thread[i], &ret);
	}


	// and again

	return 0;
}
