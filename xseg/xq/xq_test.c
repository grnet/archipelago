#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <pthread.h>
#include <sys/time.h>
#include <assert.h>

#include "xq.h"

struct item {
    long   seed;
    double seed_sin;
    long   seed_times_sin;
    long   seed_xor_times;
};

void item_calculate(struct item *item) {
    item->seed_sin = sin(item->seed | 1);
    item->seed_times_sin = (double)(item->seed | 1) * item->seed_sin;
    item->seed_xor_times = item->seed ^ item->seed_times_sin;
}

int item_verify(struct item *item) {
    struct item t;

    t.seed = item->seed;
    item_calculate(&t);

    /*
    printf("seed %ld, sin: %lf, times: %ld, xor: %ld\n",
           item->seed, item->seed_sin, item->seed_times_sin, item->seed_xor_times);
    */

    if (t.seed_sin       != item->seed_sin       ||
        t.seed_times_sin != item->seed_times_sin ||
        t.seed_xor_times != item->seed_xor_times) {
        printf("seed %ld, sin: %lf, times: %ld, xor: %ld\n",
               item->seed, item->seed_sin, item->seed_times_sin, item->seed_xor_times);
        return 0;
    }

    return 1;
}

int basic_sanity_test(struct xq *q) {
    xqindex t, r;

    //printf("append_tail 9183\n");
    r = xq_append_tail(q, 9183);
    //xq_print(q);
    //printf("\n");
    assert(r != None);

    //printf("pop_head 9183\n");
    r = xq_pop_head(q);
    //xq_print(q);
    //printf("\n");
    assert(r == 9183);

    //printf("append_head 1834\n");
    r = xq_append_head(q, 1834);
    //xq_print(q);
    //printf("\n");
    assert(r != None);

    //printf("pop_tail 1834\n");
    r = xq_pop_tail(q);
    //xq_print(q);
    //printf("\n");
    assert(r == 1834);

    //printf("append_tail 3814\n");
    xq_append_tail(q, 3814);
    //xq_print(q);
    //printf("\n");

    //printf("append_head 5294\n");
    xq_append_head(q, 5294);
    //xq_print(q);
    //printf("\n");

    //printf("append_tail 1983\n");
    r = xq_append_tail(q, 1983);
    //xq_print(q);
    //printf("\n");
    assert(r != None);

    //printf("pop_tail 1983\n");
    r = xq_pop_tail(q);
    //xq_print(q);
    //printf("\n");
    assert(r == 1983);

    //printf("append_head 8134\n");
    r = xq_append_head(q, 8134);
    //xq_print(q);
    //printf("\n");
    assert(r != None);

    //printf("pop_head 8134\n");
    r = xq_pop_head(q);
    //xq_print(q);
    //printf("\n");
    assert(r == 8134);

    //printf("pop_tail 3814\n");
    r = xq_pop_tail(q);
    //xq_print(q);
    //printf("\n");
    assert(r == 3814);

    //printf("pop_head 5294\n");
    r = xq_pop_head(q);
    //xq_print(q);
    //printf("\n");
    assert(r == 5294);

    //printf("pop_tail None\n");
    r = xq_pop_tail(q);
    //xq_print(q);
    //printf("\n");
    assert(r == None);

    //printf("pop_head None\n");
    r = xq_pop_head(q);
    //xq_print(q);
    //printf("\n");
    assert(r == None);

    xqindex qsize = q->size;
    for (t = 0; t < qsize; t += 1) {
         r = xq_append_tail(q, t);
         //if (r == None) printf("None: %lu\n", (unsigned long)t);
         //xq_print(q);
         assert(r != None);
    }

    //xq_print(q);

    for (t = qsize-1; t != None; t -= 1) {
         r = xq_pop_tail(q);
         assert(t == r);
         //printf("%lu vs %lu\n", t, (unsigned long)xq_pop_tail(q));
    }

    return 0;
}

struct thread_data {
    long loops;
    struct xq *q;
    struct item *items;
    struct random_data *rdata;
    long size;
    int id;
};

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void *random_test_thread(void *arg) {
    struct thread_data *th = arg;
    long loops = th->loops;
    struct xq *q = th->q;
    struct item *items = th->items;
    //struct random_data *rdata = th->rdata;
    int id = th->id;
    long i;


    /*
    pthread_mutex_lock(&mutex);
    printf("---->\n");
    xq_print(&q[0]);
    xq_print(&q[1]);
    printf("<----\n");
    pthread_mutex_unlock(&mutex);
    */

    for (i = 0; i < loops; i++) {
         int32_t rand;
         xqindex xqi;

         if ((i & (1024*1024 -1)) == 0) {
             printf("%d %ld\n", id, i);
         }

         //random_r(rdata, &rand);
         rand = random();

         switch (rand & 3) {
         case 0:
             xqi = xq_pop_tail(&q[0]);
             if (xqi == None) goto unlock;
             items[xqi].seed = rand;
             item_calculate(&items[xqi]);
             xq_append_head(&q[1], xqi);
             break;
         case 1:
             xqi = xq_pop_head(&q[0]);
             if (xqi == None) goto unlock;
             items[xqi].seed = rand;
             item_calculate(&items[xqi]);
             xq_append_tail(&q[1], xqi);
             break;
         case 2:
             xqi = xq_pop_tail(&q[1]);
             if (xqi == None) goto unlock;
             items[xqi].seed = rand;
             item_calculate(&items[xqi]);
             xq_append_head(&q[0], xqi);
             break;
         case 3:
             xqi = xq_pop_head(&q[1]);
             if (xqi == None) goto unlock;
             items[xqi].seed = rand;
             item_calculate(&items[xqi]);
             xq_append_tail(&q[0], xqi);
             break;
         }
    unlock:
         ;
    }

    return NULL;
}

int error(const char *msg) {
    perror(msg);
    return 1;
}

int random_test(long seed, long nr_threads, long loops, xqindex qsize, struct xq *q) {
    srandom(seed);

    struct thread_data *th = malloc(nr_threads * sizeof(struct thread_data));
    if (!th) return error("malloc");

    long t, r;

    struct item *items = malloc(qsize * sizeof(struct item));
    if (!items) return error("malloc");

    for (t = 0; t < qsize; t += 1) item_calculate(&items[t]);

    for (t = 0; t < qsize; t += 4) {
         xq_append_tail(&q[0], t+0);
         xq_append_head(&q[0], t+1);
         xq_append_tail(&q[1], t+2);
         xq_append_head(&q[1], t+3);
    }

    pthread_t *threads = malloc(nr_threads * sizeof(pthread_t));
    if (!threads) return error("malloc");

    //struct random_data *rdata = malloc(nr_threads * sizeof(struct random_data));
    //if (!rdata) return error("malloc");

    for (t = 0; t < nr_threads; t++) {
         th[t].id = t;
         th[t].loops = loops;
         th[t].size = qsize;
         th[t].q = q;
         //th[t].rdata = &rdata[t];
         th[t].items = items;
         //srandom_r(random(), th[t].rdata);
    }

    for (t = 0; t < nr_threads; t++) {
         r = pthread_create(&threads[t], NULL, random_test_thread, &th[t]);
         if (r) return error("pthread_create");
    }

    for (t = 0; t < nr_threads; t++) {
         pthread_join(threads[t], NULL);
    }

    int errors = 0;
    for (t = 0; t < qsize; t++) {
         if (!item_verify(&items[t])) {
             errors ++;
             printf("error: item %ld\n", t);
         };
    }

    return errors;
}

struct xq q[2];

int main(int argc, char **argv) {
    int r;

    if (argc < 5) {
        printf("Usage: struct xqest <seed> <nr_threads> <nr_loops> <qsize>\n");
        return 1;
    }

    long seed = atol(argv[1]);
    int nr_threads = atoi(argv[2]);
    long loops = atol(argv[3]);
    long qsize = atol(argv[4]);

    if (nr_threads < 0) nr_threads = 2;
    if (loops < 0) loops = 1000;
    if (qsize < 0) qsize = 1000;

    xq_alloc_empty(&q[0], qsize);
    xq_alloc_empty(&q[1], qsize);
    qsize = q[0].size;
    assert(q[1].size == qsize);

    r = basic_sanity_test(&q[0]);
    if (r) return r;
    printf("basic sanity test complete.\n");

    struct timeval tv0, tv1;
    gettimeofday(&tv0, NULL);
    r = random_test(seed, nr_threads, loops, qsize, q);
    gettimeofday(&tv1, NULL);
    double seconds = tv1.tv_sec + tv1.tv_usec/1000000.0 - tv0.tv_sec - tv0.tv_usec / 1000000.0;
    printf("random multi-thread test complete with %d errors in %lf seconds\n", r, seconds);
    if (r) return r;

    return 0;
}
