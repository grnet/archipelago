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

#include <xseg/protocol.h>
#include <bench-lfsr.h>

#ifdef __GNUC__
#define LIKELY(x)       __builtin_expect(!!(x),1)
#define UNLIKELY(x)     __builtin_expect(!!(x),0)
#else
#define LIKELY(x)       (x)
#define UNLIKELY(x)     (x)
#endif

/*
 * If CLOCK_MONOTONIC_RAW is not defined in our system, use CLOCK_MONOTONIC
 * instead. CLOCK_MONOTONIC_RAW is preferred since we are guaranteed that the
 * clock won't skew.
 */
#ifdef CLOCK_MONOTONIC_RAW
#define CLOCK_BENCH CLOCK_MONOTONIC_RAW
#else
#define CLOCK_BENCH CLOCK_MONOTONIC
#endif

#define MAX_ARG_LEN 10

/*
 * Pattern type occupies 1st flag bit.
 * If 0, it's sequential, if 1, it's random.
 */
#define PATTERN_FLAG_POS 0
#define PATTERN_BITMASK 1
#define PATTERN_SEQ 0
#define PATTERN_RAND 1

/*
 * Verify mode occupies 2nd and 3rd flag bit.
 * If 01, it uses metadata for verification, if 11 it writes pseudorandom nums
 * in chunk's memory range and if 00, it's off.
 */
#define VERIFY_FLAG_POS 1
#define VERIFY_BITMASK 3        /* i.e. "11" in binary form */
#define VERIFY_NO 0
#define	VERIFY_META 1
#define	VERIFY_FULL 2

/* Timer insanity occupies 4th and 5th flag bit */
#define INSANITY_FLAG_POS 3
#define INSANITY_BITMASK 3      /* i.e. "11" in binary form */
#define INSANITY_SANE 0
#define INSANITY_ECCENTRIC 1
#define INSANITY_MANIC 2
#define INSANITY_PARANOID 3

/* Progress bar option occupies 6th flag bit */
#define PROGRESS_FLAG_POS 5
#define PROGRESS_BITMASK 3      /* i.e. "11" in binary form */
#define PROGRESS_NO 0
#define PROGRESS_YES 1

/* This is not part of flags per se, but is relative to progress */
#define PTYPE_REQ 0
#define PTYPE_IO 1
#define PTYPE_BOTH 2

/* Ping option occupies 7th flag bit */
#define PING_FLAG_POS 7
#define PING_BITMASK 1
#define PING_MODE_OFF 0
#define PING_MODE_ON 1

/*
 * Current bench flags representation:
 * 63
 * .
 * .
 * .
 * 8
 * 7 <-- ping
 * 6 <-- progress
 * 5 <--   〃
 * 4 <-- insanity
 * 3 <--   〃
 * 2 <-- verify
 * 1 <--   〃
 * 0 <-- pattern
 */

/*
 * Find position of flag, make it zero, get requested flag value, store it to
 * this position
 */
#define SET_FLAG(__ftype, __flag, __val)	\
	__flag = (__flag & ~(__ftype##_BITMASK << __ftype##_FLAG_POS)) | \
	(__val << __ftype##_FLAG_POS);

/* Apply bitmask to flags, shift result to the right to get correct value */
#define GET_FLAG(__ftype, __flag)			\
	(__flag & (__ftype##_BITMASK << __ftype##_FLAG_POS)) >> __ftype##_FLAG_POS

/*
 * For now, the seed length is fixed to 9 digits whereas the object number
 * length is fixed to fifteen digits.
 */
#define SEEDLEN 9
#define OBJNUMLEN 15

struct bench {
    uint64_t to;                //Total number of objects (not for read/write)
    uint64_t ts;                //Total I/O size
    uint64_t os;                //Object size
    uint64_t bs;                //Block size
    uint32_t iodepth;           //Num of in-flight xseg reqs
    xport dst_port;
    xport src_port;
    uint32_t op;                //xseg operation
    uint64_t flags;
    unsigned int interval;
    struct peerd *peer;
    struct req_status *status;
    struct bench_lfsr *lfsr;
    struct object_vars *objvars;
    struct progress_report *rep;
    struct timer *total_tm;     //Total time for benchmark
    struct timer *get_tm;       //Time for xseg_get_request
    struct timer *sub_tm;       //Time for xseg_submit_request
    struct timer *rec_tm;       //Time for xseg_receive_request
};

struct object_vars {
    char name[XSEG_MAX_TARGETLEN];
    int namelen;
    char prefix[XSEG_MAX_TARGETLEN];
    int prefixlen;
    uint64_t seed;
    int seedlen;                /* seed length is hardcoded for now */
    uint64_t objnum;
    int objnumlen;              /* object number length is hardcoded for now */
};

struct req_status {
    uint64_t max;               /* Max requests for benchmark */
    uint64_t submitted;
    uint64_t received;
    uint64_t corrupted;         /* Requests that did not pass verification */
    uint64_t failed;
};

struct progress_report {
    int type;
    uint64_t prev_recv;
    uint64_t interval;
    int lines;
};

/*
 * Custom timespec. Made to calculate variance, where we need the square of a
 * timespec struct. This struct should be more than enough to hold the square
 * of the biggest timespec.
 */
struct timespec2 {
    unsigned long tv_sec2;
    uint64_t tv_nsec2;
};

/*
 * struct timer fields
 * ====================
 * completed: number of completed requests
 * start_time: submission time of a request
 * sum: the sum of elapsed times of every completed request
 * sum_sq: the sum of the squares of elapsed times
 * insanity: benchmarking level, higher means that the request associated with
 *           this timer is more trivial.
 */
struct timer {
    struct timespec sum;
    struct timespec2 sum_sq;
    struct timespec start_time;
    struct timespec elapsed_time;
    uint64_t completed;
    int insanity;
};

struct tm_result {
    unsigned int s;
    unsigned int ms;
    unsigned int us;
    unsigned int ns;
};

struct signature {
    uint64_t id;
    uint64_t object;
    uint64_t offset;
};

struct bw {
    double val;
    char unit[5];
};

int bench_peerd_loop(void *arg);

void timer_start(struct bench *prefs, struct timer *sample_req);
void timer_stop(struct bench *prefs, struct timer *sample_tm,
                struct timespec *start);
int init_timer(struct timer **tm, int insanity);
uint64_t str2num(char *str);
int read_op(char *op);
int read_pattern(char *pattern);
int read_insanity(char *insanity);
int read_verify(char *insanity);
int read_progress(char *progress);
int read_progress_type(char *ptype);
uint64_t read_interval(struct bench *prefs, char *str_interval);
int read_ping(char *progress);
void clear_report_lines(int lines);
void print_total_res(struct bench *prefs);
void print_rec_res(struct bench *prefs);
void print_divider();
void print_req_stats(struct bench *prefs);
void print_io_stats(struct bench *prefs);
void print_progress(struct bench *prefs);
void print_dummy_progress(struct bench *prefs);
void print_remaining(struct bench *prefs);
void create_target(struct bench *prefs, struct xseg_request *req);
void create_chunk(struct bench *prefs, struct xseg_request *req, uint64_t new);
int read_chunk(struct bench *prefs, struct xseg_request *req);
uint64_t determine_next(struct bench *prefs);
uint64_t calculate_offset(struct bench *prefs, uint64_t new);
uint64_t calculate_interval(struct bench *prefs, uint64_t percentage);
int calculate_report_lines(struct bench *prefs);
int validate_seed(struct bench *prefs, unsigned long seed);

void inspect_obv(struct object_vars *obv);
uint64_t __get_object(struct bench *prefs, uint64_t new);
