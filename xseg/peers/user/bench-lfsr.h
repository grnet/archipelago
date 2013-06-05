#ifndef FIO_LFSR_H
#define FIO_LFSR_H
#include <inttypes.h>

#define MAX_TAPS	6

struct lfsr_taps {
	unsigned int length;
	unsigned int taps[MAX_TAPS];
};


struct bench_lfsr {
	uint64_t xormask;
	uint64_t last_val;
	uint64_t cached_bit;
	uint64_t max_val;
	uint64_t num_vals;
	uint64_t cycle_length;
	uint64_t cached_cycle_length;
	unsigned int spin;
};

uint64_t lfsr_next(struct bench_lfsr *lfsr);
int lfsr_init(struct bench_lfsr *lfsr, uint64_t size,
		unsigned long seed, unsigned int spin);
int lfsr_reset(struct bench_lfsr *lfsr, unsigned long seed);
#endif
