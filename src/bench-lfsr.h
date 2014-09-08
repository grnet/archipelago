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
