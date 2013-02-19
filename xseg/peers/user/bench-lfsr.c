/*
 * Copyright 2012 GRNET S.A. All rights reserved.
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
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <pthread.h>
#include <xseg/xseg.h>
#include <peer.h>
#include <time.h>
#include <sys/util.h>
#include <signal.h>
#include <bench-xseg.h>
#include <limits.h>

#include <math.h>

#ifdef __GNUC__
#define likely(x)       __builtin_expect(!!(x),1)
#define unlikely(x)     __builtin_expect(!!(x),0)
#else
#define likely(x)       (x)
#define unlikely(x)     (x)
#endif

#define MAX_TAPS 6

#ifdef STAND_ALONE
uint64_t global_seed;
#endif

/*
 * LFSRs are pseudo-random number generators. They are deterministic (meaning
 * that the same seed will produce the same number sequence) and extremely
 * fast.
 *
 * You can find more about LFSRs from these links:
 * http://en.wikipedia.org/wiki/Linear_feedback_shift_register
 * http://www.xilinx.com/support/documentation/application_notes/xapp052.pdf
 * http://www.ti.com/lit/an/scta036a/scta036a.pdf
 * http://notabs.org/lfsr/lfsr.html
 * http://www.electricdruid.net/index.php?page=techniques.practicalLFSRs
 *
 * LFSR taps retrieved from:
 * http://home1.gte.net/res0658s/electronics/LFSRtaps.html
 *
 * It's common in the bibliography to start the numbering of LFSR bits from 1
 * instead of 0. We will use the same numbering in this code and alter it
 * where necessary.
 *
 * Below is a 64x6 uint8_t array that covers all the appropriate taps for
 * maximal length LFSRs, ranging from 3-bits to 64bit. It's memory overhead
 * should be relatively small, no more than 384 bytes.
 */
static uint8_t taps[64][MAX_TAPS] =
{
		{0}, {0}, {0},		//LFSRs with less that 3-bits cannot exist
		{3, 2},				//Tap position for 3-bit LFSR
		{4, 3},				//Tap position for 4-bit LFSR
		{5, 3},				//Tap position for 5-bit LFSR
		{6, 5},				//Tap position for 6-bit LFSR
		{7, 6},				//Tap position for 7-bit LFSR
		{8, 6, 5 ,4},		//Tap position for 8-bit LFSR
		{9, 5},				//Tap position for 9-bit LFSR
		{10, 7},			//Tap position for 10-bit LFSR
		{11, 9},			//Tap position for 11-bit LFSR
		{12, 6, 4, 1},		//Tap position for 12-bit LFSR
		{13, 4, 3, 1},		//Tap position for 13-bit LFSR
		{14, 5, 3, 1},		//Tap position for 14-bit LFSR
		{15, 14},			//Tap position for 15-bit LFSR
		{16, 15, 13, 4},	//Tap position for 16-bit LFSR
		{17, 14},			//Tap position for 17-bit LFSR
		{18, 11},			//Tap position for 18-bit LFSR
		{19, 6, 2, 1},		//Tap position for 19-bit LFSR
		{20, 17},			//Tap position for 20-bit LFSR
		{21, 19},			//Tap position for 21-bit LFSR
		{22, 21},			//Tap position for 22-bit LFSR
		{23, 18},			//Tap position for 23-bit LFSR
		{24, 23, 22, 17},	//Tap position for 24-bit LFSR
		{25, 22},			//Tap position for 25-bit LFSR
		{26, 6, 2, 1},		//Tap position for 26-bit LFSR
		{27, 5, 2, 1},		//Tap position for 27-bit LFSR
		{28, 25},			//Tap position for 28-bit LFSR
		{29, 27},			//Tap position for 29-bit LFSR
		{30, 6, 4, 1},		//Tap position for 30-bit LFSR
		{31, 28},			//Tap position for 31-bit LFSR
		{32, 31, 29, 1},	//Tap position for 32-bit LFSR
		{33, 20},			//Tap position for 33-bit LFSR
		{34, 27, 2, 1},		//Tap position for 34-bit LFSR
		{35, 33},			//Tap position for 35-bit LFSR
		{36, 25},			//Tap position for 36-bit LFSR
		{37, 5, 4, 3, 2, 1},//Tap position for 37-bit LFSR
		{38, 6, 5, 1},		//Tap position for 38-bit LFSR
		{39, 35},			//Tap position for 39-bit LFSR
		{40, 38, 21, 19},	//Tap position for 40-bit LFSR
		{41, 38},			//Tap position for 41-bit LFSR
		{42, 41, 20, 19},	//Tap position for 42-bit LFSR
		{43, 42, 38, 37},	//Tap position for 43-bit LFSR
		{44, 43, 18, 17},	//Tap position for 44-bit LFSR
		{45, 44, 42, 41},	//Tap position for 45-bit LFSR
		{46, 45, 26, 25},	//Tap position for 46-bit LFSR
		{47, 42},			//Tap position for 47-bit LFSR
		{48, 47, 21, 20},	//Tap position for 48-bit LFSR
		{49, 40},			//Tap position for 49-bit LFSR
		{50, 49, 24, 23},	//Tap position for 50-bit LFSR
		{51, 50, 36, 35},	//Tap position for 51-bit LFSR
		{52, 49},			//Tap position for 52-bit LFSR
		{53, 52, 38, 37},	//Tap position for 53-bit LFSR
		{54, 53, 18, 17},	//Tap position for 54-bit LFSR
		{55, 31},			//Tap position for 55-bit LFSR
		{56, 55, 35, 34},	//Tap position for 56-bit LFSR
		{57, 50},			//Tap position for 57-bit LFSR
		{58, 39},			//Tap position for 58-bit LFSR
		{59, 58, 38, 37},	//Tap position for 59-bit LFSR
		{60, 59},			//Tap position for 60-bit LFSR
		{61, 60, 46, 45},	//Tap position for 61-bit LFSR
		{62, 61, 6, 5},		//Tap position for 62-bit LFSR
		{63, 62},			//Tap position for 63-bit LFSR
};

/*
 * There are two kinds of LFSRs, each of which can be implemented with XOR or
 * XNOR logic:
 * a) Fibonacci LFSRs, that have XOR/XNOR gates serially to produce the input
 * bit and
 * b) Galois LFSRs, that have XOR/XNOR gates parallely, separated from one
 * another and the outputs of which are fed as input bits. Also, the tap bits
 * are flipped, depending on the output bit.
 *
 * A Galois LFSR seems more complicated but is actually the fittest
 * implementation for an LFSR on CPU, due to the fact that the input bit can
 * be computed on one turn, instead of 2 - 6 that would be needed for a
 * Fibonacci LFSR. Another point that must be taken into consideration is
 * that an LFSR with XOR gates has the 0 state as illegal, which is something
 * we do not want for benchmarks.
 *
 * That's why we use an Galois-XNOR LFSR.
 *
 * Below we create what can best be described as an XNOR-mask
 */
static uint64_t lfsr_create_xnormask(uint8_t *taps)
{
	int i;
	uint64_t xnormask = 0;

	for(i = 0; i < MAX_TAPS && taps[i] != 0; i++)
		xnormask |= 1UL << (taps[i] - 1);

	return xnormask;
}

/*
 * To initialize an LFSR we need the following:
 * a) the upper limit of random numbers that we want LFSR to generate (size)
 * b) the initial state of LFSR (seed)
 *
 * NOTE1: If the upper limit is bigger than 63 bits or smaller than 3 bits, we
 * cannot create the LFSR.
 * NOTE2: If 2^(n+1) < upper_limit <= 2^n , the LFSR that will be created will
 * have (n+1) bits.
 * NOTE3: If an LFSR has n bits, the seed must not be all ones (= 2^(n+1) - 1)
 */
/*
int lfsr_init(struct lfsr *lfsr, uint64_t size, uint64_t seed)
{
	uint8_t i;

	lfsr->limit = size;

	//i has number of bits of size
	for (i = 0; size; i++)
		size = size >> 1;

	if (i < 3 || i > 63)
		return -1;

	lfsr->length = i;
	lfsr->xnormask = lfsr_create_xnormask(taps[i]);

	if (seed == (1UL << (i + 1)) - 1)
		return -1;

	lfsr->state = seed;
	return 0;
}
*/
int lfsr_init(struct lfsr *lfsr, uint64_t size, uint64_t seed)
{
	uint8_t i;

	lfsr->limit = size;

	//i has number of bits of size
	for (i = 0; size; i++)
		size = size >> 1;

	//Too small or too big size to create an LFSR out of it
	if (i < 3 || i > 63)
		return -1;

	//The all ones state is illegal. Due to the fact that our seed is
	//nanoseconds taken from clock_gettime, we are sure that the 31st bit will
	//always be 0. The following codes has that in mind and creates a seed
	//that has at least one 0.
	if (seed == UINT64_MAX) {
		if (i < 32)
			lfsr->state = global_seed >> (31 - i);
		else
			lfsr->state = global_seed << (i - 31);
	}
	else {
		lfsr->state = seed;
	}

	lfsr->length = i;
	lfsr->xnormask = lfsr_create_xnormask(taps[i]);

	return 0;
}

#ifdef STAND_ALONE
/*
 * Sanity-check every LFSR for wrong tap positions.
 */
static int lfsr_check()
{
	struct lfsr lfsr;
	uint8_t length, i;
	uint64_t period;
	uint64_t upper_limit;

	//Create all LFSRs with maximum limit
	for (length = 3; length < 64; length++) {
		if (lfsr_init(&lfsr, pow(2, length) - 1, 1))
			return -1;

		period = 1; //Already initialized at 1
		upper_limit = pow(2, length);

		while(likely(period++ < upper_limit))
			lfsr_next(&lfsr);

		if (lfsr.state == 1) {
			printf("%u-bit LFSR has correct tap positions\n", length);
		}
		else {
			printf("%u-bit LFSR has incorrect tap positions\n", length);
			printf("Current tap positions: ");
			for (i = 0; i < MAX_TAPS && taps[length][i] != 0; i++)
				printf("%u ", taps[length][i]);
			printf("\n");
			return -1;
		}
	}

	return 0;
}

int main()
{
	int r;

	r = lfsr_check();

	return r;
}
#endif

