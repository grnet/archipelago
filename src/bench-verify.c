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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <pthread.h>
#include <xseg/xseg.h>
#include <peer.h>
#include <time.h>
#include <xseg/util.h>
#include <signal.h>
#include <bench-xseg.h>

#include <math.h>
#include <string.h>

/********************\
 * Diagnostic tools *
\********************/

#define PRINT_SIG(__who, __sig)						\
	fprintf(stdout, "%s (%lu): id %lu, object %lu, offset %lu\n",	\
			#__who, (uint64_t)(__sig),			\
			((struct signature *)__sig)->id,		\
			((struct signature *)__sig)->object,		\
			((struct signature *)__sig)->offset);

__attribute__ ((unused))
void inspect_obv(struct object_vars *obv)
{
	XSEGLOG2(&lc, D, "Struct object vars:\n"
			"\tname: %s (%d),\n"
			"\tprefix: %s (%d),\n"
			"\tseed: %lu (%d),\n"
			"\tobjnum: %lu (%d)",
			obv->name, obv->namelen, obv->prefix, obv->prefixlen,
			obv->seed, obv->seedlen,
			obv->objnum, obv->objnumlen);
}

/******************************\
 * Static miscellaneous tools *
\******************************/

static inline uint64_t __get_object_from_name(struct object_vars *obv,
		char *name)
{
	/* In case of --objname switch */
	if (obv->name[0])
		return 0;

	/* Keep only the object number */
	return atol(name + obv->namelen - obv->objnumlen);
}

static inline int __snap_to_bound8(uint64_t space)
{
	return space > 8 ? 8 : space;
}

static inline void __write_sig(struct bench_lfsr *sg, uint64_t *d, uint64_t s,
		int pos)
{
	uint64_t i;
	uint64_t last_val;
	uint64_t space_left;

	/* Write random numbers (based on global_id) every 24 bytes */
	/* TODO: Should we use memcpy? */
	for (i = pos; i < (s / 8) - (3 - pos); i += 3)
		*(d + i) = lfsr_next(sg);

	/* special care for last chunk */
	last_val = lfsr_next(sg);
	space_left = s - (i * 8);
	memcpy(d + i, &last_val, __snap_to_bound8(space_left));
}

static inline int __read_sig(struct bench_lfsr *sg, uint64_t *d, uint64_t s,
		int pos)
{
	uint64_t i;
	uint64_t last_val;
	uint64_t space_left;

	/* TODO: Should we use memcmp? */
	for (i = pos; i < (s / 8) - (3 - pos); i += 3) {
		if (*(d + i) != lfsr_next(sg))
			return 1;
	}
	/* special care for last chunk */
	last_val = lfsr_next(sg);
	space_left = s - (i * 8);
	if (memcmp(d + i, &last_val, __snap_to_bound8(space_left)))
		return 1;

	return 0;
}

/*
 * ***********************************************
 * `create_chunk` handles 3 identifiers:
 * 1. The benchmark's global_id
 * 2. The object's number
 * 3. The chunk offset in the object
 *
 * ************************************************
 * `readwrite_chunk_full` takes the above 3 identifiers and feeds them as seeds
 * in 63-bit LFSRs. The numbers generated are written consecutively in chunk's
 * memory range. For example, for a 72-byte chunk:
 *
 * || 1 | 2 | 3 | 1 | 2 | 3 | 1 | 2 | 3 ||
 *  ^   8  16  24  32  40  48  56  64   ^
 *  |                                   |
 *  |                                   |
 * start                               end
 *
 * 1,2,3 differ between each iteration
 *
 * **************************************************
 * `_create_chunk_meta` simply writes the above 3 ids in the start and end of
 * the chunk's memory range, so it should be much faster (but less safe)
 *
 * **************************************************
 * In both cases, special care is taken not to exceed the chunk's memory range.
 * Also, the bare minimum chunk to verify should be 48 bytes. This limit is set
 * by readwrite_chunk_meta, which expects to write in a memory at least this
 * big.
 *
 * **************************************************
 * Note: The diagram above also represents the x86_64's endianness.
 * Endianness must be taken into careful consideration when examining a memory
 * chunk.
 */
static int readwrite_chunk_full(struct bench *prefs, struct xseg_request *req)
{
	struct bench_lfsr id_lfsr;
	struct bench_lfsr obj_lfsr;
	struct bench_lfsr off_lfsr;
	struct xseg *xseg = prefs->peer->xseg;
	uint64_t id = prefs->objvars->seed;
	uint64_t object = prefs->objvars->objnum;
	uint64_t *d = (uint64_t *)xseg_get_data(xseg, req);
	uint64_t s = req->size;

	/* Create 63-bit LFSRs */
	lfsr_init(&id_lfsr, 0x7FFFFFFFFFFFFFFF, id, 0);
	lfsr_init(&obj_lfsr, 0x7FFFFFFFFFFFFFFF, object, 0);
	lfsr_init(&off_lfsr, 0x7FFFFFFFFFFFFFFF, req->offset, 0);

	if (s < sizeof(struct signature)) {
		XSEGLOG2(&lc, E, "Too small chunk size (%lu butes). Leaving.", s);
		return 1;
	}

	/*
	 * Every write operation has its read counterpart which, if it finds any
	 * corruption, returns 1
	 */

	if (req->op == X_WRITE) {
		__write_sig(&id_lfsr, d, s, 0);
		__write_sig(&obj_lfsr, d, s, 1);
		__write_sig(&off_lfsr, d, s, 2);
	} else {
		if (__read_sig(&id_lfsr, d, s, 0))
			return 1;
		if (__read_sig(&obj_lfsr, d, s, 1))
			return 1;
		if(__read_sig(&off_lfsr, d, s, 2))
			return 1;
	}

	return 0;
}

static int readwrite_chunk_meta(struct bench *prefs, struct xseg_request *req)
{
	struct xseg *xseg = prefs->peer->xseg;
	struct signature sig;
	uint64_t id = prefs->objvars->seed;
	uint64_t object = prefs->objvars->objnum;
	char *d = xseg_get_data(xseg, req);
	uint64_t s = req->size;
	int sig_s = sizeof(struct signature);
	int r = 0;

	sig.id = id;
	sig.object = object;
	sig.offset = req->offset;

	if (s < sig_s) {
		XSEGLOG2(&lc, E, "Too small chunk size (%lu butes). "
				"Leaving.", s);
		return 1;
	}

	//PRINT_SIG(expected, (&sig));
	/* Read/Write chunk signature both at its start and at its end */
	if (req->op == X_WRITE) {
		memcpy(d, &sig, sig_s);
		memcpy(d + s - sig_s, &sig, sig_s);
	} else {
		if (memcmp(d, &sig, sig_s))
			r = 1;
		else if (memcmp(d + s - sig_s, &sig, sig_s))
			r = 1;
	}
	//PRINT_SIG(start, d);
	//PRINT_SIG(end, (d + s - sig_s));
	return r;
}

/*
 * We want these functions to be as fast as possible in case we haven't asked
 * for verification
 */
void create_chunk(struct bench *prefs, struct xseg_request *req, uint64_t new)
{
	int verify;

	verify = GET_FLAG(VERIFY, prefs->flags);
	switch (verify) {
		case VERIFY_NO:
			break;
		case VERIFY_META:
			readwrite_chunk_meta(prefs, req);
			break;
		case VERIFY_FULL:
			readwrite_chunk_full(prefs, req);
			break;
		default:
			XSEGLOG2(&lc, W, "Unexpected verification mode: %d\n",
					verify);
	}
}

int read_chunk(struct bench *prefs, struct xseg_request *req)
{
	struct xseg *xseg = prefs->peer->xseg;
	struct object_vars *obv = prefs->objvars;
	char *target;
	int verify;
	int r = 0;

	verify = GET_FLAG(VERIFY, prefs->flags);
	switch (verify) {
		case VERIFY_NO:
			break;
		case VERIFY_META:
			target = xseg_get_target(xseg, req);
			obv->objnum = __get_object_from_name(obv, target);
			r = readwrite_chunk_meta(prefs, req);
			break;
		case VERIFY_FULL:
			target = xseg_get_target(xseg, req);
			obv->objnum = __get_object_from_name(obv, target);
			r = readwrite_chunk_full(prefs, req);
			break;
		default:
			XSEGLOG2(&lc, W, "Unexpected verification mode: %d\n",
					verify);
	}
	return r;
}

