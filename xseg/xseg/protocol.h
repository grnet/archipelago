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

#ifndef _PROTOCOL_H
#define _PROTOCOL_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

/*
 * Reply structures.
 * Every X_OP returns a corresponding xseg_reply_op struct
 * for structured replies. See <xseg/xseg.h> for the list of ops.
 */
struct xseg_reply_info {
	uint64_t size;
};

#define XSEG_MAX_TARGETLEN 256

#if (XSEG_MAX_TARGETLEN < 64)
#warning "XSEG_MAX_TARGETLEN should be at least 64!"
#undef XSEG_MAX_TARGETLEN
#define XSEG_MAX_TARGETLEN 64
#endif

struct xseg_reply_map_scatterlist {
	char target[XSEG_MAX_TARGETLEN];
	uint32_t targetlen;
	uint64_t offset;
	uint64_t size;
};

struct xseg_reply_map {
	uint32_t cnt;
	struct xseg_reply_map_scatterlist segs[];
};

struct xseg_request_clone {
        char target[XSEG_MAX_TARGETLEN];
	uint32_t targetlen;
        uint64_t size;
};

struct xseg_request_copy {
        char target[XSEG_MAX_TARGETLEN];
	uint32_t targetlen;
};

struct xseg_request_snapshot {
        char target[XSEG_MAX_TARGETLEN];
	uint32_t targetlen;
};

struct xseg_reply_hash {
	char target[XSEG_MAX_TARGETLEN];
	uint32_t targetlen;
};

#endif
