#ifndef _PROTOCOL_H
#define _PROTOCOL_H

#include <stdint.h>

/*
 * Reply structures.
 * Every X_OP returns a corresponding xseg_reply_op struct
 * for structured replies. See <xseg/xseg.h> for the list of ops.
 */
struct xseg_reply_info {
	uint64_t size;
};

#ifndef XSEG_MAX_TARGETLEN
#define XSEG_MAX_TARGETLEN 256
#endif

#if (XSEG_MAX_TARGETLEN < 64)
#pragma message("XSEG_MAX_TARGETLEN should be at least 64!")
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


#endif
