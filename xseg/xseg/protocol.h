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

#define XSEG_MAX_TARGETLEN 256

struct xseg_reply_map_scatterlist {
	char target[XSEG_MAX_TARGETLEN];
	uint64_t offset;
	uint64_t size;
};

struct xseg_reply_map {
	uint32_t cnt;
	struct xseg_reply_map_scatterlist segs[];
};

struct xseg_request_clone {
        char target[XSEG_MAX_TARGETLEN];
        uint64_t size;
};

struct xseg_request_copy {
        char target[XSEG_MAX_TARGETLEN];
};


#endif
