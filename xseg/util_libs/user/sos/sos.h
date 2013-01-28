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

#ifndef _SOS_H
#define _SOS_H

#include <stdlib.h>
#include <stdint.h>

struct sos_request {
	unsigned long id;		/* request id 			*/
	char *target;			/* target object name 		*/
	uint32_t targetlen;		/* target object name length	*/
	uint64_t offset;		/* target object offset 	*/
	uint64_t size;			/* requested size of data 	*/
	char *data;			/* data pointer 		*/
	uint32_t flags;			/* request flags		*/	
	volatile unsigned long state;	/* state of request 		*/
	int retval;			/* return value of the operation*/
	uint32_t op;			/* operation to be performed	*/
	void *priv;			/* private data 		*/
};

/* OPS */
#define S_NONE	0
#define S_READ	1
#define S_WRITE	2

typedef int (*sos_cb_t)(struct sos_request *req, unsigned long event_flags);

struct sos_handle;
typedef struct sos_handle *sos_handle_t;

sos_handle_t sos_init(sos_cb_t cb);
void sos_shut(sos_handle_t sos);
int sos_submit(sos_handle_t sos, struct sos_request *req);

void sos_set_debug_level(unsigned int level);
/* sos notify flags */
#define S_NOTIFY_FAIL	(1 << 0)
#define S_NOTIFY_ACK 	(1 << 1)
#define S_NOTIFY_COMMIT	(1 << 2)

#define SOS_POOL "sos"

/* sos request states */
#define S_PENDING 	(1 << 0)
#define S_ACKED 	(1 << 1)
#define S_COMMITED	(1 << 2)
#define S_FAILED 	(1 << 3)

/* sos request flags */
#define SF_SYNC		(1 << 1)
#define SF_FLUSH	(1 << 2)
#define SF_FUA		(1 << 3)


#endif	/* _SOS_H */
