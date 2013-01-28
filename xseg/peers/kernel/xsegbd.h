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

#ifndef _XSEGBD_REAR
#define _XSEGBD_REAR

#define XSEGBD_NAME "xsegbd"

#define XSEGBD_SEGMENT_NAMELEN 32
#define XSEGBD_TARGET_NAMELEN 127

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <xseg/xseg.h>
#include <xtypes/xq.h>

struct xsegbd_device;

struct xsegbd_pending {
	struct request *request;
	struct completion *comp;
	struct xsegbd_device *dev;
};

struct xsegbd {
	char name[XSEGBD_SEGMENT_NAMELEN];
	struct xseg_config config;
	struct xseg *xseg;
};

struct xsegbd_device {
	struct xseg *xseg;
	spinlock_t rqlock;
	struct request_queue *blk_queue;
	struct gendisk *gd;
	int id;
	int major;
	sector_t sectors;
	uint64_t segsize;
	xport src_portno, dst_portno;
	uint32_t  nr_requests;
	struct xq blk_queue_pending;
	struct xsegbd *xsegbd;
	struct xsegbd_pending *blk_req_pending;
	struct device dev;
	struct list_head node;
	char target[XSEGBD_TARGET_NAMELEN + 1];
	uint32_t targetlen;
};

void __xsegbd_get(struct xsegbd_device *xsegbd_dev);
void __xsegbd_put(struct xsegbd_device *xsegbd_dev);
struct xsegbd_device *__xsegbd_get_dev(unsigned long id);
#endif
