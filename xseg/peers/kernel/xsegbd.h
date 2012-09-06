#ifndef _XSEGBD_REAR
#define _XSEGBD_REAR

#define XSEGBD_NAME "xsegbd"

#define XSEGBD_SEGMENT_NAMELEN 32
#define XSEGBD_TARGET_NAMELEN 127

#include <linux/kernel.h>
#include <linux/types.h>
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
	spinlock_t reqdatalock;
	struct request_queue *blk_queue;
	struct gendisk *gd;
	int id;
	int major;
	sector_t sectors;
	uint64_t segsize;
	uint32_t src_portno, dst_portno, nr_requests;
	struct xq blk_queue_pending;
	struct xsegbd *xsegbd;
	struct xsegbd_pending *blk_req_pending;
	struct device dev;
	struct list_head node;
	char target[XSEGBD_TARGET_NAMELEN + 1];
	uint32_t targetlen;
};

#endif
