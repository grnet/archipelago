#ifndef _XSEGBD_REAR
#define _XSEGBD_REAR

#define XSEGBD_NAME "xsegbd"

#define XSEGLOG_PREFIX KERN_INFO XSEGBD_NAME ": "
#define XSEGLOG(message, args...) printk(XSEGLOG_PREFIX message "\n", ##args)

#define XSEGBD_VOLUME_NAMELEN 32

#include <linux/kernel.h>
#include <linux/types.h>
#include <xseg/xseg.h>
#include <xq/xq.h>

struct xsegbd {
	spinlock_t lock;
	struct request_queue *blk_queue;
	struct gendisk *gd;
        int id;
	struct xsegbd_backer *backer;
	sector_t sectors;
	uint64_t segsize;
	char name[XSEGBD_VOLUME_NAMELEN];
	uint32_t namesize;
	struct xseg_config config;
	struct xseg *xseg;
	uint32_t src_portno, dst_portno;
	struct xq blk_queue_pending;
	char *_blk_queue_mem;
	struct request **blk_req_pending;
};

#endif
