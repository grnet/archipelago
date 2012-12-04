/*
 * Copyright (C) 2012 GRNET S.A.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/* xsegbd.c
 *
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/device.h>
#include <linux/completion.h>
#include <linux/wait.h>
#include <sys/kernel/segdev.h>
#include "xsegbd.h"
#include <xseg/protocol.h>

#define XSEGBD_MINORS 1
/* define max request size to be used in xsegbd */
#define XSEGBD_MAX_REQUEST_SIZE 4194304U

MODULE_DESCRIPTION("xsegbd");
MODULE_AUTHOR("XSEG");
MODULE_LICENSE("GPL");

static long sector_size = 0;
static long blksize = 512;
static int major = 0;
static int max_dev = 200;
static long start_portno = 0;
static long end_portno = 199;
static char name[XSEGBD_SEGMENT_NAMELEN] = "xsegbd";
static char spec[256] = "segdev:xsegbd:512:1024:12";

module_param(sector_size, long, 0644);
module_param(blksize, long, 0644);
module_param(start_portno, long, 0644);
module_param(end_portno, long, 0644);
module_param(major, int, 0644);
module_param_string(name, name, sizeof(name), 0644);
module_param_string(spec, spec, sizeof(spec), 0644);

static struct xsegbd xsegbd;
static struct xsegbd_device **xsegbd_devices; /* indexed by portno */
static DEFINE_MUTEX(xsegbd_mutex);
static DEFINE_SPINLOCK(xsegbd_devices_lock);


struct xsegbd_device *__xsegbd_get_dev(unsigned long id)
{
	struct xsegbd_device *xsegbd_dev = NULL;

	spin_lock(&xsegbd_devices_lock);
	xsegbd_dev = xsegbd_devices[id];
	spin_unlock(&xsegbd_devices_lock);

	return xsegbd_dev;
}

static int src_portno_to_id(xport src_portno)
{
	return (src_portno - start_portno);
}

/* ************************* */
/* ***** sysfs helpers ***** */
/* ************************* */

static struct xsegbd_device *dev_to_xsegbd(struct device *dev)
{
	return container_of(dev, struct xsegbd_device, dev);
}

static struct device *xsegbd_get_dev(struct xsegbd_device *xsegbd_dev)
{
	/* FIXME */
	return get_device(&xsegbd_dev->dev);
}

static void xsegbd_put_dev(struct xsegbd_device *xsegbd_dev)
{
	put_device(&xsegbd_dev->dev);
}

/* ************************* */
/* ** XSEG Initialization ** */
/* ************************* */

static void xseg_callback(uint32_t portno);

int xsegbd_xseg_init(void)
{
	int r;

	if (!xsegbd.name[0])
		strncpy(xsegbd.name, name, XSEGBD_SEGMENT_NAMELEN);

	r = xseg_initialize();
	if (r) {
		XSEGLOG("cannot initialize 'segdev' peer");
		goto err;
	}

	r = xseg_parse_spec(spec, &xsegbd.config);
	if (r)
		goto err;

	if (strncmp(xsegbd.config.type, "segdev", 16))
		XSEGLOG("WARNING: unexpected segment type '%s' vs 'segdev'",
			 xsegbd.config.type);

	/* leave it here for now */
	XSEGLOG("joining segment");
	xsegbd.xseg = xseg_join(	xsegbd.config.type,
					xsegbd.config.name,
					"segdev",
					xseg_callback		);
	if (!xsegbd.xseg) {
		XSEGLOG("cannot find segment");
		r = -ENODEV;
		goto err;
	}

	return 0;
err:
	return r;

}

int xsegbd_xseg_quit(void)
{
	struct segdev *segdev;

	/* make sure to unmap the segment first */
	segdev = segdev_get(0);
	clear_bit(SEGDEV_RESERVED, &segdev->flags);
	xsegbd.xseg->priv->segment_type.ops.unmap(xsegbd.xseg, xsegbd.xseg->segment_size);
	segdev_put(segdev);

	return 0;
}


/* ***************************** */
/* ** Block Device Operations ** */
/* ***************************** */

static int xsegbd_open(struct block_device *bdev, fmode_t mode)
{
	struct gendisk *disk = bdev->bd_disk;
	struct xsegbd_device *xsegbd_dev = disk->private_data;

	xsegbd_get_dev(xsegbd_dev);

	return 0;
}

static int xsegbd_release(struct gendisk *gd, fmode_t mode)
{
	struct xsegbd_device *xsegbd_dev = gd->private_data;

	xsegbd_put_dev(xsegbd_dev);

	return 0;
}

static int xsegbd_ioctl(struct block_device *bdev, fmode_t mode,
			unsigned int cmd, unsigned long arg)
{
	return -ENOTTY;
}

static const struct block_device_operations xsegbd_ops = {
	.owner		= THIS_MODULE,
	.open		= xsegbd_open,
	.release	= xsegbd_release,
	.ioctl		= xsegbd_ioctl 
};


/* *************************** */
/* ** Device Initialization ** */
/* *************************** */

static void xseg_request_fn(struct request_queue *rq);
static int xsegbd_get_size(struct xsegbd_device *xsegbd_dev);
static int xsegbd_mapclose(struct xsegbd_device *xsegbd_dev);

static int xsegbd_dev_init(struct xsegbd_device *xsegbd_dev)
{
	int ret = -ENOMEM;
	struct gendisk *disk;
	unsigned int max_request_size_bytes;

	spin_lock_init(&xsegbd_dev->rqlock);

	xsegbd_dev->xsegbd = &xsegbd;

	/* allocates and initializes queue */
	xsegbd_dev->blk_queue = blk_init_queue(xseg_request_fn, &xsegbd_dev->rqlock);
	if (!xsegbd_dev->blk_queue)
		goto out;

	xsegbd_dev->blk_queue->queuedata = xsegbd_dev;

	blk_queue_flush(xsegbd_dev->blk_queue, REQ_FLUSH | REQ_FUA);
	blk_queue_logical_block_size(xsegbd_dev->blk_queue, 512);
	blk_queue_physical_block_size(xsegbd_dev->blk_queue, blksize);
	blk_queue_bounce_limit(xsegbd_dev->blk_queue, BLK_BOUNCE_ANY);
	

	max_request_size_bytes = XSEGBD_MAX_REQUEST_SIZE;
	blk_queue_max_hw_sectors(xsegbd_dev->blk_queue, max_request_size_bytes >> 9);
//	blk_queue_max_sectors(xsegbd_dev->blk_queue, max_request_size_bytes >> 10);
	blk_queue_max_segments(xsegbd_dev->blk_queue, 1024);
	blk_queue_max_segment_size(xsegbd_dev->blk_queue, max_request_size_bytes);
	blk_queue_io_min(xsegbd_dev->blk_queue, max_request_size_bytes);
	blk_queue_io_opt(xsegbd_dev->blk_queue, max_request_size_bytes);

	queue_flag_set_unlocked(QUEUE_FLAG_NONROT, xsegbd_dev->blk_queue);

	/* vkoukis says we don't need partitions */
	xsegbd_dev->gd = disk = alloc_disk(XSEGBD_MINORS);
	if (!disk)
		goto out;

	disk->major = xsegbd_dev->major;
	disk->first_minor = xsegbd_dev->id * XSEGBD_MINORS;
	disk->fops = &xsegbd_ops;
	disk->queue = xsegbd_dev->blk_queue;
	disk->private_data = xsegbd_dev;
	disk->flags |= GENHD_FL_SUPPRESS_PARTITION_INFO;
	snprintf(disk->disk_name, 32, "xsegbd%u", xsegbd_dev->id);

	ret = 0;

	/* allow a non-zero sector_size parameter to override the disk size */
	if (sector_size)
		xsegbd_dev->sectors = sector_size;
	else {
		ret = xsegbd_get_size(xsegbd_dev);
		if (ret)
			goto out;
	}

	set_capacity(disk, xsegbd_dev->sectors);
	XSEGLOG("xsegbd active...");
	add_disk(disk); /* immediately activates the device */

out:
	/* on error, everything is cleaned up in xsegbd_dev_release */
	return ret;
}

static void xsegbd_dev_release(struct device *dev)
{
	struct xsegbd_device *xsegbd_dev = dev_to_xsegbd(dev);


	/* cleanup gendisk and blk_queue the right way */
	if (xsegbd_dev->gd) {
		if (xsegbd_dev->gd->flags & GENHD_FL_UP)
			del_gendisk(xsegbd_dev->gd);

		xsegbd_mapclose(xsegbd_dev);
	}

	spin_lock(&xsegbd_devices_lock);
	BUG_ON(xsegbd_devices[xsegbd_dev->id] != xsegbd_dev);
	xsegbd_devices[xsegbd_dev->id] = NULL;
	spin_unlock(&xsegbd_devices_lock);

	XSEGLOG("releasing id: %d", xsegbd_dev->id);
//	xseg_cancel_wait(xsegbd_dev->xseg, xsegbd_dev->src_portno);
	xseg_quit_local_signal(xsegbd_dev->xseg, xsegbd_dev->src_portno);

	if (xsegbd_dev->blk_queue)
		blk_cleanup_queue(xsegbd_dev->blk_queue);
	if (xsegbd_dev->gd)
		put_disk(xsegbd_dev->gd);

//	if (xseg_free_requests(xsegbd_dev->xseg,
//			xsegbd_dev->src_portno, xsegbd_dev->nr_requests) < 0)
//		XSEGLOG("Error trying to free requests!\n");

	if (xsegbd_dev->xseg){
		xseg_leave(xsegbd_dev->xseg);
		xsegbd_dev->xseg = NULL;
	}

	if (xsegbd_dev->blk_req_pending){
		kfree(xsegbd_dev->blk_req_pending);
		xsegbd_dev->blk_req_pending = NULL;
	}
	xq_free(&xsegbd_dev->blk_queue_pending);
	kfree(xsegbd_dev);
	module_put(THIS_MODULE);
}

/* ******************* */
/* ** Critical Path ** */
/* ******************* */

static void blk_to_xseg(struct xseg *xseg, struct xseg_request *xreq,
			struct request *blkreq)
{
	struct bio_vec *bvec;
	struct req_iterator iter;
	uint64_t off = 0;
	char *data = xseg_get_data(xseg, xreq);
	rq_for_each_segment(bvec, blkreq, iter) {
		char *bdata = kmap_atomic(bvec->bv_page) + bvec->bv_offset;
		memcpy(data + off, bdata, bvec->bv_len);
		off += bvec->bv_len;
		kunmap_atomic(bdata);
	}
}

static void xseg_to_blk(struct xseg *xseg, struct xseg_request *xreq,
			struct request *blkreq)
{
	struct bio_vec *bvec;
	struct req_iterator iter;
	uint64_t off = 0;
	char *data = xseg_get_data(xseg, xreq);
	rq_for_each_segment(bvec, blkreq, iter) {
		char *bdata = kmap_atomic(bvec->bv_page) + bvec->bv_offset;
		memcpy(bdata, data + off, bvec->bv_len);
		off += bvec->bv_len;
		kunmap_atomic(bdata);
	}
}

static void xseg_request_fn(struct request_queue *rq)
{
	struct xseg_request *xreq;
	struct xsegbd_device *xsegbd_dev = rq->queuedata;
	struct request *blkreq;
	struct xsegbd_pending *pending;
	xqindex blkreq_idx;
	char *target;
	uint64_t datalen;
	xport p;
	int r;
	unsigned long flags;

	spin_unlock_irq(&xsegbd_dev->rqlock);
	for (;;) {
		if (current_thread_info()->preempt_count || irqs_disabled()){
			XSEGLOG("Current thread preempt_count: %d, irqs_disabled(): %lu ",
					current_thread_info()->preempt_count, irqs_disabled());
		}
		//XSEGLOG("Priority: %d", current_thread_info()->task->prio);
		//XSEGLOG("Static priority: %d", current_thread_info()->task->static_prio);
		//XSEGLOG("Normal priority: %d", current_thread_info()->task->normal_prio);
		//XSEGLOG("Rt_priority: %u", current_thread_info()->task->rt_priority);
		blkreq_idx = Noneidx;
		xreq = xseg_get_request(xsegbd_dev->xseg, xsegbd_dev->src_portno, 
				xsegbd_dev->dst_portno, X_ALLOC);
		if (!xreq)
			break;

		blkreq_idx = xq_pop_head(&xsegbd_dev->blk_queue_pending, 
						xsegbd_dev->src_portno);
		if (blkreq_idx == Noneidx)
			break;

		if (blkreq_idx >= xsegbd_dev->nr_requests) {
			XSEGLOG("blkreq_idx >= xsegbd_dev->nr_requests");
			BUG_ON(1);
			break;
		}


		spin_lock_irqsave(&xsegbd_dev->rqlock, flags);
		blkreq = blk_fetch_request(rq);
		if (!blkreq){
			spin_unlock_irqrestore(&xsegbd_dev->rqlock, flags);
			break;
		}

		if (blkreq->cmd_type != REQ_TYPE_FS) {
			//FIXME we lose xreq here
			XSEGLOG("non-fs cmd_type: %u. *shrug*", blkreq->cmd_type);
			__blk_end_request_all(blkreq, 0);
			spin_unlock_irqrestore(&xsegbd_dev->rqlock, flags);
			continue;
		}
		spin_unlock_irqrestore(&xsegbd_dev->rqlock, flags);
		if (current_thread_info()->preempt_count || irqs_disabled()){
			XSEGLOG("Current thread preempt_count: %d, irqs_disabled(): %lu ",
					current_thread_info()->preempt_count, irqs_disabled());
		}

		datalen = blk_rq_bytes(blkreq);
		r = xseg_prep_request(xsegbd_dev->xseg, xreq, 
					xsegbd_dev->targetlen, datalen);
		if (r < 0) {
			XSEGLOG("couldn't prep request");
			blk_end_request_err(blkreq, r);
			BUG_ON(1);
			break;
		}
		r = -ENOMEM;
		if (xreq->bufferlen - xsegbd_dev->targetlen < datalen){
			XSEGLOG("malformed req buffers");
			blk_end_request_err(blkreq, r);
			BUG_ON(1);
			break;
		}

		target = xseg_get_target(xsegbd_dev->xseg, xreq);
		strncpy(target, xsegbd_dev->target, xsegbd_dev->targetlen);

		pending = &xsegbd_dev->blk_req_pending[blkreq_idx];
		pending->dev = xsegbd_dev;
		pending->request = blkreq;
		pending->comp = NULL;

		xreq->size = datalen;
		xreq->offset = blk_rq_pos(blkreq) << 9;
		xreq->priv = (uint64_t) blkreq_idx;

		/*
		if (xreq->offset >= (sector_size << 9))
			XSEGLOG("sector offset: %lu > %lu, flush:%u, fua:%u",
				 blk_rq_pos(blkreq), sector_size,
				 blkreq->cmd_flags & REQ_FLUSH,
				 blkreq->cmd_flags & REQ_FUA);
		*/

		if (blkreq->cmd_flags & REQ_FLUSH)
			xreq->flags |= XF_FLUSH;

		if (blkreq->cmd_flags & REQ_FUA)
			xreq->flags |= XF_FUA;

		if (rq_data_dir(blkreq)) {
			blk_to_xseg(xsegbd_dev->xseg, xreq, blkreq);
			xreq->op = X_WRITE;
		} else {
			xreq->op = X_READ;
		}


//		XSEGLOG("%s : %lu (%lu)", xsegbd_dev->target, xreq->offset, xreq->datalen);
		r = -EIO;
		p = xseg_submit(xsegbd_dev->xseg, xreq, 
					xsegbd_dev->src_portno, X_ALLOC);
		if (p == NoPort) {
			XSEGLOG("coundn't submit req");
			WARN_ON(1);
			blk_end_request_err(blkreq, r);
			break;
		}
		WARN_ON(xseg_signal(xsegbd_dev->xsegbd->xseg, p) < 0);
	}
	if (xreq)
		BUG_ON(xseg_put_request(xsegbd_dev->xsegbd->xseg, xreq, 
					xsegbd_dev->src_portno) == -1);
	if (blkreq_idx != Noneidx)
		BUG_ON(xq_append_head(&xsegbd_dev->blk_queue_pending, 
				blkreq_idx, xsegbd_dev->src_portno) == Noneidx);
	spin_lock_irq(&xsegbd_dev->rqlock);
}

int update_dev_sectors_from_request(	struct xsegbd_device *xsegbd_dev,
					struct xseg_request *xreq	)
{
	void *data;
	if (!xreq) {
		XSEGLOG("Invalid xreq");
		return -EIO;
	}

	if (xreq->state & XS_FAILED)
		return -ENOENT;

	if (!(xreq->state & XS_SERVED))
		return -EIO;

	data = xseg_get_data(xsegbd_dev->xseg, xreq);
	if (!data) {
		XSEGLOG("Invalid req data");
		return -EIO;
	}
	if (!xsegbd_dev) {
		XSEGLOG("Invalid xsegbd_dev");
		return -ENOENT;
	}
	xsegbd_dev->sectors = *((uint64_t *) data) / 512ULL;
	return 0;
}

static int xsegbd_get_size(struct xsegbd_device *xsegbd_dev)
{
	struct xseg_request *xreq;
	char *target;
	xqindex blkreq_idx;
	struct xsegbd_pending *pending;
	struct completion comp;
	xport p;
	int ret = -EBUSY;

	xreq = xseg_get_request(xsegbd_dev->xseg, xsegbd_dev->src_portno,
			xsegbd_dev->dst_portno, X_ALLOC);
	if (!xreq)
		goto out;

	BUG_ON(xseg_prep_request(xsegbd_dev->xseg, xreq, xsegbd_dev->targetlen, 
				sizeof(struct xseg_reply_info)));

	init_completion(&comp);
	blkreq_idx = xq_pop_head(&xsegbd_dev->blk_queue_pending, 1);
	if (blkreq_idx == Noneidx)
		goto out_put;

	pending = &xsegbd_dev->blk_req_pending[blkreq_idx];
	pending->dev = xsegbd_dev;
	pending->request = NULL;
	pending->comp = &comp;


	xreq->priv = (uint64_t) blkreq_idx;

	target = xseg_get_target(xsegbd_dev->xseg, xreq);
	strncpy(target, xsegbd_dev->target, xsegbd_dev->targetlen);
	xreq->size = xreq->datalen;
	xreq->offset = 0;
	xreq->op = X_INFO;

	xseg_prepare_wait(xsegbd_dev->xseg, xsegbd_dev->src_portno);
	p = xseg_submit(xsegbd_dev->xseg, xreq,
				xsegbd_dev->src_portno, X_ALLOC);
	if ( p == NoPort) {
		XSEGLOG("couldn't submit request");
		BUG_ON(1);
		goto out_queue;
	}
	WARN_ON(xseg_signal(xsegbd_dev->xseg, p) < 0);
	XSEGLOG("Before wait for completion, comp %lx [%llu]", (unsigned long) pending->comp, (unsigned long long) blkreq_idx);
	wait_for_completion_interruptible(&comp);
	XSEGLOG("Woken up after wait_for_completion_interruptible(), comp: %lx [%llu]", (unsigned long) pending->comp, (unsigned long long) blkreq_idx);
	ret = update_dev_sectors_from_request(xsegbd_dev, xreq);
	XSEGLOG("get_size: sectors = %ld\n", (long)xsegbd_dev->sectors);

out_queue:
	pending->dev = NULL;
	pending->comp = NULL;
	xq_append_head(&xsegbd_dev->blk_queue_pending, blkreq_idx, 1);
out_put:
	BUG_ON(xseg_put_request(xsegbd_dev->xseg, xreq, xsegbd_dev->src_portno) == -1);
out:
	return ret;
}

static int xsegbd_mapclose(struct xsegbd_device *xsegbd_dev)
{
	struct xseg_request *xreq;
	char *target;
	xqindex blkreq_idx;
	struct xsegbd_pending *pending;
	struct completion comp;
	xport p;
	int ret = -EBUSY;

	xreq = xseg_get_request(xsegbd_dev->xseg, xsegbd_dev->src_portno,
			xsegbd_dev->dst_portno, X_ALLOC);
	if (!xreq)
		goto out;

	BUG_ON(xseg_prep_request(xsegbd_dev->xseg, xreq, xsegbd_dev->targetlen, 0));

	init_completion(&comp);
	blkreq_idx = xq_pop_head(&xsegbd_dev->blk_queue_pending, 1);
	if (blkreq_idx == Noneidx)
		goto out_put;

	pending = &xsegbd_dev->blk_req_pending[blkreq_idx];
	pending->dev = xsegbd_dev;
	pending->request = NULL;
	pending->comp = &comp;


	xreq->priv = (uint64_t) blkreq_idx;

	target = xseg_get_target(xsegbd_dev->xseg, xreq);
	strncpy(target, xsegbd_dev->target, xsegbd_dev->targetlen);
	xreq->size = xreq->datalen;
	xreq->offset = 0;
	xreq->op = X_CLOSE;

	xseg_prepare_wait(xsegbd_dev->xseg, xsegbd_dev->src_portno);
	p = xseg_submit(xsegbd_dev->xseg, xreq, 
				xsegbd_dev->src_portno, X_ALLOC);
	if ( p == NoPort) {
		XSEGLOG("couldn't submit request");
		BUG_ON(1);
		goto out_queue;
	}
	WARN_ON(xseg_signal(xsegbd_dev->xseg, p) < 0);
	wait_for_completion_interruptible(&comp);
	ret = 0;
	if (xreq->state & XS_FAILED)
		XSEGLOG("Couldn't close disk on mapper");

out_queue:
	pending->dev = NULL;
	pending->comp = NULL;
	xq_append_head(&xsegbd_dev->blk_queue_pending, blkreq_idx, 1);
out_put:
	BUG_ON(xseg_put_request(xsegbd_dev->xseg, xreq, xsegbd_dev->src_portno) == -1);
out:
	return ret;
}

static void xseg_callback(xport portno)
{
	struct xsegbd_device *xsegbd_dev;
	struct xseg_request *xreq;
	struct request *blkreq;
	struct xsegbd_pending *pending;
	unsigned long flags;
	xqindex blkreq_idx, ridx;
	int err;

	xsegbd_dev  = __xsegbd_get_dev(portno);
	if (!xsegbd_dev) {
		XSEGLOG("portno: %u has no xsegbd device assigned", portno);
		WARN_ON(1);
		return;
	}

	for (;;) {
		xseg_prepare_wait(xsegbd_dev->xseg, xsegbd_dev->src_portno);
		xreq = xseg_receive(xsegbd_dev->xseg, portno, 0);
		if (!xreq)
			break;

//		xseg_cancel_wait(xsegbd_dev->xseg, xsegbd_dev->src_portno);

		blkreq_idx = (xqindex) xreq->priv;
		if (blkreq_idx >= xsegbd_dev->nr_requests) {
			WARN_ON(1);
			//FIXME maybe put request?
			continue;
		}

		pending = &xsegbd_dev->blk_req_pending[blkreq_idx];
		if (pending->comp) {
			/* someone is blocking on this request
			   and will handle it when we wake them up. */
			complete(pending->comp);
			/* the request is blocker's responsibility so
			   we will not put_request(); */
			continue;
		}

		/* this is now treated as a block I/O request to end */
		blkreq = pending->request;
		pending->request = NULL;
		if (xsegbd_dev != pending->dev) {
			//FIXME maybe put request?
			XSEGLOG("xsegbd_dev != pending->dev");
			WARN_ON(1);
			continue;
		}
		pending->dev = NULL;
		if (!blkreq){
			//FIXME maybe put request?
			XSEGLOG("blkreq does not exist");
			WARN_ON(1);
			continue;
		}

		err = -EIO;
		if (!(xreq->state & XS_SERVED))
			goto blk_end;

		if (xreq->serviced != blk_rq_bytes(blkreq))
			goto blk_end;

		err = 0;
		if (!rq_data_dir(blkreq)){
			xseg_to_blk(xsegbd_dev->xseg, xreq, blkreq);
		}
blk_end:
		blk_end_request_all(blkreq, err);

		ridx = xq_append_head(&xsegbd_dev->blk_queue_pending, 
					blkreq_idx, xsegbd_dev->src_portno);
		if (ridx == Noneidx) {
			XSEGLOG("couldnt append blkreq_idx");
			WARN_ON(1);
		}

		if (xseg_put_request(xsegbd_dev->xseg, xreq, 
						xsegbd_dev->src_portno) < 0){
			XSEGLOG("couldn't put req");
			BUG_ON(1);
		}
	}
	if (xsegbd_dev) {
		spin_lock_irqsave(&xsegbd_dev->rqlock, flags);
		xseg_request_fn(xsegbd_dev->blk_queue);
		spin_unlock_irqrestore(&xsegbd_dev->rqlock, flags);
	}
}


/* sysfs interface */

static struct bus_type xsegbd_bus_type = {
	.name	= "xsegbd",
};

static ssize_t xsegbd_size_show(struct device *dev,
					struct device_attribute *attr, char *buf)
{
	struct xsegbd_device *xsegbd_dev = dev_to_xsegbd(dev);

	return sprintf(buf, "%llu\n", (unsigned long long) xsegbd_dev->sectors * 512ULL);
}

static ssize_t xsegbd_major_show(struct device *dev,
					struct device_attribute *attr, char *buf)
{
	struct xsegbd_device *xsegbd_dev = dev_to_xsegbd(dev);

	return sprintf(buf, "%d\n", xsegbd_dev->major);
}

static ssize_t xsegbd_srcport_show(struct device *dev,
					struct device_attribute *attr, char *buf)
{
	struct xsegbd_device *xsegbd_dev = dev_to_xsegbd(dev);

	return sprintf(buf, "%u\n", (unsigned) xsegbd_dev->src_portno);
}

static ssize_t xsegbd_dstport_show(struct device *dev,
					struct device_attribute *attr, char *buf)
{
	struct xsegbd_device *xsegbd_dev = dev_to_xsegbd(dev);

	return sprintf(buf, "%u\n", (unsigned) xsegbd_dev->dst_portno);
}

static ssize_t xsegbd_id_show(struct device *dev,
					struct device_attribute *attr, char *buf)
{
	struct xsegbd_device *xsegbd_dev = dev_to_xsegbd(dev);

	return sprintf(buf, "%u\n", (unsigned) xsegbd_dev->id);
}

static ssize_t xsegbd_reqs_show(struct device *dev,
					struct device_attribute *attr, char *buf)
{
	struct xsegbd_device *xsegbd_dev = dev_to_xsegbd(dev);

	return sprintf(buf, "%u\n", (unsigned) xsegbd_dev->nr_requests);
}

static ssize_t xsegbd_target_show(struct device *dev,
					struct device_attribute *attr, char *buf)
{
	struct xsegbd_device *xsegbd_dev = dev_to_xsegbd(dev);

	return sprintf(buf, "%s\n", xsegbd_dev->target);
}

static ssize_t xsegbd_image_refresh(struct device *dev,
					struct device_attribute *attr,
					const char *buf,
					size_t size)
{
	struct xsegbd_device *xsegbd_dev = dev_to_xsegbd(dev);
	int rc, ret = size;

	mutex_lock_nested(&xsegbd_mutex, SINGLE_DEPTH_NESTING);

	rc = xsegbd_get_size(xsegbd_dev);
	if (rc < 0) {
		ret = rc;
		goto out;
	}

	set_capacity(xsegbd_dev->gd, xsegbd_dev->sectors);

out:
	mutex_unlock(&xsegbd_mutex);
	return ret;
}

//FIXME
//maybe try callback, first and then do a more invasive cleanup
static ssize_t xsegbd_cleanup(struct device *dev,
					struct device_attribute *attr,
					const char *buf,
					size_t size)
{
	struct xsegbd_device *xsegbd_dev = dev_to_xsegbd(dev);
	int ret = size, i;
	struct request *blkreq = NULL;
	struct xsegbd_pending *pending = NULL;
	struct completion *comp = NULL;

	mutex_lock_nested(&xsegbd_mutex, SINGLE_DEPTH_NESTING);
	xlock_acquire(&xsegbd_dev->blk_queue_pending.lock, 
				xsegbd_dev->src_portno);
	for (i = 0; i < xsegbd_dev->nr_requests; i++) {
		if (!__xq_check(&xsegbd_dev->blk_queue_pending, i)) {
			pending = &xsegbd_dev->blk_req_pending[i];
			blkreq = pending->request;
			pending->request = NULL;
			comp = pending->comp;
			pending->comp = NULL;
			if (blkreq){
				XSEGLOG("Cleaning up blkreq %lx [%d]", (unsigned long) blkreq, i);
				blk_end_request_all(blkreq, -EIO);
			}
			if (comp){
				XSEGLOG("Cleaning up comp %lx [%d]", (unsigned long) comp, i);
				complete(comp);
			}
			__xq_append_tail(&xsegbd_dev->blk_queue_pending, i);
		}
	}
	xlock_release(&xsegbd_dev->blk_queue_pending.lock);

	mutex_unlock(&xsegbd_mutex);
	return ret;
}

static DEVICE_ATTR(size, S_IRUGO, xsegbd_size_show, NULL);
static DEVICE_ATTR(major, S_IRUGO, xsegbd_major_show, NULL);
static DEVICE_ATTR(srcport, S_IRUGO, xsegbd_srcport_show, NULL);
static DEVICE_ATTR(dstport, S_IRUGO, xsegbd_dstport_show, NULL);
static DEVICE_ATTR(id , S_IRUGO, xsegbd_id_show, NULL);
static DEVICE_ATTR(reqs , S_IRUGO, xsegbd_reqs_show, NULL);
static DEVICE_ATTR(target, S_IRUGO, xsegbd_target_show, NULL);
static DEVICE_ATTR(refresh , S_IWUSR, NULL, xsegbd_image_refresh);
static DEVICE_ATTR(cleanup , S_IWUSR, NULL, xsegbd_cleanup);

static struct attribute *xsegbd_attrs[] = {
	&dev_attr_size.attr,
	&dev_attr_major.attr,
	&dev_attr_srcport.attr,
	&dev_attr_dstport.attr,
	&dev_attr_id.attr,
	&dev_attr_reqs.attr,
	&dev_attr_target.attr,
	&dev_attr_refresh.attr,
	&dev_attr_cleanup.attr,
	NULL
};

static struct attribute_group xsegbd_attr_group = {
	.attrs = xsegbd_attrs,
};

static const struct attribute_group *xsegbd_attr_groups[] = {
	&xsegbd_attr_group,
	NULL
};

static void xsegbd_sysfs_dev_release(struct device *dev)
{
}

static struct device_type xsegbd_device_type = {
	.name		= "xsegbd",
	.groups		= xsegbd_attr_groups,
	.release	= xsegbd_sysfs_dev_release,
};

static void xsegbd_root_dev_release(struct device *dev)
{
}

static struct device xsegbd_root_dev = {
	.init_name	= "xsegbd",
	.release	= xsegbd_root_dev_release,
};

static int xsegbd_bus_add_dev(struct xsegbd_device *xsegbd_dev)
{
	int ret = -ENOMEM;
	struct device *dev;

	mutex_lock_nested(&xsegbd_mutex, SINGLE_DEPTH_NESTING);
	dev = &xsegbd_dev->dev;

	dev->bus = &xsegbd_bus_type;
	dev->type = &xsegbd_device_type;
	dev->parent = &xsegbd_root_dev;
	dev->release = xsegbd_dev_release;
	dev_set_name(dev, "%d", xsegbd_dev->id);

	ret = device_register(dev);

	mutex_unlock(&xsegbd_mutex);
	return ret;
}

static void xsegbd_bus_del_dev(struct xsegbd_device *xsegbd_dev)
{
	device_unregister(&xsegbd_dev->dev);
}

static ssize_t xsegbd_add(struct bus_type *bus, const char *buf, size_t count)
{
	struct xsegbd_device *xsegbd_dev;
	struct xseg_port *port;
	ssize_t ret = -ENOMEM;

	if (!try_module_get(THIS_MODULE))
		return -ENODEV;

	xsegbd_dev = kzalloc(sizeof(*xsegbd_dev), GFP_KERNEL);
	if (!xsegbd_dev)
		goto out;

	spin_lock_init(&xsegbd_dev->rqlock);
	INIT_LIST_HEAD(&xsegbd_dev->node);

	/* parse cmd */
	if (sscanf(buf, "%" __stringify(XSEGBD_TARGET_NAMELEN) "s "
			"%d:%d:%d", xsegbd_dev->target, &xsegbd_dev->src_portno,
			&xsegbd_dev->dst_portno, &xsegbd_dev->nr_requests) < 3) {
		ret = -EINVAL;
		goto out_dev;
	}
	xsegbd_dev->targetlen = strlen(xsegbd_dev->target);

	if (xsegbd_dev->src_portno < start_portno || xsegbd_dev->src_portno > end_portno){
		XSEGLOG("Invadid portno");
		ret = -EINVAL;
		goto out_dev;
	}
	xsegbd_dev->id = src_portno_to_id(xsegbd_dev->src_portno);

	spin_lock(&xsegbd_devices_lock);
	if (xsegbd_devices[xsegbd_dev->id] != NULL) {
		ret = -EINVAL;
		goto out_unlock;
	}
	xsegbd_devices[xsegbd_dev->id] = xsegbd_dev;
	spin_unlock(&xsegbd_devices_lock);

	xsegbd_dev->major = major;

	ret = xsegbd_bus_add_dev(xsegbd_dev);
	if (ret)
		goto out_delentry;

	if (!xq_alloc_seq(&xsegbd_dev->blk_queue_pending,
				xsegbd_dev->nr_requests,
				xsegbd_dev->nr_requests))
		goto out_bus;

	xsegbd_dev->blk_req_pending = kzalloc(
			xsegbd_dev->nr_requests *sizeof(struct xsegbd_pending),
				   GFP_KERNEL);
	if (!xsegbd_dev->blk_req_pending)
		goto out_bus;


	XSEGLOG("joining segment");
	//FIXME use xsebd module config for now
	xsegbd_dev->xseg = xseg_join(	xsegbd.config.type,
					xsegbd.config.name,
					"segdev",
					xseg_callback		);
	if (!xsegbd_dev->xseg)
		goto out_bus;

	XSEGLOG("%s binding to source port %u (destination %u)", xsegbd_dev->target,
			xsegbd_dev->src_portno, xsegbd_dev->dst_portno);
	port = xseg_bind_port(xsegbd_dev->xseg, xsegbd_dev->src_portno, NULL);
	if (!port) {
		XSEGLOG("cannot bind to port");
		ret = -EFAULT;

		goto out_bus;
	}
	
	if (xsegbd_dev->src_portno != xseg_portno(xsegbd_dev->xseg, port)) {
		XSEGLOG("portno != xsegbd_dev->src_portno");
		BUG_ON(1);
		ret = -EFAULT;
		goto out_bus;
	}
	xseg_init_local_signal(xsegbd_dev->xseg, xsegbd_dev->src_portno);


	/* make sure we don't get any requests until we're ready to handle them */
	xseg_cancel_wait(xsegbd_dev->xseg, xseg_portno(xsegbd_dev->xseg, port));

	ret = xsegbd_dev_init(xsegbd_dev);
	if (ret)
		goto out_bus;

	xseg_prepare_wait(xsegbd_dev->xseg, xseg_portno(xsegbd_dev->xseg, port));
	return count;

out_bus:
	xsegbd_bus_del_dev(xsegbd_dev);
	return ret;

out_delentry:
	spin_lock(&xsegbd_devices_lock);
	xsegbd_devices[xsegbd_dev->id] = NULL;

out_unlock:
	spin_unlock(&xsegbd_devices_lock);

out_dev:
	kfree(xsegbd_dev);

out:
	return ret;
}

static ssize_t xsegbd_remove(struct bus_type *bus, const char *buf, size_t count)
{
	struct xsegbd_device *xsegbd_dev = NULL;
	int id, ret;
	unsigned long ul_id;

	ret = strict_strtoul(buf, 10, &ul_id);
	if (ret)
		return ret;

	id = (int) ul_id;
	if (id != ul_id)
		return -EINVAL;

	mutex_lock_nested(&xsegbd_mutex, SINGLE_DEPTH_NESTING);

	ret = count;
	xsegbd_dev = __xsegbd_get_dev(id);
	if (!xsegbd_dev) {
		ret = -ENOENT;
		goto out_unlock;
	}
	xsegbd_bus_del_dev(xsegbd_dev);

out_unlock:
	mutex_unlock(&xsegbd_mutex);
	return ret;
}

static struct bus_attribute xsegbd_bus_attrs[] = {
	__ATTR(add, S_IWUSR, NULL, xsegbd_add),
	__ATTR(remove, S_IWUSR, NULL, xsegbd_remove),
	__ATTR_NULL
};

static int xsegbd_sysfs_init(void)
{
	int ret;

	ret = device_register(&xsegbd_root_dev);
	if (ret < 0)
		return ret;

	xsegbd_bus_type.bus_attrs = xsegbd_bus_attrs;
	ret = bus_register(&xsegbd_bus_type);
	if (ret < 0)
		device_unregister(&xsegbd_root_dev);

	return ret;
}

static void xsegbd_sysfs_cleanup(void)
{
	bus_unregister(&xsegbd_bus_type);
	device_unregister(&xsegbd_root_dev);
}

/* *************************** */
/* ** Module Initialization ** */
/* *************************** */

static int __init xsegbd_init(void)
{
	int ret = -ENOMEM;
	max_dev = end_portno - start_portno;
	if (max_dev < 0){
		XSEGLOG("invalid port numbers");
		ret = -EINVAL;
		goto out;
	}
	xsegbd_devices = kzalloc(max_dev * sizeof(struct xsegbd_devices *), GFP_KERNEL);
	if (!xsegbd_devices)
		goto out;

	spin_lock_init(&xsegbd_devices_lock);

	XSEGLOG("registering block device major %d", major);
	ret = register_blkdev(major, XSEGBD_NAME);
	if (ret < 0) {
		XSEGLOG("cannot register block device!");
		ret = -EBUSY;
		goto out_free;
	}
	major = ret;
	XSEGLOG("registered block device major %d", major);

	ret = -ENOSYS;
	ret = xsegbd_xseg_init();
	if (ret)
		goto out_unregister;

	ret = xsegbd_sysfs_init();
	if (ret)
		goto out_xseg;

	XSEGLOG("initialization complete");

out:
	return ret;

out_xseg:
	xsegbd_xseg_quit();

out_unregister:
	unregister_blkdev(major, XSEGBD_NAME);

out_free:
	kfree(xsegbd_devices);

	goto out;
}

static void __exit xsegbd_exit(void)
{
	xsegbd_sysfs_cleanup();
	xsegbd_xseg_quit();
	unregister_blkdev(major, XSEGBD_NAME);
}

module_init(xsegbd_init);
module_exit(xsegbd_exit);

