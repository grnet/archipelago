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

#include <sys/kernel/segdev.h>
#include "xsegbd.h"

#define XSEGBD_MINORS 1

MODULE_DESCRIPTION("xsegbd");
MODULE_AUTHOR("XSEG");
MODULE_LICENSE("GPL");

static long sector_size = 0;
static long blksize = 512;
static int major = 0;
static int max_nr_pending = 1024;
static char name[XSEGBD_SEGMENT_NAMELEN] = "xsegbd";
static char spec[256] = "segdev:xsegbd:4:512:64:1024:12";

module_param(sector_size, long, 0644);
module_param(blksize, long, 0644);
module_param(max_nr_pending, int, 0644);
module_param(major, int, 0644);
module_param_string(name, name, sizeof(name), 0644);
module_param_string(spec, spec, sizeof(spec), 0644);

struct pending {
	struct request *request;
	struct completion *comp;
	struct xsegbd_device *dev;
};

static struct xq blk_queue_pending;
static struct pending *blk_req_pending;
static unsigned int nr_pending;
static spinlock_t __lock;
static struct xsegbd xsegbd;
static DEFINE_MUTEX(xsegbd_mutex);
static LIST_HEAD(xsegbd_dev_list);

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

static void xseg_callback(struct xseg *xseg, uint32_t portno);

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

static int xsegbd_dev_init(struct xsegbd_device *xsegbd_dev)
{
	int ret = -ENOMEM;
	struct gendisk *disk;
	unsigned int max_request_size_bytes;

	spin_lock_init(&xsegbd_dev->lock);

	xsegbd_dev->xsegbd = &xsegbd;

	xsegbd_dev->blk_queue = blk_alloc_queue(GFP_KERNEL);
	if (!xsegbd_dev->blk_queue)
		goto out;

	blk_init_allocated_queue(xsegbd_dev->blk_queue, xseg_request_fn, &xsegbd_dev->lock);
	xsegbd_dev->blk_queue->queuedata = xsegbd_dev;

	blk_queue_flush(xsegbd_dev->blk_queue, REQ_FLUSH | REQ_FUA);
	blk_queue_logical_block_size(xsegbd_dev->blk_queue, 512);
	blk_queue_physical_block_size(xsegbd_dev->blk_queue, blksize);
	blk_queue_bounce_limit(xsegbd_dev->blk_queue, BLK_BOUNCE_ANY);
	
	//blk_queue_max_segments(dev->blk_queue, 512);
	/* calculate maximum block request size
	 * request size in pages * page_size
	 * leave one page in buffer for name
	 */
	max_request_size_bytes =
		 (unsigned int)	(xsegbd.config.request_size - 1) *
			 	( 1 << xsegbd.config.page_shift) ;
	blk_queue_max_hw_sectors(xsegbd_dev->blk_queue, max_request_size_bytes >> 9);
	blk_queue_max_segment_size(xsegbd_dev->blk_queue, max_request_size_bytes);
	blk_queue_io_min(xsegbd_dev->blk_queue, max_request_size_bytes);
	blk_queue_io_opt(xsegbd_dev->blk_queue, max_request_size_bytes);

	queue_flag_set_unlocked(QUEUE_FLAG_NONROT, xsegbd_dev->blk_queue);

	/* vkoukis says we don't need partitions */
	xsegbd_dev->gd = disk = alloc_disk(1);
	if (!disk)
		goto out_disk;

	disk->major = xsegbd_dev->major;
	disk->first_minor = 0; // id * XSEGBD_MINORS;
	disk->fops = &xsegbd_ops;
	disk->queue = xsegbd_dev->blk_queue;
	disk->private_data = xsegbd_dev;
	disk->flags |= GENHD_FL_SUPPRESS_PARTITION_INFO;
	snprintf(disk->disk_name, 32, "xsegbd%u", xsegbd_dev->id);

	ret = 0;
	spin_lock_irq(&__lock);
	if (nr_pending + xsegbd_dev->nr_requests > max_nr_pending)
		ret = -ENOBUFS;
	else
		nr_pending += xsegbd_dev->nr_requests;
	spin_unlock_irq(&__lock);

	if (ret)
		goto out_disk;

	/* allow a non-zero sector_size parameter to override the disk size */
	if (sector_size)
		xsegbd_dev->sectors = sector_size;
	else {
		ret = xsegbd_get_size(xsegbd_dev);
		if (ret)
			goto out_disk;
	}

	
	set_capacity(disk, xsegbd_dev->sectors);
	XSEGLOG("xsegbd active...");
	add_disk(disk); /* immediately activates the device */

	return 0;

out_disk:
	put_disk(disk);
out:
	return ret;
}

static void xsegbd_dev_release(struct device *dev)
{
	struct xsegbd_device *xsegbd_dev = dev_to_xsegbd(dev);
	struct xseg_port *port;

	/* cleanup gendisk and blk_queue the right way */
	if (xsegbd_dev->gd) {
		if (xsegbd_dev->gd->flags & GENHD_FL_UP)
			del_gendisk(xsegbd_dev->gd);

		blk_cleanup_queue(xsegbd_dev->blk_queue);
		put_disk(xsegbd_dev->gd);
	}

	/* reset the port's waitcue (aka cancel_wait) */
	port = &xsegbd.xseg->ports[xsegbd_dev->src_portno];
	port->waitcue = (long) NULL;

	xseg_free_requests(xsegbd.xseg, xsegbd_dev->src_portno, xsegbd_dev->nr_requests);

	WARN_ON(nr_pending < xsegbd_dev->nr_requests);
	spin_lock_irq(&__lock);
	nr_pending -= xsegbd_dev->nr_requests;
	spin_unlock_irq(&__lock);

	unregister_blkdev(xsegbd_dev->major, XSEGBD_NAME);

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
	char *data = XSEG_TAKE_PTR(xreq->data, xseg->segment);
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
	char *data = XSEG_TAKE_PTR(xreq->data, xseg->segment);
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
	struct pending *pending;
	xqindex blkreq_idx;
	char *name;
	uint64_t datasize;

	for (;;) {
		xreq = xseg_get_request(xsegbd.xseg, xsegbd_dev->src_portno);
		if (!xreq)
			break;

		blkreq = blk_fetch_request(rq);
		if (!blkreq)
			break;

		if (blkreq->cmd_type != REQ_TYPE_FS) {
			XSEGLOG("non-fs cmd_type: %u. *shrug*", blkreq->cmd_type);
			__blk_end_request_all(blkreq, 0);
		}


		datasize = blk_rq_bytes(blkreq);
		BUG_ON(xreq->buffersize - xsegbd_dev->namesize < datasize);
		BUG_ON(xseg_prep_request(xreq, xsegbd_dev->namesize, datasize));

		name = XSEG_TAKE_PTR(xreq->name, xsegbd.xseg->segment);
		strncpy(name, xsegbd_dev->name, xsegbd_dev->namesize);
		blkreq_idx = xq_pop_head(&blk_queue_pending);
		BUG_ON(blkreq_idx == None);
		pending = &blk_req_pending[blkreq_idx];
		pending->dev = xsegbd_dev;
		pending->request = blkreq;
		pending->comp = NULL;
		xreq->priv = (uint64_t)blkreq_idx;
		xreq->size = datasize;
		xreq->offset = blk_rq_pos(blkreq) << 9;
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
			/* unlock for data transfers? */
			blk_to_xseg(xsegbd.xseg, xreq, blkreq);
			xreq->op = X_WRITE;
		} else {
			xreq->op = X_READ;
		}

		BUG_ON(xseg_submit(xsegbd.xseg, xsegbd_dev->dst_portno, xreq) == NoSerial);
	}

	/* TODO:
	 * This is going to happen at least once.
	 * Add a WARN_ON when debugging find out why it happens more than once.
	 */
	xseg_signal(xsegbd_dev->xsegbd->xseg, xsegbd_dev->dst_portno);
	if (xreq)
		xseg_put_request(xsegbd_dev->xsegbd->xseg, xsegbd_dev->src_portno, xreq);
}

int update_dev_sectors_from_request(	struct xsegbd_device *xsegbd_dev,
					struct xseg_request *xreq	)
{
	void *data;

	if (xreq->state & XS_FAILED)
		return -ENOENT;

	if (!(xreq->state & XS_SERVED))
		return -EIO;

	data = XSEG_TAKE_PTR(xreq->data, xsegbd.xseg->segment);
	xsegbd_dev->sectors = *((uint64_t *) data) / 512ULL;
	return 0;
}

static int xsegbd_get_size(struct xsegbd_device *xsegbd_dev)
{
	struct xseg_request *xreq;
	struct xseg_port *port;
	char *name;
	uint64_t datasize;
	xqindex blkreq_idx;
	struct pending *pending;
	struct completion comp;
	int ret = -EBUSY;

	xreq = xseg_get_request(xsegbd.xseg, xsegbd_dev->src_portno);
	if (!xreq)
		goto out;

	datasize = sizeof(uint64_t);
	BUG_ON(xreq->buffersize - xsegbd_dev->namesize < datasize);
	BUG_ON(xseg_prep_request(xreq, xsegbd_dev->namesize, datasize));

	init_completion(&comp);
	blkreq_idx = xq_pop_head(&blk_queue_pending);
	BUG_ON(blkreq_idx == None);
	pending = &blk_req_pending[blkreq_idx];
	pending->dev = xsegbd_dev;
	pending->request = NULL;
	pending->comp = &comp;
	xreq->priv = (uint64_t)blkreq_idx;

	name = XSEG_TAKE_PTR(xreq->name, xsegbd.xseg->segment);
	strncpy(name, xsegbd_dev->name, xsegbd_dev->namesize);
	xreq->size = datasize;
	xreq->offset = 0;

	xreq->op = X_INFO;

	port = &xsegbd.xseg->ports[xsegbd_dev->src_portno];
	port->waitcue = (uint64_t)(long)xsegbd_dev;

	BUG_ON(xseg_submit(xsegbd.xseg, xsegbd_dev->dst_portno, xreq) == NoSerial);
	xseg_signal(xsegbd.xseg, xsegbd_dev->dst_portno);

	wait_for_completion_interruptible(&comp);
	XSEGLOG("Woken up after wait_for_completion_interruptible()\n");
	ret = update_dev_sectors_from_request(xsegbd_dev, xreq);
	XSEGLOG("get_size: sectors = %ld\n", (long)xsegbd_dev->sectors);
out:
	xseg_put_request(xsegbd.xseg, xsegbd_dev->src_portno, xreq);
	return ret;
}

static void xseg_callback(struct xseg *xseg, uint32_t portno)
{
	struct xsegbd_device *xsegbd_dev = NULL, *old_dev = NULL;
	struct xseg_request *xreq;
	struct request *blkreq;
	struct pending *pending;
	unsigned long flags;
	uint32_t blkreq_idx;
	int err;

	for (;;) {
		xreq = xseg_receive(xseg, portno);
		if (!xreq)
			break;

		/* we rely upon our peers to not have touched ->priv */
		blkreq_idx = (uint64_t)xreq->priv;
		if (blkreq_idx >= max_nr_pending) {
			WARN_ON(1);
			continue;
		}

		pending = &blk_req_pending[blkreq_idx];
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
		xsegbd_dev = pending->dev;
		pending->dev = NULL;
		WARN_ON(!blkreq);

		if ((xsegbd_dev != old_dev) && old_dev) {
			spin_lock_irqsave(&old_dev->lock, flags);
			xseg_request_fn(old_dev->blk_queue);
			spin_unlock_irqrestore(&old_dev->lock, flags);
		}

		old_dev = xsegbd_dev;

		if (!(xreq->state & XS_SERVED))
			goto blk_end;

		if (xreq->serviced != blk_rq_bytes(blkreq))
			goto blk_end;

		/* unlock for data transfer? */
		if (!rq_data_dir(blkreq))
			xseg_to_blk(xseg, xreq, blkreq);

		err = 0;
blk_end:
		blk_end_request_all(blkreq, err);
		xq_append_head(&blk_queue_pending, blkreq_idx);
		xseg_put_request(xseg, xreq->portno, xreq);
	}

	if (xsegbd_dev) {
		spin_lock_irqsave(&xsegbd_dev->lock, flags);
		xseg_request_fn(xsegbd_dev->blk_queue);
		spin_unlock_irqrestore(&xsegbd_dev->lock, flags);
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

static ssize_t xsegbd_name_show(struct device *dev,
					struct device_attribute *attr, char *buf)
{
	struct xsegbd_device *xsegbd_dev = dev_to_xsegbd(dev);

	return sprintf(buf, "%s\n", xsegbd_dev->name);
}

static DEVICE_ATTR(size, S_IRUGO, xsegbd_size_show, NULL);
static DEVICE_ATTR(major, S_IRUGO, xsegbd_major_show, NULL);
static DEVICE_ATTR(srcport, S_IRUGO, xsegbd_srcport_show, NULL);
static DEVICE_ATTR(dstport, S_IRUGO, xsegbd_dstport_show, NULL);
static DEVICE_ATTR(id , S_IRUGO, xsegbd_id_show, NULL);
static DEVICE_ATTR(reqs , S_IRUGO, xsegbd_reqs_show, NULL);
static DEVICE_ATTR(name , S_IRUGO, xsegbd_name_show, NULL);

static struct attribute *xsegbd_attrs[] = {
	&dev_attr_size.attr,
	&dev_attr_major.attr,
	&dev_attr_srcport.attr,
	&dev_attr_dstport.attr,
	&dev_attr_id.attr,
	&dev_attr_reqs.attr,
	&dev_attr_name.attr,
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
	struct xseg_port *xport;
	ssize_t ret = -ENOMEM;
	int new_id = 0;
	struct list_head *tmp;

	if (!try_module_get(THIS_MODULE))
		return -ENODEV;

	xsegbd_dev = kzalloc(sizeof(*xsegbd_dev), GFP_KERNEL);
	if (!xsegbd_dev)
		goto out;

	spin_lock_init(&xsegbd_dev->lock);
	INIT_LIST_HEAD(&xsegbd_dev->node);

	/* parse cmd */
	if (sscanf(buf, "%" __stringify(XSEGBD_TARGET_NAMELEN) "s "
			"%d:%d:%d", xsegbd_dev->name, &xsegbd_dev->src_portno,
			&xsegbd_dev->dst_portno, &xsegbd_dev->nr_requests) < 3) {
		ret = -EINVAL;
		goto out_dev;
	}
	xsegbd_dev->namesize = strlen(xsegbd_dev->name);

	mutex_lock_nested(&xsegbd_mutex, SINGLE_DEPTH_NESTING);

	list_for_each(tmp, &xsegbd_dev_list) {
		struct xsegbd_device *entry;

		entry = list_entry(tmp, struct xsegbd_device, node);

		if (entry->src_portno == xsegbd_dev->src_portno) {
			ret = -EINVAL;
			goto out_unlock;
		}

		if (entry->id >= new_id)
			new_id = entry->id + 1;
	}

	xsegbd_dev->id = new_id;

	list_add_tail(&xsegbd_dev->node, &xsegbd_dev_list);

	mutex_unlock(&xsegbd_mutex);

	XSEGLOG("registering block device major %d", major);
	ret = register_blkdev(major, XSEGBD_NAME);
	if (ret < 0) {
		XSEGLOG("cannot register block device!");
		ret = -EBUSY;
		goto out_delentry;
	}
	xsegbd_dev->major = ret;
	XSEGLOG("registered block device major %d", xsegbd_dev->major);

	ret = xsegbd_bus_add_dev(xsegbd_dev);
	if (ret)
		goto out_blkdev;

	XSEGLOG("binding to source port %u (destination %u)",
			xsegbd_dev->src_portno, xsegbd_dev->dst_portno);
	xport = xseg_bind_port(xsegbd.xseg, xsegbd_dev->src_portno);
	if (!xport) {
		XSEGLOG("cannot bind to port");
		ret = -EFAULT;

		goto out_bus;
	}
	/* make sure we don't get any requests until we're ready to handle them */
	xport->waitcue = (long) NULL;

	XSEGLOG("allocating %u requests", xsegbd_dev->nr_requests);
	if (xseg_alloc_requests(xsegbd.xseg, xsegbd_dev->src_portno, xsegbd_dev->nr_requests)) {
		XSEGLOG("cannot allocate requests");
		ret = -EFAULT;

		goto out_bus;
	}

	ret = xsegbd_dev_init(xsegbd_dev);
	if (ret)
		goto out_bus;

	return count;

out_bus:
	mutex_lock_nested(&xsegbd_mutex, SINGLE_DEPTH_NESTING);

	list_del_init(&xsegbd_dev->node);
	xsegbd_bus_del_dev(xsegbd_dev);

	mutex_unlock(&xsegbd_mutex);

	return ret;

out_blkdev:
	unregister_blkdev(xsegbd_dev->major, XSEGBD_NAME);

out_delentry:
	mutex_lock_nested(&xsegbd_mutex, SINGLE_DEPTH_NESTING);
	list_del_init(&xsegbd_dev->node);

out_unlock:
	mutex_unlock(&xsegbd_mutex);

out_dev:
	kfree(xsegbd_dev);

out:
	return ret;
}

static struct xsegbd_device *__xsegbd_get_dev(unsigned long id)
{
	struct list_head *tmp;
	struct xsegbd_device *xsegbd_dev;

	list_for_each(tmp, &xsegbd_dev_list) {
		xsegbd_dev = list_entry(tmp, struct xsegbd_device, node);
		if (xsegbd_dev->id == id)
			return xsegbd_dev;

	}

	return NULL;
}

static ssize_t xsegbd_remove(struct bus_type *bus, const char *buf, size_t count)
{
	struct xsegbd_device *xsegbd_dev = NULL;
	int id, ret;
	unsigned long ul_id;

	ret = kstrtoul(buf, 10, &ul_id);
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

	list_del_init(&xsegbd_dev->node);

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

	xsegbd_bus_type.bus_attrs = xsegbd_bus_attrs;

	ret = bus_register(&xsegbd_bus_type);
	if (ret < 0)
		return ret;

	ret = device_register(&xsegbd_root_dev);

	return ret;
}

static void xsegbd_sysfs_cleanup(void)
{
	device_unregister(&xsegbd_root_dev);
	bus_unregister(&xsegbd_bus_type);
}

/* *************************** */
/* ** Module Initialization ** */
/* *************************** */

static int __init xsegbd_init(void)
{
	int ret = -ENOMEM;

	if (!xq_alloc_seq(&blk_queue_pending, max_nr_pending, max_nr_pending))
		goto out;

	blk_req_pending = kzalloc(sizeof(struct pending) * max_nr_pending, GFP_KERNEL);
	if (!blk_req_pending)
		goto out_queue;

	ret = -ENOSYS;
	ret = xsegbd_xseg_init();
	if (ret)
		goto out_pending;

	ret = xsegbd_sysfs_init();
	if (ret)
		goto out_xseg;

	XSEGLOG("initialization complete");

out:
	return ret;

out_xseg:
	xsegbd_xseg_quit();
out_pending:
	kfree(blk_req_pending);
out_queue:
	xq_free(&blk_queue_pending);
	goto out;
}

static void __exit xsegbd_exit(void)
{
	xsegbd_sysfs_cleanup();
	xsegbd_xseg_quit();
}

module_init(xsegbd_init);
module_exit(xsegbd_exit);

