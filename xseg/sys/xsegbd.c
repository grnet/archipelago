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

#include "xsegdev.h"
#include "xsegbd.h"

#define XSEGBD_MINORS 1

MODULE_DESCRIPTION("xsegbd");
MODULE_AUTHOR("XSEG");
MODULE_LICENSE("GPL");

static long sector_size = 0;
static long blksize = 512;
static int major = 0;
static char name[XSEGBD_VOLUME_NAMELEN] = "xsegbd";
static char spec[256] = "xsegdev:xsegbd:4:512:64:1024:12";

module_param(sector_size, long, 0644);
module_param(blksize, long, 0644);
module_param(major, int, 0644);
module_param_string(name, name, sizeof(name), 0644);
module_param_string(spec, spec, sizeof(spec), 0644);

static struct xsegbd xsegbd;
static DEFINE_MUTEX(xsegbd_mutex);
static LIST_HEAD(xsegbd_dev_list);

/* ********************* */
/* ** XSEG Operations ** */
/* ********************* */

static void *xsegdev_malloc(uint64_t size)
{
	return kmalloc((size_t)size, GFP_KERNEL);
}

static void *xsegdev_realloc(void *mem, uint64_t size)
{
	return krealloc(mem, (size_t)size, GFP_KERNEL);
}

static void xsegdev_mfree(void *ptr)
{
	return kfree(ptr);
}

static long xsegdev_allocate(const char *name, uint64_t size)
{
	int r;
	struct xsegdev *xsegdev = xsegdev_get(0);

	r = IS_ERR(xsegdev) ? PTR_ERR(xsegdev) : 0;
	if (r) {
		XSEGLOG("cannot acquire xsegdev");
		goto err;
	}

	if (xsegdev->segment) {
		XSEGLOG("destroying existing xsegdev segment");
		r = xsegdev_destroy_segment(xsegdev);
		if (r)
			goto err;
	}

	XSEGLOG("creating xsegdev segment size %llu", size);
	r = xsegdev_create_segment(xsegdev, size, 1);
	if (r)
		goto err;

	xsegdev->segsize = size;
	xsegdev_put(xsegdev);
	return 0;

err:
	return r;
}

static long xsegdev_deallocate(const char *name)
{
	struct xsegdev *xsegdev = xsegdev_get(0);
	int r = IS_ERR(xsegdev) ? PTR_ERR(xsegdev) : 0;
	if (r)
		return r;

	clear_bit(XSEGDEV_RESERVED, &xsegdev->flags);
	XSEGLOG("destroying segment");
	r = xsegdev_destroy_segment(xsegdev);
	if (r)
		XSEGLOG("   ...failed");
	xsegdev_put(xsegdev);
	return r;
}

static long xseg_callback(void *arg);

static void *xsegdev_map(const char *name, uint64_t size)
{
	struct xseg *xseg = NULL;
	struct xsegdev *dev = xsegdev_get(0);
	int r;
	r = IS_ERR(dev) ? PTR_ERR(dev) : 0;
	if (r)
		goto out;

	if (!dev->segment)
		goto put_out;

	if (size > dev->segsize)
		goto put_out;

	if (dev->callback) /* in use */
		goto put_out;

	dev->callback = xseg_callback;
	xseg = (void *)dev->segment;

put_out:
	xsegdev_put(dev);
out:
	return xseg;
}

static void xsegdev_unmap(void *ptr, uint64_t size)
{
	struct xsegdev *xsegdev = xsegdev_get(0);
	int r = IS_ERR(xsegdev) ? PTR_ERR(xsegdev) : 0;
	if (r)
		return;

	//xsegdev->callarg = NULL;
	xsegdev->callback = NULL;
	xsegdev_put(xsegdev);
}

static struct xseg_type xseg_xsegdev = {
	/* xseg operations */
	{
		.malloc = xsegdev_malloc,
		.realloc = xsegdev_realloc,
		.mfree = xsegdev_mfree,
		.allocate = xsegdev_allocate,
		.deallocate = xsegdev_deallocate,
		.map = xsegdev_map,
		.unmap = xsegdev_unmap
	},
	/* name */
	"xsegdev"
};

static int posix_signal_init(void)
{
	return 0;
}

static void posix_signal_quit(void) { }

static int posix_prepare_wait(struct xseg_port *port)
{
	return 0;
}

static int posix_cancel_wait(struct xseg_port *port)
{
	return 0;
}

static int posix_wait_signal(struct xseg_port *port, uint32_t timeout)
{
	return 0;
}

static int posix_signal(struct xseg_port *port)
{
	struct pid *pid;
	struct task_struct *task;
	int ret = -ENOENT;

	rcu_read_lock();
	pid = find_vpid((pid_t)port->waitcue);
	if (!pid)
		goto out;
 	task = pid_task(pid, PIDTYPE_PID);
	if (!task)
		goto out;

	ret = send_sig(SIGIO, task, 1);
out:
	rcu_read_unlock();
	return ret;
}

static void *posix_malloc(uint64_t size)
{
	return NULL;
}

static void *posix_realloc(void *mem, uint64_t size)
{
	return NULL;
}

static void posix_mfree(void *mem) { }

static struct xseg_peer xseg_peer_posix = {
	/* xseg signal operations */
	{
		.signal_init = posix_signal_init,
		.signal_quit = posix_signal_quit,
		.cancel_wait = posix_cancel_wait,
		.prepare_wait = posix_prepare_wait,
		.wait_signal = posix_wait_signal,
		.signal = posix_signal,
		.malloc = posix_malloc,
		.realloc = posix_realloc,
		.mfree = posix_mfree
	},
	/* name */
	"posix"
};

static int xsegdev_signal_init(void)
{
	return 0;
}

static void xsegdev_signal_quit(void) { }

static int xsegdev_prepare_wait(struct xseg_port *port)
{
	return -1;
}

static int xsegdev_cancel_wait(struct xseg_port *port)
{
	return -1;
}

static int xsegdev_wait_signal(struct xseg_port *port, uint32_t timeout)
{
	return -1;
}

static int xsegdev_signal(struct xseg_port *port)
{
	return -1;
}

static struct xseg_peer xseg_peer_xsegdev = {
	/* xseg signal operations */
	{
		.signal_init = xsegdev_signal_init,
		.signal_quit = xsegdev_signal_quit,
		.cancel_wait = xsegdev_cancel_wait,
		.prepare_wait = xsegdev_prepare_wait,
		.wait_signal = xsegdev_wait_signal,
		.signal = xsegdev_signal,
		.malloc = xsegdev_malloc,
		.realloc = xsegdev_realloc,
		.mfree = xsegdev_mfree
	},
	/* name */
	"xsegdev"
};


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

int xsegbd_xseg_init(void)
{
	struct xsegdev *xsegdev;
	int r;

	if (!xsegbd.name[0])
		strncpy(xsegbd.name, name, XSEGBD_VOLUME_NAMELEN);

	XSEGLOG("registering xseg types");
	xsegbd.namesize = strlen(xsegbd.name);

	r = xseg_register_type(&xseg_xsegdev);
	if (r)
		goto err0;

	r = xseg_register_peer(&xseg_peer_posix);
	if (r)
		goto err1;

	r = xseg_register_peer(&xseg_peer_xsegdev);
	if (r)
		goto err2;

	r = xseg_initialize("xsegdev");
	if (r) {
		XSEGLOG("cannot initialize 'xsegdev' peer");
		goto err3;
	}

	r = xseg_parse_spec(spec, &xsegbd.config);
	if (r)
		goto err3;

	if (strncmp(xsegbd.config.type, "xsegdev", 16))
		XSEGLOG("WARNING: unexpected segment type '%s' vs 'xsegdev'",
			 xsegbd.config.type);

	xsegdev = xsegdev_get(0);
	if (!xsegdev->segment) {
		XSEGLOG("creating segment");
		r = xseg_create(&xsegbd.config);
		if (r) {
			XSEGLOG("cannot create segment");
			goto err3;
		}
	}
	xsegdev_put(xsegdev);

	XSEGLOG("joining segment");
	xsegbd.xseg = xseg_join("xsegdev", "xsegbd");
	if (!xsegbd.xseg) {
		XSEGLOG("cannot join segment");
		r = -EFAULT;
		goto err3;
	}

	return 0;
err3:
	xseg_unregister_peer(xseg_peer_xsegdev.name);
err2:
	xseg_unregister_peer(xseg_peer_posix.name);
err1:
	xseg_unregister_type(xseg_xsegdev.name);
err0:
	return r;

}

int xsegbd_xseg_quit(void)
{
	/* make sure to unmap the segment first */
	xsegbd.xseg->type.ops.unmap(xsegbd.xseg, xsegbd.xseg->segment_size);

	xseg_unregister_peer(xseg_peer_xsegdev.name);
	xseg_unregister_peer(xseg_peer_posix.name);
	xseg_unregister_type(xseg_xsegdev.name);

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

static loff_t xsegbd_get_size(struct xsegbd_device *xsegbd_dev)
{
	struct xseg_request *xreq;
	char *name, *data;
	uint64_t datasize;
	loff_t size;

	xreq = xseg_get_request(xsegbd.xseg, xsegbd_dev->src_portno);
	if (!xreq)
		return -EINVAL;

	datasize = sizeof(loff_t);
	BUG_ON(xreq->buffersize - xsegbd.namesize < datasize);
	BUG_ON(xseg_prep_request(xreq, xsegbd.namesize, datasize));

	name = XSEG_TAKE_PTR(xreq->name, xsegbd.xseg->segment);
	strncpy(name, xsegbd.name, xsegbd.namesize);
	xreq->size = datasize;
	xreq->offset = 0;

	xreq->op = X_INFO;

	BUG_ON(xseg_submit(xsegbd.xseg, xsegbd_dev->dst_portno, xreq) == NoSerial);

	xseg_signal(xsegbd.xseg, xsegbd_dev->dst_portno);

	/* callback_fn doesn't handle X_INFO reqs atm, and more importantly we
	 * cannot use an async operation to learn the disk size. Currently, this
	 * behaves like a busy-wait loop and makes insmod block until a peer
	 * responds to our X_INFO req. This will change when the sysfs interface is
	 * implemented, to handle disk operations.
	 */
	while (!(xreq = xseg_receive(xsegbd.xseg, xsegbd_dev->src_portno))) ;

	while (!(xreq->state & XS_SERVED)) ;

	data = XSEG_TAKE_PTR(xreq->data, xsegbd.xseg->segment);
	/* TODO: make sure we use consistent types accross peers */
	size = *((off_t *) data);

	if (xreq)
		xseg_put_request(xsegbd.xseg, xsegbd_dev->src_portno, xreq);

	return size;
}


static int xsegbd_dev_init(struct xsegbd_device *xsegbd_dev, sector_t size)
{
	int ret = -ENOMEM;
	struct gendisk *disk;

	spin_lock_init(&xsegbd_dev->lock);

	xsegbd_dev->blk_queue = blk_alloc_queue(GFP_KERNEL);
	if (!xsegbd_dev->blk_queue)
		goto out;

	blk_init_allocated_queue(xsegbd_dev->blk_queue, xseg_request_fn, &xsegbd_dev->lock);
	xsegbd_dev->blk_queue->queuedata = xsegbd_dev;

	blk_queue_flush(xsegbd_dev->blk_queue, REQ_FLUSH | REQ_FUA);
	blk_queue_logical_block_size(xsegbd_dev->blk_queue, 512);
	blk_queue_physical_block_size(xsegbd_dev->blk_queue, blksize);
	blk_queue_bounce_limit(xsegbd_dev->blk_queue, BLK_BOUNCE_ANY);
	/* we can handle any number of segments, BUT
	 * parts of the request may be available far sooner than others
	 * but we cannot complete them (unless we handle their bios directly).
	 */
	blk_queue_max_segments(xsegbd_dev->blk_queue, 1);
	queue_flag_set_unlocked(QUEUE_FLAG_NONROT, xsegbd_dev->blk_queue);

	/* vkoukis says we don't need partitions */
	xsegbd_dev->gd = disk = alloc_disk(1);
	if (!disk)
		goto out_free_queue;

	disk->major = xsegbd_dev->major;
	disk->first_minor = 0; // id * XSEGBD_MINORS;
	disk->fops = &xsegbd_ops;
	disk->queue = xsegbd_dev->blk_queue;
	disk->private_data = xsegbd_dev;
	disk->flags |= GENHD_FL_SUPPRESS_PARTITION_INFO;
	snprintf(disk->disk_name, 32, "xsegbd%u", xsegbd_dev->id);

	if (!xq_alloc_seq(&xsegbd_dev->blk_queue_pending, xsegbd_dev->nr_requests, xsegbd_dev->nr_requests))
		goto out_free_disk;

	xsegbd_dev->blk_req_pending = kmalloc(sizeof(struct request *) * xsegbd_dev->nr_requests, GFP_KERNEL);
	if (!xsegbd_dev->blk_req_pending)
		goto out_free_pending;

	/* allow a non-zero sector_size parameter to override the disk size */
	xsegbd_dev->sectors = sector_size ? sector_size : xsegbd_get_size(xsegbd_dev) / 512ULL;
	set_capacity(disk, xsegbd_dev->sectors);

	add_disk(disk); /* immediately activates the device */

	return 0;

out:
	return ret;

out_free_pending:
	xq_free(&xsegbd_dev->blk_queue_pending);

out_free_disk:
	put_disk(disk);

out_free_queue:
	blk_cleanup_queue(xsegbd_dev->blk_queue);

	goto out;
}

static void xsegbd_dev_release(struct device *dev)
{
	struct xsegbd_device *xsegbd_dev = dev_to_xsegbd(dev);

	xq_free(&xsegbd_dev->blk_queue_pending);
	kfree(xsegbd_dev->blk_req_pending);
	del_gendisk(xsegbd_dev->gd);
	put_disk(xsegbd_dev->gd);
	blk_cleanup_queue(xsegbd_dev->blk_queue);
	unregister_blkdev(xsegbd_dev->major, XSEGBD_NAME);
	xseg_free_requests(xsegbd.xseg, xsegbd_dev->src_portno, xsegbd_dev->nr_requests);
	kfree(xsegbd_dev);
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
	struct xseg_port port;
	struct request *blkreq;
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
		BUG_ON(xreq->buffersize - xsegbd.namesize < datasize);
		BUG_ON(xseg_prep_request(xreq, xsegbd.namesize, datasize));

		name = XSEG_TAKE_PTR(xreq->name, xsegbd.xseg->segment);
		strncpy(name, xsegbd.name, xsegbd.namesize);
		blkreq_idx = xq_pop_head(&xsegbd_dev->blk_queue_pending);
		BUG_ON(blkreq_idx == None);
		/* WARN_ON(xsegbd_dev->blk_req_pending[blkreq_idx] */
		xsegbd_dev->blk_req_pending[blkreq_idx] = blkreq;
		xreq->priv = (void *)(unsigned long)blkreq_idx;
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

		/* TODO:
		 * Temp/ugly hack, add support for it in prepare_wait instead
		 */
		port = xsegbd.xseg->ports[xsegbd_dev->src_portno];
		port.waitcue = (long) xsegbd_dev;

		BUG_ON(xseg_submit(xsegbd.xseg, xsegbd_dev->dst_portno, xreq) == NoSerial);
	}

	if (xreq)
		xseg_put_request(xsegbd.xseg, xsegbd_dev->src_portno, xreq);
}

static long xseg_callback(void *arg)
{
	struct xsegbd_device *xsegbd_dev = NULL;
	struct xseg_request *xreq;
	struct xseg_port *port;
	struct request *blkreq;
	unsigned long flags;
	xqindex blkreq_idx;
	int err;

	port = XSEG_TAKE_PTR(arg, xsegbd.xseg->segment);
	xsegbd_dev = (struct xsegbd_device *) port->waitcue;

	if (!xsegbd_dev)
		return -ENODEV;

	for (;;) {
		xreq = xseg_receive(xsegbd.xseg, xsegbd_dev->src_portno);
		if (!xreq)
			break;

		/* we rely upon our peers to not have touched ->priv */
		blkreq_idx = (xqindex)(unsigned long)xreq->priv;
		if (blkreq_idx < 0 || blkreq_idx >= xsegbd_dev->nr_requests) {
			XSEGLOG("invalid request index: %u! Ignoring.", blkreq_idx);
			goto xseg_put;
		}

		blkreq = xsegbd_dev->blk_req_pending[blkreq_idx];
		/* WARN_ON(!blkreq); */
		err = -EIO;

		if (!(xreq->state & XS_SERVED))
			goto blk_end;

		if (xreq->serviced != blk_rq_bytes(blkreq))
			goto blk_end;

		/* unlock for data transfer? */
		if (!rq_data_dir(blkreq))
			xseg_to_blk(xsegbd.xseg, xreq, blkreq);

		err = 0;
blk_end:
		blk_end_request_all(blkreq, err);
		xq_append_head(&xsegbd_dev->blk_queue_pending, blkreq_idx);
xseg_put:
		xseg_put_request(xsegbd.xseg, xreq->portno, xreq);
	}

	spin_lock_irqsave(&xsegbd_dev->lock, flags);
	xseg_request_fn(xsegbd_dev->blk_queue);
	spin_unlock_irqrestore(&xsegbd_dev->lock, flags);
	return 0;
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

static DEVICE_ATTR(size, S_IRUGO, xsegbd_size_show, NULL);
static DEVICE_ATTR(major, S_IRUGO, xsegbd_major_show, NULL);
static DEVICE_ATTR(srcport, S_IRUGO, xsegbd_srcport_show, NULL);
static DEVICE_ATTR(dstport, S_IRUGO, xsegbd_dstport_show, NULL);
static DEVICE_ATTR(id , S_IRUGO, xsegbd_id_show, NULL);
static DEVICE_ATTR(reqs , S_IRUGO, xsegbd_reqs_show, NULL);

static struct attribute *xsegbd_attrs[] = {
	&dev_attr_size.attr,
	&dev_attr_major.attr,
	&dev_attr_srcport.attr,
	&dev_attr_dstport.attr,
	&dev_attr_id.attr,
	&dev_attr_reqs.attr,
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

	xsegbd_dev = kzalloc(sizeof(*xsegbd_dev), GFP_KERNEL);
	if (!xsegbd_dev)
		goto out;

	spin_lock_init(&xsegbd_dev->lock);
	INIT_LIST_HEAD(&xsegbd_dev->node);

	/* parse cmd */
	if (sscanf(buf, "%d:%d:%d", &xsegbd_dev->src_portno, &xsegbd_dev->dst_portno, &xsegbd_dev->nr_requests) < 3) {
		ret = -EINVAL;
		goto out_dev;
	}

	mutex_lock_nested(&xsegbd_mutex, SINGLE_DEPTH_NESTING);

	list_for_each(tmp, &xsegbd_dev_list) {
		struct xsegbd_device *entry;

		entry = list_entry(tmp, struct xsegbd_device, node);

		if (entry->src_portno == xsegbd_dev->src_portno) {
			ret = -EINVAL;
			goto out_unlock;
		}

		if (xsegbd_dev->id >= new_id)
			new_id = xsegbd_dev->id + 1;
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

	XSEGLOG("allocating %u requests", xsegbd_dev->nr_requests);
	if (xseg_alloc_requests(xsegbd.xseg, xsegbd_dev->src_portno, xsegbd_dev->nr_requests)) {
		XSEGLOG("cannot allocate requests");
		ret = -EFAULT;

		goto out_bus;
	}

	ret = xsegbd_dev_init(xsegbd_dev, 0);
	if (ret)
		goto out_free_requests;

	return count;

out_free_requests:
	xseg_free_requests(xsegbd.xseg, xsegbd_dev->src_portno, xsegbd_dev->nr_requests);

out_bus:
	xsegbd_bus_del_dev(xsegbd_dev);

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
	XSEGLOG("found dev @%p", xsegbd_dev);
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
	int ret;

	ret = xsegbd_xseg_init();
	if (ret)
		goto out;

	ret = xsegbd_sysfs_init();
	if (ret)
		goto out_xseg_destroy;

	XSEGLOG("initialization complete");

	goto out;

out_xseg_destroy:
	xsegbd_xseg_quit();
out:
	return ret;
}

static void __exit xsegbd_exit(void)
{
	xsegbd_sysfs_cleanup();
	xsegbd_xseg_quit();
}

module_init(xsegbd_init);
module_exit(xsegbd_exit);
