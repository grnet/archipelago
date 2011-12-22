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

#include "xsegdev.h"
#include "xsegbd.h"

#define XSEGBD_MINORS 1

MODULE_DESCRIPTION("xsegbd");
MODULE_AUTHOR("XSEG");
MODULE_LICENSE("GPL");

static long sector_size = 100000;
static long blksize = 512;
static int major = 0;
static char name[XSEGBD_VOLUME_NAMELEN] = "xsegbd";
static char spec[256] = "xsegdev:xsegbd:4:512:64:1024:12";
static int src_portno = 0, dst_portno = 1, nr_requests = 128;

module_param(sector_size, long, 0644);
module_param(blksize, long, 0644);
module_param(major, int, 0644);
module_param(src_portno, int, 0644);
module_param(dst_portno, int, 0644);
module_param(nr_requests, int, 0644);
module_param_string(name, name, sizeof(name), 0644);
module_param_string(spec, spec, sizeof(spec), 0644);

static volatile int count;
struct semaphore xsegbd_lock;
static struct xsegbd xsegbd;


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
	dev->callarg = &xsegbd;
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

	xsegdev->callarg = NULL;
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
/* ** XSEG Initialization ** */
/* ************************* */

int xsegbd_xseg_init(struct xsegbd *dev)
{
	struct xseg_port *xport;
	int r;

	if (!dev->name[0])
		strncpy(dev->name, name, XSEGBD_VOLUME_NAMELEN);

	XSEGLOG("registering xseg types");
	dev->namesize = strlen(dev->name);
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

	r = xseg_parse_spec(spec, &dev->config);
	if (r)
		goto err3;

	if (strncmp(dev->config.type, "xsegdev", 16))
		XSEGLOG("WARNING: unexpected segment type '%s' vs 'xsegdev'",
			 dev->config.type);

	XSEGLOG("creating segment");
	r = xseg_create(&dev->config);
	if (r) {
		XSEGLOG("cannot create segment");
		goto err3;
	}

	XSEGLOG("joining segment");
	dev->xseg = xseg_join("xsegdev", "xsegbd");
	if (!dev->xseg) {
		XSEGLOG("cannot join segment");
		r = -EFAULT;
		goto err3;
	}

	XSEGLOG("binding to source port %u (destination %u)",
		 src_portno, dst_portno);
	xport = xseg_bind_port(dev->xseg, src_portno);
	if (!xport) {
		XSEGLOG("cannot bind to port");
		dev->xseg = NULL;
		r = -EFAULT;
		goto err3;
	}
	dev->src_portno = xseg_portno(dev->xseg, xport);
	dev->dst_portno = dst_portno;

	if (nr_requests > dev->xseg->config.nr_requests)
		nr_requests = dev->xseg->config.nr_requests;

	if (xseg_alloc_requests(dev->xseg, src_portno, nr_requests)) {
		XSEGLOG("cannot allocate requests");
		dev->xseg = NULL;
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

int xsegbd_xseg_quit(struct xsegbd *dev)
{
	/* make sure to unmap the segment first */
	dev->xseg->type.ops.unmap(dev->xseg, dev->xseg->segment_size);

	xseg_destroy(dev->xseg);
	dev->xseg = NULL;
	return 0;
}


/* ***************************** */
/* ** Block Device Operations ** */
/* ***************************** */

static int xsegbd_open(struct block_device *bdev, fmode_t mode)
{
	int ret = down_interruptible(&xsegbd_lock);
	if (ret == 0) {
		count ++;
		up(&xsegbd_lock);
	}
	return ret;
}

static int xsegbd_release(struct gendisk *gd, fmode_t mode)
{
	int ret = down_interruptible(&xsegbd_lock);
	if (ret == 0) {
		count --;
		up(&xsegbd_lock);
	}
	return ret;
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

static loff_t xsegbd_get_size(struct xsegbd *dev)
{
	struct xseg_request *xreq;
	char *name, *data;
	uint64_t datasize;
	loff_t size;

	xseg_prepare_wait(dev->xseg, dev->src_portno);

	if ((xreq = xseg_get_request(dev->xseg, dev->src_portno))) {
		xseg_cancel_wait(dev->xseg, dev->src_portno);

		datasize = sizeof(loff_t);
		BUG_ON(xreq->buffersize - dev->namesize < datasize);
		BUG_ON(xseg_prep_request(xreq, dev->namesize, datasize));

		name = XSEG_TAKE_PTR(xreq->name, dev->xseg->segment);
		strncpy(name, dev->name, dev->namesize);
		xreq->size = datasize;
		xreq->offset = 0;

		xreq->op = X_INFO;

		BUG_ON(xseg_submit(dev->xseg, dev->dst_portno, xreq) == NoSerial);

		xseg_signal(dev->xseg, dev->dst_portno);
	}

	while (!(xreq = xseg_receive(dev->xseg, dev->src_portno))) ;

	xseg_cancel_wait(dev->xseg, dev->src_portno);
	while (!(xreq->state & XS_SERVED)) ;

	data = XSEG_TAKE_PTR(xreq->data, dev->xseg->segment);
	size = *((off_t *) data);

	if (xreq)
		xseg_put_request(dev->xseg, dev->src_portno, xreq);

	return size;
}

static int xsegbd_dev_init(struct xsegbd *dev, int id, sector_t size)
{
	int ret = -ENOMEM;
	struct gendisk *disk;

	spin_lock_init(&dev->lock);

	dev->id = id;
	dev->blk_queue = blk_alloc_queue(GFP_KERNEL);
	if (!dev->blk_queue)
		goto out;

	blk_init_allocated_queue(dev->blk_queue, xseg_request_fn, &dev->lock);
	dev->blk_queue->queuedata = dev;

	blk_queue_flush(dev->blk_queue, REQ_FLUSH | REQ_FUA);
	blk_queue_logical_block_size(dev->blk_queue, 512);
	blk_queue_physical_block_size(dev->blk_queue, blksize);
	blk_queue_bounce_limit(dev->blk_queue, BLK_BOUNCE_ANY);
	/* we can handle any number of segments, BUT
	 * parts of the request may be available far sooner than others
	 * but we cannot complete them (unless we handle their bios directly).
	 */
	blk_queue_max_segments(dev->blk_queue, 1);
	queue_flag_set_unlocked(QUEUE_FLAG_NONROT, dev->blk_queue);

	/* vkoukis says we don't need partitions */
	dev->gd = disk = alloc_disk(1);
	if (!disk)
		goto out_free_queue;

	disk->major = major;
	disk->first_minor = id * XSEGBD_MINORS;
	disk->fops = &xsegbd_ops;
	disk->queue = dev->blk_queue;
	disk->private_data = dev;
	disk->flags |= GENHD_FL_SUPPRESS_PARTITION_INFO;
	snprintf(disk->disk_name, 32, "xsegbd%c", 'a' + id);

	ret = xsegbd_xseg_init(dev);
	if (ret < 0)
		goto out_free_disk;

	if (!xq_alloc_seq(&dev->blk_queue_pending, nr_requests, nr_requests))
		goto out_quit;

	dev->blk_req_pending = kmalloc(sizeof(struct request *) * nr_requests, GFP_KERNEL);
	if (!dev->blk_req_pending)
		goto out_free_pending;

	dev->sectors = xsegbd_get_size(dev) / 512ULL;
	set_capacity(disk, dev->sectors);

	add_disk(disk); /* immediately activates the device */

out:
	return ret;

out_free_pending:
	xq_free(&dev->blk_queue_pending);

out_quit:
	xsegbd_xseg_quit(dev);

out_free_disk:
	put_disk(disk);

out_free_queue:
	blk_cleanup_queue(dev->blk_queue);

	goto out;
}

static int xsegbd_dev_destroy(struct xsegbd *dev)
{
	xq_free(&dev->blk_queue_pending);
	kfree(dev->blk_req_pending);
	del_gendisk(dev->gd);
	put_disk(dev->gd);
	blk_cleanup_queue(dev->blk_queue);
	xsegbd_xseg_quit(dev);
	return 0;
}


/* *************************** */
/* ** Module Initialization ** */
/* *************************** */

static int __init xsegbd_init(void)
{
	int ret;

        sema_init(&xsegbd_lock, 1);

	XSEGLOG("registering block device major %d", major);
	ret = register_blkdev(major, XSEGBD_NAME);
	if (ret < 0) {
		XSEGLOG("cannot register block device!");
		ret = -EBUSY;
		goto out;
	}
	major = ret;
	XSEGLOG("registered block device major %d", major);

	XSEGLOG("initializing device");
	ret = xsegbd_dev_init(&xsegbd, 0, sector_size);
	if (ret < 0) {
		XSEGLOG("cannot initialize device!");
		goto unregister;
	}

	XSEGLOG("initialization complete");
out:
	return ret;

unregister:
	unregister_blkdev(major, XSEGBD_NAME);
	goto out;
}

static void __exit xsegbd_exit(void)
{
	unregister_blkdev(major, XSEGBD_NAME);

	xseg_disable_driver(xsegbd.xseg, "posix");
	xseg_unregister_peer("posix");
	xseg_disable_driver(xsegbd.xseg, "xsegdev");
	xseg_unregister_peer("xsegdev");

	xsegbd_dev_destroy(&xsegbd);
	xseg_unregister_type("xsegdev");
}

module_init(xsegbd_init);
module_exit(xsegbd_exit);


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
	struct xsegbd *dev = rq->queuedata;
	struct request *blkreq;
	xqindex blkreq_idx;
	char *name;
	uint64_t datasize;

	for (;;) {
		xreq = xseg_get_request(dev->xseg, dev->src_portno);
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
		BUG_ON(xreq->buffersize - dev->namesize < datasize);
		BUG_ON(xseg_prep_request(xreq, dev->namesize, datasize));

		name = XSEG_TAKE_PTR(xreq->name, dev->xseg->segment);
		strncpy(name, dev->name, dev->namesize);
		blkreq_idx = xq_pop_head(&dev->blk_queue_pending);
		BUG_ON(blkreq_idx == None);
		/* WARN_ON(dev->blk_req_pending[blkreq_idx] */
		dev->blk_req_pending[blkreq_idx] = blkreq;
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
			blk_to_xseg(dev->xseg, xreq, blkreq);
			xreq->op = X_WRITE;
		} else {
			xreq->op = X_READ;
		}

		BUG_ON(xseg_submit(dev->xseg, dev->dst_portno, xreq) == NoSerial);
	}

	if (xreq)
		xseg_put_request(dev->xseg, dev->src_portno, xreq);
}

static long xseg_callback(void *arg)
{
	struct xsegbd *dev = arg;
	struct xseg_request *xreq;
	struct request *blkreq;
	unsigned long flags;
	xqindex blkreq_idx;
	int err;

	for (;;) {
		xreq = xseg_receive(dev->xseg, dev->src_portno);
		if (!xreq)
			break;

		/* we rely upon our peers to not have touched ->priv */
		blkreq_idx = (xqindex)(unsigned long)xreq->priv;
		if (blkreq_idx < 0 || blkreq_idx >= nr_requests) {
			XSEGLOG("invalid request index: %u! Ignoring.", blkreq_idx);
			goto xseg_put;
		}

		blkreq = dev->blk_req_pending[blkreq_idx];
		/* WARN_ON(!blkreq); */
		err = -EIO;

		if (!(xreq->state & XS_SERVED))
			goto blk_end;

		if (xreq->serviced != blk_rq_bytes(blkreq))
			goto blk_end;

		/* unlock for data transfer? */
		if (!rq_data_dir(blkreq))
			xseg_to_blk(dev->xseg, xreq, blkreq);

		err = 0;
blk_end:
		blk_end_request_all(blkreq, err);
		xq_append_head(&dev->blk_queue_pending, blkreq_idx);
xseg_put:
		xseg_put_request(dev->xseg, xreq->portno, xreq);
	}

	spin_lock_irqsave(&dev->lock, flags);
	xseg_request_fn(dev->blk_queue);
	spin_unlock_irqrestore(&dev->lock, flags);
	return 0;
}


