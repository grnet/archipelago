/* xseg_segdev.c
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

#include <xseg/xseg.h>
#include <sys/kernel/segdev.h>
#include <sys/util.h>

MODULE_DESCRIPTION("xseg_segdev");
MODULE_AUTHOR("XSEG");
MODULE_LICENSE("GPL");

/* for now, support only one peer */
static struct xseg *xsegments[1];
static unsigned int nr_xsegments = 1;

struct segpriv {
	unsigned int segno;
};

static void *segdev_malloc(uint64_t size)
{
	return kmalloc((size_t)size, GFP_KERNEL);
}

static void *segdev_realloc(void *mem, uint64_t size)
{
	return krealloc(mem, (size_t)size, GFP_KERNEL);
}

static void segdev_mfree(void *ptr)
{
	return kfree(ptr);
}

static long segdev_allocate(const char *name, uint64_t size)
{
	int r;
	struct segdev *segdev = segdev_get(0);

	r = IS_ERR(segdev) ? PTR_ERR(segdev) : 0;
	if (r) {
		XSEGLOG("cannot acquire segdev");
		goto out;
	}

	if (segdev->segment) {
		XSEGLOG("destroying existing segdev segment");
		r = segdev_destroy_segment(segdev);
		if (r)
			goto out;
	}

	XSEGLOG("creating segdev segment size %llu", size);
	r = segdev_create_segment(segdev, size, 1);
	if (r)
		goto out;

	segdev_put(segdev);
	r = 0;
out:
	return r;
}

static long segdev_deallocate(const char *name)
{
	struct segdev *segdev = segdev_get(0);
	int r = IS_ERR(segdev) ? PTR_ERR(segdev) : 0;
	if (r)
		return r;

	clear_bit(SEGDEV_RESERVED, &segdev->flags);
	XSEGLOG("destroying segment");
	r = segdev_destroy_segment(segdev);
	if (r)
		XSEGLOG("   ...failed");
	segdev_put(segdev);
	return r;
}

static void *segdev_map(const char *name, uint64_t size)
{
	struct xseg *xseg = NULL;
	/* map() holds a reference to the segment */
	struct segdev *dev = segdev_get(0);
	int r;
	r = IS_ERR(dev) ? PTR_ERR(dev) : 0;
	if (r)
		goto out;

	if (!dev->segment)
		goto out;

	if (size > dev->segsize)
		goto out;

	xseg = (void *)dev->segment;
out:
	return xseg;
}

static void segdev_unmap(void *ptr, uint64_t size)
{
	struct segdev *segdev = segdev_get(0);
	int r = IS_ERR(segdev) ? PTR_ERR(segdev) : 0;
	if (r)
		return;

	/* unmap() releases the reference taken by map() */
	segdev_put(segdev);
}

static void segdev_callback(struct segdev *dev)
{
	struct xseg *xseg;
	struct segpriv *priv = dev->priv;
	struct xseg_private *xpriv;
	uint32_t portno;
	if (priv->segno > nr_xsegments)
		return;

	if (dev->buffer_index != sizeof(uint32_t)) {
		WARN_ON(1);
		return;
	}

	portno = *(uint32_t *)dev->buffer;
	xseg = xsegments[priv->segno];
	xpriv = xseg->priv;
	if (xpriv->wakeup)
		xpriv->wakeup(xseg, portno);
}

static struct xseg_type xseg_segdev = {
	/* xseg operations */
	{
		.allocate = segdev_allocate,
		.deallocate = segdev_deallocate,
		.map = segdev_map,
		.unmap = segdev_unmap
	},
	/* name */
	"segdev"
};

static int segdev_signal_init(void)
{
	struct segdev *segdev = segdev_get(0);
	struct segpriv *segpriv;
	int r = IS_ERR(segdev) ? PTR_ERR(segdev) : 0;
	if (r)
		goto out;

	r = -EADDRINUSE;
	if (xsegments[0]) 
		goto out;

	r = -ENOMEM;
	segpriv = kmalloc(sizeof(struct segpriv), GFP_KERNEL);
	if (!segpriv)
		goto out;

	segpriv->segno = 0;
	segdev->callback = segdev_callback;
	segdev->priv = segpriv;
	r = 0;
out:
	return r;
}

static void segdev_signal_quit(void)
{
	struct segdev *segdev = segdev_get(0);
	int r = IS_ERR(segdev) ? PTR_ERR(segdev) : 0;
	xsegments[0] = NULL;
	if (!r)
		segdev->callback = NULL;
	return;
}

static int segdev_prepare_wait(struct xseg *xseg, uint32_t portno)
{
	return -1;
}

static int segdev_cancel_wait(struct xseg *xseg, uint32_t portno)
{
	return -1;
}

static int segdev_wait_signal(struct xseg *xseg, uint32_t timeout)
{
	return -1;
}

static int segdev_signal(struct xseg *xseg, uint32_t portno)
{
	return -1;
}

static struct xseg_peer xseg_peer_segdev = {
	/* xseg signal operations */
	{
		.signal_init = segdev_signal_init,
		.signal_quit = segdev_signal_quit,
		.cancel_wait = segdev_cancel_wait,
		.prepare_wait = segdev_prepare_wait,
		.wait_signal = segdev_wait_signal,
		.signal = segdev_signal,
		.malloc = segdev_malloc,
		.realloc = segdev_realloc,
		.mfree = segdev_mfree
	},
	/* name */
	"segdev"
};


/* ************************* */
/* ** XSEG Initialization ** */
/* ************************* */

static int segdev_init(void)
{
	int r;

	XSEGLOG("registering xseg types");
	r = xseg_register_type(&xseg_segdev);
	if (r)
		goto err0;

	r = xseg_register_peer(&xseg_peer_segdev);
	if (r)
		goto err1;

	return 0;
err1:
	xseg_unregister_type(xseg_segdev.name);
err0:
	return r;
}

static int segdev_quit(void)
{
	struct segdev *segdev;

	/* make sure to unmap the segment first */
	segdev = segdev_get(0);
	clear_bit(SEGDEV_RESERVED, &segdev->flags);
	segdev_put(segdev);

	xseg_unregister_peer(xseg_peer_segdev.name);
	xseg_unregister_type(xseg_segdev.name);

	return 0;
}

/* *************************** */
/* ** Module Initialization ** */
/* *************************** */

static int __init xseg_segdev_init(void)
{
	int ret = -ENOSYS;

	ret = segdev_init();
	if (ret)
		goto out;

	XSEGLOG("initialization complete");
out:
	return ret;
}

static void __exit xseg_segdev_exit(void)
{
	segdev_quit();
}

module_init(xseg_segdev_init);
module_exit(xseg_segdev_exit);

