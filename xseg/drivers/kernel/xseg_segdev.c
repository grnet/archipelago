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
#include <drivers/xseg_segdev.h>
#include <peers/kernel/xsegbd.h>
MODULE_DESCRIPTION("xseg_segdev");
MODULE_AUTHOR("XSEG");
MODULE_LICENSE("BSD");

/* FIXME */
static struct xseg *xsegments[65536];
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

	/*
	if (segdev->segment) {
		XSEGLOG("destroying existing segdev segment");
		r = segdev_destroy_segment(segdev);
		if (r)
			goto out;
	}
	*/

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

static void *segdev_map(const char *name, uint64_t size, struct xseg *seg)
{
	struct xseg *xseg = NULL;
	/* map() holds a reference to the segment */
	struct segdev *dev = segdev_get(0);
	struct segpriv *priv;
	int r;
	r = IS_ERR(dev) ? PTR_ERR(dev) : 0;
	if (r)
		goto out;

	if (!dev->segment)
		goto out;

	if (size > dev->segsize)
		goto out;

	priv = dev->priv;
	if (priv->segno >= nr_xsegments)
		goto out;

//	if (seg)
//		xsegments[priv->segno] = seg;

	xseg = (void *)dev->segment;
out:
	return xseg;
}

static void segdev_unmap(void *ptr, uint64_t size)
{
	struct segdev *segdev = segdev_get(0);
	struct segpriv *priv;
	int r = IS_ERR(segdev) ? PTR_ERR(segdev) : 0;
	if (r)
		return;

	priv = segdev->priv;
	if (priv->segno >= nr_xsegments)
		goto out;

//	xsegments[priv->segno] = NULL;

out:
	/* unmap() releases the reference taken by map() */
	segdev_put(segdev);

	segdev_put(segdev);
}

static void segdev_callback(struct segdev *dev, xport portno)
{
	struct xseg *xseg;
	struct segpriv *priv = dev->priv;
	struct xseg_private *xpriv;
	struct xseg_port *port;
	struct segdev_signal_desc *ssd;

	xseg = xsegments[portno];
	if (!xseg)
		return;
	if (priv->segno >= nr_xsegments)
		return;

	xpriv = xseg->priv;
	port = xseg_get_port(xseg, portno);
	if (!port)
		return;
	ssd = xseg_get_signal_desc(xseg, port);
	if (!ssd || !ssd->waitcue){
		return;
	}

	if (xpriv->wakeup) {
		xpriv->wakeup(portno);
	}
	return;
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

static int segdev_remote_signal_init(void)
{
	return 0;
}

static void segdev_remote_signal_quit(void)
{
	return;
}

static int segdev_local_signal_init(struct xseg *xseg, xport portno)
{
	//assert xsegments[portno] == NULL;
	xsegments[portno] = xseg;
	return 0;
}

static void segdev_local_signal_quit(struct xseg *xseg, xport portno)
{
	//assert xsegments[portno] == xseg;
	xsegments[portno] = NULL;
	return;
}

static int segdev_prepare_wait(struct xseg *xseg, uint32_t portno)
{
	struct segdev_signal_desc *ssd; 
	struct xseg_port *port = xseg_get_port(xseg, portno);
	if (!port)
		return -1;
	ssd = xseg_get_signal_desc(xseg, port);
	if (!ssd)
		return -1;
	/* true/false value */
	ssd->waitcue = 1;
	return 0;
}

static int segdev_cancel_wait(struct xseg *xseg, uint32_t portno)
{
	struct segdev_signal_desc *ssd; 
	struct xseg_port *port = xseg_get_port(xseg, portno);
	if (!port)
		return -1;
	ssd = xseg_get_signal_desc(xseg, port);
	if (!ssd)
		return -1;
	/* true/false value */
	ssd->waitcue = 0;
	return -0;
}

static int segdev_wait_signal(struct xseg *xseg, uint32_t timeout)
{
	return -1;
}

static int segdev_signal(struct xseg *xseg, uint32_t portno)
{
	return -1;
}

static int segdev_init_signal_desc(struct xseg *xseg, void *sd)
{
	struct segdev_signal_desc *ssd = sd;
	if (!ssd)
		return -1;
	ssd->waitcue = 0;
	return 0;
}

static void segdev_quit_signal_desc(struct xseg *xseg, void *sd)
{
	return;
}

static void *segdev_alloc_data(struct xseg *xseg)
{
	struct xobject_h *sd_h = xseg_get_objh(xseg, MAGIC_SEGDEV_SD,
				sizeof(struct segdev_signal_desc));
	return sd_h;
}

static void segdev_free_data(struct xseg *xseg, void *data)
{
	if (data)
		xseg_put_objh(xseg, (struct xobject_h *)data);
}

static void *segdev_alloc_signal_desc(struct xseg *xseg, void *data)
{
	struct segdev_signal_desc *ssd;
	struct xobject_h *sd_h = (struct xobject_h *) data;
	if (!sd_h)
		return NULL;
	ssd = xobj_get_obj(sd_h, X_ALLOC);
	if (!ssd)
		return NULL;
	ssd->waitcue = 0;
	return ssd;
}

static void segdev_free_signal_desc(struct xseg *xseg, void *data, void *sd)
{
	struct xobject_h *sd_h = (struct xobject_h *) data;
	if (!sd_h)
		return;
	if (sd)
		xobj_put_obj(sd_h, sd);
	return;
}

static struct xseg_peer xseg_peer_segdev = {
	/* xseg signal operations */
	{
		.init_signal_desc   = segdev_init_signal_desc,
		.quit_signal_desc   = segdev_quit_signal_desc,
		.alloc_data         = segdev_alloc_data,
		.free_data          = segdev_free_data,
		.alloc_signal_desc  = segdev_alloc_signal_desc,
		.free_signal_desc   = segdev_free_signal_desc,
		.local_signal_init  = segdev_local_signal_init,
		.local_signal_quit  = segdev_local_signal_quit,
		.remote_signal_init = segdev_remote_signal_init,
		.remote_signal_quit = segdev_remote_signal_quit,
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
	struct segdev *segdev;
	struct segpriv *segpriv;
	int r;

	XSEGLOG("registering xseg types");
	r = xseg_register_type(&xseg_segdev);
	if (r)
		goto err0;

	r = xseg_register_peer(&xseg_peer_segdev);
	if (r)
		goto err1;
	
	segdev = segdev_get(0);
	r = IS_ERR(segdev) ? PTR_ERR(segdev) : 0;
	if (r)
		goto err2;

	r = -ENOMEM;
	segpriv = kmalloc(sizeof(struct segpriv), GFP_KERNEL);
	if (!segpriv)
		goto err3;

	segpriv->segno = 0;
	segdev->callback = segdev_callback;
	segdev->priv = segpriv;

	return 0;

err3:
	segdev_put(segdev);
err2:
	xseg_unregister_peer(xseg_peer_segdev.name);
err1:
	xseg_unregister_type(xseg_segdev.name);
err0:
	return r;
}

static int segdev_quit(void)
{
	struct segdev *segdev = segdev_get(0);
	int r = IS_ERR(segdev) ? PTR_ERR(segdev) : 0;
	if (!r){
		/* make sure to unmap the segment first */
		clear_bit(SEGDEV_RESERVED, &segdev->flags);
		segdev->callback = NULL;
		//FIXME what aboud segdev->priv?
		segdev_put(segdev);
	}
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

