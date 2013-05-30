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

/*
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/mmzone.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <sys/util.h>
#include "segdev.h"

static struct segdev segdev;

int segdev_create_segment(struct segdev *dev, u64 segsize, char reserved)
{
	void *segment;
	int ret = mutex_lock_interruptible(&dev->mutex);
	if (ret)
		goto out;

	ret = -EBUSY;
	if (dev->segment)
		goto out_unlock;

	/* vmalloc can handle large sizes */
	ret = -ENOMEM;
	XSEGLOG("creating segment of size %llu\n", segsize);
	segment = vmalloc(segsize);
	if (!segment)
		goto out_unlock;

	dev->segsize = segsize;
	dev->segment = segment;
	memset(dev->segment, 0, segsize);
	set_bit(SEGDEV_READY, &dev->flags);
	if (reserved)
		set_bit(SEGDEV_RESERVED, &dev->flags);
	ret = 0;

out_unlock:
	mutex_unlock(&dev->mutex);
out:
	return ret;
}

EXPORT_SYMBOL(segdev_create_segment);

int segdev_destroy_segment(struct segdev *dev)
{
	int ret = mutex_lock_interruptible(&dev->mutex);
	if (ret)
		goto out;

	/* VERIFY:
	 * The segment trully dies when everyone in userspace has unmapped it.
	 * However, the kernel mapping is immediately destroyed.
	 * Kernel users are notified to abort via switching of SEGDEV_READY.
	 * The mapping deallocation is performed when all kernel users
	 * have stopped using the segment as reported by usercount.
	*/

	ret = -EINVAL;
	if (!dev->segment)
		goto out_unlock;

	ret = -EBUSY;
	if (test_bit(SEGDEV_RESERVED, &dev->flags))
		goto out_unlock;

	clear_bit(SEGDEV_READY, &dev->flags);
	ret = wait_event_interruptible(dev->wq, atomic_read(&dev->usercount) <= 1);
	if (ret)
		goto out_unlock;

	vfree(dev->segment);
	dev->segment = NULL;
	dev->segsize = 0;
	ret = 0;

out_unlock:
	mutex_unlock(&dev->mutex);
	set_bit(SEGDEV_READY, &dev->flags);
out:
	return ret;
}

EXPORT_SYMBOL(segdev_destroy_segment);

struct segdev *segdev_get(int minor)
{
	struct segdev *dev = ERR_PTR(-ENODEV);
	if (minor)
		goto out;

	dev = &segdev;
	atomic_inc(&dev->usercount);
	if (!test_bit(SEGDEV_READY, &dev->flags))
		goto fail_busy;
out:
	return dev;

fail_busy:
	segdev_put(dev);
	dev = ERR_PTR(-EBUSY);
	goto out;
}

EXPORT_SYMBOL(segdev_get);

void segdev_put(struct segdev *dev)
{
	atomic_dec(&dev->usercount);
	wake_up(&dev->wq);
	/* ain't all this too heavy ? */
}

EXPORT_SYMBOL(segdev_put);

/* ********************* */
/* ** File Operations ** */
/* ********************* */

struct segdev_file {
	int minor;
};

static int segdev_open(struct inode *inode, struct file *file)
{
	struct segdev_file *vf = kmalloc(sizeof(struct segdev_file), GFP_KERNEL);
	if (!vf)
		return -ENOMEM;
	vf->minor = 0;
	file->private_data = vf;
	return 0;
}

static int segdev_release(struct inode *inode, struct file *file)
{
	struct segdev_file *vf = file->private_data;
	kfree(vf);
	return 0;
}

static long segdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct segdev *dev;
	char *seg;
	long size;
	int ret = -EINVAL;

	switch (cmd) {

	case SEGDEV_IOC_CREATESEG:
		dev = segdev_get(0);
		ret = IS_ERR(dev) ? PTR_ERR(dev) : 0;
		if (ret)
			goto out;

		ret = segdev_create_segment(dev, (u64)arg, 0);
		segdev_put(dev);
		goto out;

	case SEGDEV_IOC_DESTROYSEG:
		dev = segdev_get(0);
		ret = segdev_destroy_segment(&segdev);
		segdev_put(dev);
		goto out;

	case SEGDEV_IOC_SEGSIZE:
		dev = segdev_get(0);

		ret = IS_ERR(dev) ? PTR_ERR(dev) : 0;
		if (ret)
			goto out;

		size = dev->segsize;
		seg = dev->segment;
		segdev_put(dev);

		ret = -ENODEV;
		if (!seg)
			goto out;

		return size;
	}

out:
	return ret;
}

static ssize_t segdev_read(struct file *file, char __user *buf,
			   size_t count, loff_t *f_pos)
{
	return 0;
}

static ssize_t segdev_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *f_pos)
{
	struct segdev_file *vf = file->private_data;
	struct segdev *dev = segdev_get(vf->minor);
	uint32_t portno;
	int ret = -ENODEV;
	if (!dev)
		goto out;

	if (count != sizeof(uint32_t))
		goto out_put;

	ret = copy_from_user(&portno, buf, sizeof(uint32_t));
	if (ret < 0)
		goto out_put;

	if((count - ret) != sizeof(uint32_t))
		goto out_put;

	ret = 0;
	if (dev->callback)
		dev->callback(dev, portno);
	else
		ret = -ENOSYS;

	dev->buffer_index = 0;
out_put:
	segdev_put(dev);
out:
	return ret;
}

static int segdev_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct segdev_file *vf = file->private_data;
	struct segdev *dev;
	size_t size = vma->vm_end - vma->vm_start;
	unsigned long start = vma->vm_start, end = start + size;
	char *ptr;
	int ret = -ENODEV;

	dev = segdev_get(vf->minor);
	if (IS_ERR(dev))
		goto out;

	ptr = dev->segment;
	if (!ptr)
		goto out_put;

	ret = -EINVAL;

	/* do not allow offset mappings, for now */
	if (vma->vm_pgoff || size > dev->segsize)
		goto out_put;

	/* allow only shared, read-write mappings */
	if (!(vma->vm_flags & VM_SHARED))
		goto out_put;

	/* the segment is vmalloc() so we have to iterate through
         * all pages and laboriously map them one by one. */
	for (; start < end; start += PAGE_SIZE, ptr += PAGE_SIZE) {
		ret = remap_pfn_range(vma, start, vmalloc_to_pfn(ptr),
				      PAGE_SIZE, vma->vm_page_prot);
		if (ret)
			goto out_put; /* mmap syscall should clean up, right? */
	}

	ret = 0;

out_put:
	segdev_put(dev);
out:
	return ret;
}

static struct file_operations segdev_ops = 
{
        .owner		= THIS_MODULE,
	.open		= segdev_open,
	.release	= segdev_release,
	.read		= segdev_read,
	.write		= segdev_write,
	.mmap		= segdev_mmap,
	.unlocked_ioctl	= segdev_ioctl,
};


/* *************************** */
/* ** Module Initialization ** */
/* *************************** */

static void segdev_init(struct segdev *dev, int minor)
{
	dev->minor = 0;
	dev->segment = NULL;
	dev->segsize = 0;
	dev->flags = 0;
	atomic_set(&dev->usercount, 0);
	init_waitqueue_head(&dev->wq);
	cdev_init(&dev->cdev, &segdev_ops);
	mutex_init(&dev->mutex);
	spin_lock_init(&dev->lock);
	dev->cdev.owner = THIS_MODULE;
	set_bit(SEGDEV_READY, &dev->flags);
}

int __init segdev_mod_init(void)
{
	int ret;
	dev_t dev_no = MKDEV(SEGDEV_MAJOR, 0);
	ret = register_chrdev_region(dev_no, 1, "segdev");
	if (ret < 0)
		goto out;

	segdev_init(&segdev, 0);
	ret = cdev_add(&segdev.cdev, dev_no, 1);
	if (ret < 0)
		goto out_unregister;

	return ret;

out_unregister:
	unregister_chrdev_region(dev_no, 1);
out:
	return ret;
}

void __exit segdev_mod_exit(void)
{
	dev_t dev_no = MKDEV(SEGDEV_MAJOR, 0);
	segdev_destroy_segment(&segdev);
	cdev_del(&segdev.cdev);
	unregister_chrdev_region(dev_no, 1);
}

module_init(segdev_mod_init);
module_exit(segdev_mod_exit);

MODULE_DESCRIPTION("segdev");
MODULE_AUTHOR("XSEG");
MODULE_LICENSE("BSD");

