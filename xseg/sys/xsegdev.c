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

#include "xsegdev.h"

static struct xsegdev xsegdev;

int xsegdev_create_segment(struct xsegdev *dev, u64 segsize, char reserved)
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
	segment = vmalloc(segsize);
	if (!segment)
		goto out_unlock;

	dev->segsize = segsize;
	dev->segment = segment;
	memset(dev->segment, 0, segsize);
	set_bit(XSEGDEV_READY, &dev->flags);
	if (reserved)
		set_bit(XSEGDEV_RESERVED, &dev->flags);
	ret = 0;

out_unlock:
	mutex_unlock(&dev->mutex);
out:
	return ret;
}

EXPORT_SYMBOL(xsegdev_create_segment);

int xsegdev_destroy_segment(struct xsegdev *dev)
{
	int ret = mutex_lock_interruptible(&dev->mutex);
	if (ret)
		goto out;

	/* VERIFY:
	 * The segment trully dies when everyone in userspace has unmapped it.
	 * However, the kernel mapping is immediately destroyed.
	 * Kernel users are notified to abort via switching of XSEGDEV_READY.
	 * The mapping deallocation is performed when all kernel users
	 * have stopped using the segment as reported by usercount.
	*/

	ret = -EINVAL;
	if (!dev->segment)
		goto out_unlock;

	ret = -EBUSY;
	if (test_bit(XSEGDEV_RESERVED, &dev->flags))
		goto out_unlock;

	clear_bit(XSEGDEV_READY, &dev->flags);
	ret = wait_event_interruptible(dev->wq, atomic_read(&dev->usercount) <= 1);
	if (ret)
		goto out_unlock;

	vfree(dev->segment);
	dev->segment = NULL;
	dev->segsize = 0;
	ret = 0;

out_unlock:
	mutex_unlock(&dev->mutex);
	set_bit(XSEGDEV_READY, &dev->flags);
out:
	return ret;
}

EXPORT_SYMBOL(xsegdev_destroy_segment);

struct xsegdev *xsegdev_get(int minor)
{
	struct xsegdev *dev = ERR_PTR(-ENODEV);
	if (minor)
		goto out;

	dev = &xsegdev;
	atomic_inc(&dev->usercount);
	if (!test_bit(XSEGDEV_READY, &dev->flags))
		goto fail_busy;
out:
	return dev;

fail_busy:
	atomic_dec(&dev->usercount);
	dev = ERR_PTR(-EBUSY);
	goto out;
}

EXPORT_SYMBOL(xsegdev_get);

void xsegdev_put(struct xsegdev *dev)
{
	atomic_dec(&dev->usercount);
	wake_up(&dev->wq);
	/* ain't all this too heavy ? */
}

EXPORT_SYMBOL(xsegdev_put);

/* ********************* */
/* ** File Operations ** */
/* ********************* */

struct xsegdev_file {
	int minor;
};

static int xsegdev_open(struct inode *inode, struct file *file)
{
	struct xsegdev_file *vf = kmalloc(sizeof(struct xsegdev_file), GFP_KERNEL);
	if (!vf)
		return -ENOMEM;
	vf->minor = 0;
	file->private_data = vf;
	return 0;
}

static int xsegdev_release(struct inode *inode, struct file *file)
{
	struct xsegdev_file *vf = file->private_data;
	kfree(vf);
	return 0;
}

static long xsegdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct xsegdev *dev;
	char *seg;
	long size;
	int ret = -EINVAL;

	switch (cmd) {

	case XSEGDEV_IOC_CREATESEG:
		dev = xsegdev_get(0);
		ret = IS_ERR(dev) ? PTR_ERR(dev) : 0;
		if (ret)
			goto out;

		ret = xsegdev_create_segment(dev, (u64)arg, 0);
		xsegdev_put(dev);
		goto out;

	case XSEGDEV_IOC_DESTROYSEG:
		dev = xsegdev_get(0);
		ret = xsegdev_destroy_segment(&xsegdev);
		xsegdev_put(dev);
		goto out;

	case XSEGDEV_IOC_SEGSIZE:
		dev = xsegdev_get(0);

		ret = IS_ERR(dev) ? PTR_ERR(dev) : 0;
		if (ret)
			goto out;

		size = dev->segsize;
		seg = dev->segment;
		xsegdev_put(dev);

		ret = -ENODEV;
		if (!seg)
			goto out;

		return size;
	}

out:
	return ret;
}

static ssize_t xsegdev_read(struct file *file, char __user *buf,
			   size_t count, loff_t *f_pos)
{
	return 0;
}

static ssize_t xsegdev_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *f_pos)
{
	struct xsegdev_file *vf = file->private_data;
	struct xsegdev *dev = xsegdev_get(vf->minor);
	struct xseg_port *port;
	int ret = -ENODEV;
	if (!dev)
		goto out;

	ret = copy_from_user(&port, buf, sizeof(port));
	if (ret < 0)
		goto out;

	ret = -ENOSYS;
	if (dev->callback)
		ret = dev->callback(port);

	xsegdev_put(dev);
out:
	return ret;
}

static int xsegdev_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct xsegdev_file *vf = file->private_data;
	struct xsegdev *dev;
	size_t size = vma->vm_end - vma->vm_start;
	unsigned long start = vma->vm_start, end = start + size;
	char *ptr;
	int ret = -ENODEV;

	dev = xsegdev_get(vf->minor);
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
	xsegdev_put(dev);
out:
	return ret;
}

static struct file_operations xsegdev_ops = 
{
        .owner		= THIS_MODULE,
	.open		= xsegdev_open,
	.release	= xsegdev_release,
	.read		= xsegdev_read,
	.write		= xsegdev_write,
	.mmap		= xsegdev_mmap,
	.unlocked_ioctl	= xsegdev_ioctl,
};


/* *************************** */
/* ** Module Initialization ** */
/* *************************** */

static void xsegdev_init(struct xsegdev *dev, int minor)
{
	dev->minor = 0;
	dev->segment = NULL;
	dev->segsize = 0;
	dev->flags = 0;
	atomic_set(&dev->usercount, 0);
	init_waitqueue_head(&dev->wq);
	cdev_init(&dev->cdev, &xsegdev_ops);
	mutex_init(&dev->mutex);
	spin_lock_init(&dev->lock);
	dev->cdev.owner = THIS_MODULE;
	set_bit(XSEGDEV_READY, &dev->flags);
}

int __init xsegdev_mod_init(void)
{
	int ret;
	dev_t dev_no = MKDEV(XSEGDEV_MAJOR, 0);
	ret = register_chrdev_region(dev_no, 1, "xsegdev");
	if (ret < 0)
		goto out;

	xsegdev_init(&xsegdev, 0);
	ret = cdev_add(&xsegdev.cdev, dev_no, 1);
	if (ret < 0)
		goto out_unregister;

	return ret;

out_unregister:
	unregister_chrdev_region(dev_no, 1);
out:
	return ret;
}

void __exit xsegdev_mod_exit(void)
{
	dev_t dev_no = MKDEV(XSEGDEV_MAJOR, 0);
	xsegdev_destroy_segment(&xsegdev);
	cdev_del(&xsegdev.cdev);
	unregister_chrdev_region(dev_no, 1);
}

module_init(xsegdev_mod_init);
module_exit(xsegdev_mod_exit);

MODULE_DESCRIPTION("xsegdev");
MODULE_AUTHOR("XSEG");
MODULE_LICENSE("GPL");

