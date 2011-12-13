/*
 */

#ifndef _XSEGDEV_H
#define _XSEGDEV_H

#define XSEGDEV_MAJOR		60

#ifdef __KERNEL__ 

#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cdev.h>

#define XSEGDEV_READY		1
#define XSEGDEV_RESERVED	2

struct xsegdev {
	int minor;
	u64 segsize;
	char *segment;
	struct cdev cdev;
	unsigned long flags;
	long (*callback)(void *arg);
	void *callarg;

	spinlock_t lock;
	struct mutex mutex;
	wait_queue_head_t wq;
	atomic_t usercount;
};

int xsegdev_create_segment(struct xsegdev *dev, u64 segsize, char reserved);
int xsegdev_destroy_segment(struct xsegdev *dev);
struct xsegdev *xsegdev_get(int minor);
void xsegdev_put(struct xsegdev *dev);


#endif  /* __KERNEL__ */

#include <linux/ioctl.h>

#define XSEGDEV_IOC_MAGIC	XSEGDEV_MAJOR
#define XSEGDEV_IOC_CREATESEG	_IOR(XSEGDEV_IOC_MAGIC, 0, unsigned long)
#define XSEGDEV_IOC_DESTROYSEG	_IOR(XSEGDEV_IOC_MAGIC, 1, unsigned long)
#define XSEGDEV_IOC_SEGSIZE	_IOR(XSEGDEV_IOC_MAGIC, 2, unsigned long)

#define XSEGDEV_IOC_MAXNR	2

#endif  /* _XSEGDEV_H */

