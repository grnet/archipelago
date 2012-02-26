/*
 */

#ifndef _SEGDEV_H
#define _SEGDEV_H

#define SEGDEV_MAJOR		60

#ifdef __KERNEL__ 

#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cdev.h>

#define SEGDEV_READY		1
#define SEGDEV_RESERVED		2
#define SEGDEV_BUFSIZE		1024

struct segdev {
	int minor;
	u64 segsize;
	char *segment;
	struct cdev cdev;
	unsigned long flags;
	void (*callback)(struct segdev *dev);
	void *priv;

	spinlock_t lock;
	struct mutex mutex;
	wait_queue_head_t wq;
	atomic_t usercount;
	unsigned int buffer_index;
	char buffer[SEGDEV_BUFSIZE];
};

int segdev_create_segment(struct segdev *dev, u64 segsize, char reserved);
int segdev_destroy_segment(struct segdev *dev);
struct segdev *segdev_get(int minor);
void segdev_put(struct segdev *dev);


#endif  /* __KERNEL__ */

#include <linux/ioctl.h>

#define SEGDEV_IOC_MAGIC	SEGDEV_MAJOR
#define SEGDEV_IOC_CREATESEG	_IOR(SEGDEV_IOC_MAGIC, 0, unsigned long)
#define SEGDEV_IOC_DESTROYSEG	_IOR(SEGDEV_IOC_MAGIC, 1, unsigned long)
#define SEGDEV_IOC_SEGSIZE	_IOR(SEGDEV_IOC_MAGIC, 2, unsigned long)

#define SEGDEV_IOC_MAXNR	2

#endif  /* _SEGDEV_H */

