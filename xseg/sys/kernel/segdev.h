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
#define SEGDEV_BUFSIZE		512

struct segdev {
	int minor;
	u64 segsize;
	char *segment;
	struct cdev cdev;
	unsigned long flags;
	void (*callback)(struct segdev *segdev, uint32_t portno);
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

