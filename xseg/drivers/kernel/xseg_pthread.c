/*
 * Copyright (C) 2012 GRNET S.A.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/* xseg_pthread.c
 * kernel driver for pthread peers
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
#include <xtypes/xpool.h>
#include <drivers/xseg_pthread.h>

MODULE_DESCRIPTION("xseg_pthread");
MODULE_AUTHOR("XSEG");
MODULE_LICENSE("GPL");

static int pthread_remote_signal_init(void)
{
	return 0;
}

static void pthread_remote_signal_quit(void)
{
	return;
}

static int pthread_local_signal_init(struct xseg *xseg, xport portno)
{
	return -1;
}

static void pthread_local_signal_quit(struct xseg *xseg, xport portno)
{
	return;
}

static int pthread_prepare_wait(struct xseg *xseg, uint32_t portno)
{
	return -1;
}

static int pthread_cancel_wait(struct xseg *xseg, uint32_t portno)
{
	return -1;
}

static int pthread_wait_signal(struct xseg *xseg, void *sd, uint32_t timeout)
{
	return -1;
}

static int pthread_signal(struct xseg *xseg, uint32_t portno)
{
	struct pid *pid;
	int i;
	pid_t cue = 0;
	struct task_struct *task;
	int ret = -ENOENT;
	struct pthread_signal_desc *psd;
	struct xseg_port *port = xseg_get_port(xseg, portno);
	if (!port) 
		return -1;
	psd = xseg_get_signal_desc(xseg, port);
	if (!psd)
		return -1;

	rcu_read_lock();
	/* XXX Security: xseg peers can kill anyone */

	for (i = 0; i < MAX_WAITERS; i++) {
		cue = psd->pids[i];
		if (cue)
			break;
	}
	if (!cue){
		/* no waiters found */
		ret = 0;
		goto out;
	}


	pid = find_vpid(cue);
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

static void *pthread_malloc(uint64_t size)
{
	return NULL;
}

static void *pthread_realloc(void *mem, uint64_t size)
{
	return NULL;
}

static void pthread_mfree(void *mem) { }

int pthread_init_signal_desc(struct xseg *xseg, void *sd)
{
	return -1;
}

void pthread_quit_signal_desc(struct xseg *xseg, void *sd)
{
	return;
}

void * pthread_alloc_data(struct xseg *xseg)
{
	return NULL;
}

void pthread_free_data(struct xseg *xseg, void *data)
{
	return;
}

void *pthread_alloc_signal_desc(struct xseg *xseg, void *data)
{
	return NULL;
}

void pthread_free_signal_desc(struct xseg *xseg, void *data, void *sd)
{
	return;
}


static struct xseg_peer xseg_peer_pthread = {
	/* xseg signal operations */
	{
		.init_signal_desc   = pthread_init_signal_desc,
		.quit_signal_desc   = pthread_quit_signal_desc,
		.alloc_data         = pthread_alloc_data,
		.free_data          = pthread_free_data,
		.alloc_signal_desc  = pthread_alloc_signal_desc,
		.free_signal_desc   = pthread_free_signal_desc,
		.local_signal_init  = pthread_local_signal_init,
		.local_signal_quit  = pthread_local_signal_quit,
		.remote_signal_init = pthread_remote_signal_init,
		.remote_signal_quit = pthread_remote_signal_quit,
		.prepare_wait	    = pthread_prepare_wait,
		.cancel_wait = pthread_cancel_wait,
		.prepare_wait = pthread_prepare_wait,
		.wait_signal = pthread_wait_signal,
		.signal = pthread_signal,
		.malloc = pthread_malloc,
		.realloc = pthread_realloc,
		.mfree = pthread_mfree
	},
	/* name */
	"pthread"
};

static int pthread_init(void)
{
	int r;

	XSEGLOG("registering xseg types");

	r = xseg_register_peer(&xseg_peer_pthread);

	return r;
}

static int pthread_quit(void)
{
	xseg_unregister_peer(xseg_peer_pthread.name);
	return 0;
}

/* *************************** */
/* ** Module Initialization ** */
/* *************************** */

static int __init xseg_pthread_init(void)
{
	int ret = -ENOSYS;

	ret = pthread_init();
	if (ret)
		goto out;

	XSEGLOG("initialization complete");
out:
	return ret;
}

static void __exit xseg_pthread_exit(void)
{
	pthread_quit();
}

module_init(xseg_pthread_init);
module_exit(xseg_pthread_exit);
