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

/* xseg_posix.c
 * kernel driver for posix peers
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
#include <drivers/xseg_posix.h>

MODULE_DESCRIPTION("xseg_posix");
MODULE_AUTHOR("XSEG");
MODULE_LICENSE("GPL");

static int posix_remote_signal_init(void)
{
	return 0;
}

static void posix_remote_signal_quit(void)
{
	return;
}

static int posix_local_signal_init(struct xseg *xseg, xport portno)
{
	return -1;
}

static void posix_local_signal_quit(struct xseg *xseg, xport portno)
{
	return;
}

static int posix_prepare_wait(struct xseg *xseg, uint32_t portno)
{
	return -1;
}

static int posix_cancel_wait(struct xseg *xseg, uint32_t portno)
{
	return -1;
}

static int posix_wait_signal(struct xseg *xseg, void *sd, uint32_t timeout)
{
	return -1;
}

static int posix_signal(struct xseg *xseg, uint32_t portno)
{
	struct posix_signal_desc *psd;
	struct pid *pid;
	struct task_struct *task;
	int ret = -ENOENT;
	uint64_t p;
	struct xseg_port *port = xseg_get_port(xseg, portno);
	if (!port) 
		return -1;

	psd = xseg_get_signal_desc(xseg, port);
	if (!psd)
		return -1;

	rcu_read_lock();
	/* XXX Security: xseg peers can kill anyone */
	p = * (volatile uint64_t *) &psd->waitcue;
	if (!p) {
		ret = 0;
		goto out;
	}

	pid = find_vpid((pid_t)p);
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

int posix_init_signal_desc(struct xseg *xseg, void *sd)
{
	return -1;
}

void posix_quit_signal_desc(struct xseg *xseg, void *sd)
{
	return;
}

void * posix_alloc_data(struct xseg *xseg)
{
	return NULL;
}

void posix_free_data(struct xseg *xseg, void *data)
{
	return;
}

void *posix_alloc_signal_desc(struct xseg *xseg, void *data)
{
	return NULL;
}

void posix_free_signal_desc(struct xseg *xseg, void *data, void *sd)
{
	return;
}

static struct xseg_peer xseg_peer_posix = {
	/* xseg signal operations */
	{
		.init_signal_desc   = posix_init_signal_desc,
		.quit_signal_desc   = posix_quit_signal_desc,
		.alloc_data         = posix_alloc_data,
		.free_data          = posix_free_data,
		.alloc_signal_desc  = posix_alloc_signal_desc,
		.free_signal_desc   = posix_free_signal_desc,
		.local_signal_init  = posix_local_signal_init,
		.local_signal_quit  = posix_local_signal_quit,
		.remote_signal_init = posix_remote_signal_init,
		.remote_signal_quit = posix_remote_signal_quit,
		.prepare_wait	    = posix_prepare_wait,
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

static int posix_init(void)
{
	int r;

	XSEGLOG("registering xseg types");

	r = xseg_register_peer(&xseg_peer_posix);

	return r;
}

static int posix_quit(void)
{
	xseg_unregister_peer(xseg_peer_posix.name);
	return 0;
}

/* *************************** */
/* ** Module Initialization ** */
/* *************************** */

static int __init xseg_posix_init(void)
{
	int ret = -ENOSYS;

	ret = posix_init();
	if (ret)
		goto out;

	XSEGLOG("initialization complete");
out:
	return ret;
}

static void __exit xseg_posix_exit(void)
{
	posix_quit();
}

module_init(xseg_posix_init);
module_exit(xseg_posix_exit);
