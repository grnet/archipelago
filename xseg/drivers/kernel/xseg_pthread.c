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

MODULE_DESCRIPTION("xseg_pthread");
MODULE_AUTHOR("XSEG");
MODULE_LICENSE("GPL");

static int pthread_signal_init(void)
{
	return 0;
}

static void pthread_signal_quit(void)
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

static int pthread_wait_signal(struct xseg *xseg, uint32_t timeout)
{
	return -1;
}

static int pthread_signal(struct xseg *xseg, uint32_t portno)
{
	struct pid *pid;
	struct task_struct *task;
	int ret = -ENOENT;
	xpool_data data;
	xpool_index idx;
	struct xseg_port *port = xseg_get_port(xseg, portno);
	if (!port) 
		return -1;

	rcu_read_lock();
	/* XXX Security: xseg peers can kill anyone */
	idx = xpool_peek(&port->waiters, &data, portno); //FIXME portno is not the caller but the callee
	if (idx == NoIndex)
		/* no waiters */
		goto out;

	pid = find_vpid((pid_t) data);
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

static struct xseg_peer xseg_peer_pthread = {
	/* xseg signal operations */
	{
		.signal_init = pthread_signal_init,
		.signal_quit = pthread_signal_quit,
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
