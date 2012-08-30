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

MODULE_DESCRIPTION("xseg_posix");
MODULE_AUTHOR("XSEG");
MODULE_LICENSE("GPL");

static int posix_signal_init(void)
{
	return 0;
}

static void posix_signal_quit(void)
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

static int posix_wait_signal(struct xseg *xseg, uint32_t timeout)
{
	return -1;
}

static int posix_signal(struct xseg *xseg, uint32_t portno)
{
	struct pid *pid;
	struct task_struct *task;
	int ret = -ENOENT;
	struct xseg_port *port = xseg_get_port(xseg, portno);
	if (!port) 
		return -1;


	rcu_read_lock();
	/* XXX Security: xseg peers can kill anyone */
	if (!port->waitcue) {
		ret = 0;
		goto out;
	}

	pid = find_vpid((pid_t)port->waitcue);
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

static struct xseg_peer xseg_peer_posix = {
	/* xseg signal operations */
	{
		.signal_init = posix_signal_init,
		.signal_quit = posix_signal_quit,
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
