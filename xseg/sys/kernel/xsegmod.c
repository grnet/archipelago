#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/module.h>

#include <sys/domain.h>
#include <xq/domain.h>
#include <xseg/domain.h>

int (*xseg_snprintf)(char *str, size_t size, const char *format, ...) = snprintf;
EXPORT_SYMBOL(xseg_snprintf);

char __xseg_errbuf[4096];
EXPORT_SYMBOL(__xseg_errbuf);

static spinlock_t __lock;

void __lock_domain(void)
{
	spin_lock_irq(&__lock);
}

void __unlock_domain(void)
{
	spin_unlock_irq(&__lock);
}

void __load_plugin(const char *name)
{
	return;
}

uint64_t __get_id(void)
{
	return (uint64_t)1;
}

int __xseg_preinit(void)
{
	return 0;
}

void __xseg_log(const char *msg)
{
	(void)printk(KERN_INFO "%s\n", msg);
}
EXPORT_SYMBOL(__xseg_log);

void *xq_malloc(unsigned long size)
{
	return kmalloc(size, GFP_KERNEL);
}

void xq_mfree(void *ptr)
{
	return kfree(ptr);
}

static int __init xsegmod_init(void)
{
	printk(KERN_INFO "xseg loaded");
	return 0;
}

static void __exit xsegmod_exit(void)
{
	printk(KERN_INFO "xseg unloaded");
	return;
}

module_init(xsegmod_init);
module_exit(xsegmod_exit);

MODULE_DESCRIPTION("xseg");
MODULE_AUTHOR("XSEG");
MODULE_LICENSE("GPL");

