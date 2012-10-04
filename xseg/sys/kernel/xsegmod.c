#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/time.h>

#include <sys/domain.h>
#include <sys/util.h>
#include <xtypes/domain.h>
#include <xseg/domain.h>

int (*xseg_snprintf)(char *str, size_t size, const char *format, ...) = snprintf;

char __xseg_errbuf[4096];

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

void *xtypes_malloc(unsigned long size)
{
	return kmalloc(size, GFP_KERNEL);
}

void xtypes_free(void *ptr)
{
	return kfree(ptr);
}

void __get_current_time(struct timeval *tv)
{
	do_gettimeofday(tv);
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

int kernel_init_logctx(struct log_ctx *lc, char *peer_name, enum log_level log_level, char *logfile)
{
	lc->peer_name = peer_name;
	lc->log_level = log_level;
	lc->logfile = NULL;
	return 0;
}
int (*init_logctx)(struct log_ctx *lc, char *peer_name, enum log_level log_level, char *logfile) = kernel_init_logctx;

void __xseg_log2(struct log_ctx *lc, unsigned int level, char *fmt, ...)
{
	va_list ap;
	struct timeval t;
	struct tm broken;
	char buffer[1500];
	char *buf = buffer;
	char *type = NULL, *pn = NULL;

	va_start(ap, fmt);
	switch (level) {
		case E: type = "XSEG[EE]"; break;
		case W: type = "XSEG[WW]"; break;
		case I: type = "XSEG[II]"; break;
		case D: type = "XSEG[DD]"; break;
		default: type = "XSEG[UNKNONW]"; break;
	}
	pn = lc->peer_name;
	if (!pn)
		pn = "Invalid peer name";

	do_gettimeofday(&t);
	time_to_tm(t.tv_sec, 0, &broken);	
	
	buf += sprintf(buf, "%s: %s: ", type, lc->peer_name);
	buf += sprintf(buf, "%d:%d:%d:%ld\n\t", broken.tm_hour, broken.tm_min, 
                         broken.tm_sec, t.tv_usec);
	buf += vsprintf(buf, fmt, ap);
	buf += sprintf(buf, "\n");

	(void)printk(KERN_INFO "%s\n", buffer);
	va_end(ap);

	return;
}

void xseg_printtrace(void)
{
	dump_stack();
}

module_init(xsegmod_init);
module_exit(xsegmod_exit);

MODULE_DESCRIPTION("xseg");
MODULE_AUTHOR("XSEG");
MODULE_LICENSE("GPL");

