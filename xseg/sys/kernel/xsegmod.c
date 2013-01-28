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


int __renew_logctx(struct log_ctx *lc, char *peer_name,
                enum log_level log_level, char *logfile, uint32_t flags)
{
	return 0;
}

int (*renew_logctx)(struct log_ctx *lc, char *peer_name,
        enum log_level log_level, char *logfile, uint32_t flags) = __renew_logctx;

int __init_logctx(struct log_ctx *lc, char *peer_name,
		enum log_level log_level, char *logfile, uint32_t flags)
{
	if (peer_name){
		strncpy(lc->peer_name, peer_name, MAX_PEER_NAME);
		lc->peer_name[MAX_PEER_NAME -1] = 0;
	}
	else {
		return -1;
	}

	lc->log_level = log_level;
	lc->logfile = NULL;
	return 0;
}
int (*init_logctx)(struct log_ctx *lc, char *peer_name,
	enum log_level log_level, char *logfile, uint32_t flags) = __init_logctx;

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
MODULE_LICENSE("BSD");

