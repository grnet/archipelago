#ifndef _SYS_DOMAIN_H
#define _SYS_DOMAIN_H

extern char __xseg_errbuf[4096];
void __xseg_log(const char *msg);
extern int (*xseg_snprintf)(char *str, size_t size, const char *format, ...);

#endif
