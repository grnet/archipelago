#ifndef _SYS_DOMAIN_H
#define _SYS_DOMAIN_H

extern char __xseg_errbuf[4096];
void __xseg_log(const char *msg);
extern int (*xseg_snprintf)(char *str, size_t size, const char *format, ...);

struct log_ctx;
enum log_level { E = 0, W = 1, I = 2, D = 3};
extern int (*init_logctx)(struct log_ctx *lc, char *peer_name, enum log_level log_level, char *logfile);
void __xseg_log2(struct log_ctx *lc, enum log_level level, char *fmt, ...);

void xseg_printtrace(void);
#endif
