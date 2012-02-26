#ifndef _XSEG_DOMAIN_H
#define _XSEG_DOMAIN_H

/* domain-provided functions */
void __lock_domain(void);
void __unlock_domain(void);
void __load_plugin(const char *name);
int __xseg_preinit(void);
uint64_t __get_id(void);

#endif
