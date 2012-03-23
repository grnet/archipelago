/*
 * vkoukis.h
 */

#define _GNU_SOURCE

#ifndef _COMMON_H
#define _COMMON_H

#ifdef DEBUG
#define p_debug(str, arg...)	\
	perr(PD, 0, "%s: " str, __func__ , ##arg)
#else
#define p_debug(arg...)		do { } while (0)
#endif

#define always_assert(condition) \
	do { \
		if (!(condition)) \
		perr(PFE, 1, "%s:%d: Assertion failed: " # condition, \
				__FILE__, __LINE__); \
	} while (0)

#ifdef DEBUG
#define assert(condition) \
	do { \
		if (!(condition)) \
		perr(PFE, 0, "%s:%d: Assertion failed: " # condition, \
				__FILE__, __LINE__); \
	} while (0)
#else
#define assert(condition)	do { } while (0)
#endif

#define PERR_BUF_SIZE		2048	
#define HOSTNAME_BUF_SIZE	100

/* Compiler-specific stuff */
#define VAR_MAY_BE_UNUSED(x)	((void)(x))

/*
 * Function prototypes and extern definitions
 */

/* Perr fatal error, error, information, warning, debug */
enum perr_type { PFE = 1, PE = 0, PI = -1, PW = -2, PD = -3 };

void init_perr(char *prog_name);
void perr_func(int type, int want_errno, char *fmt, ...)
	__attribute__ ((format (printf, 3, 4)));

/* No inline form of perr can be used, since it is variadic (See gcc manual) */
#ifdef DEBUG
#define perr(type, want_errno, fmt, arg...) \
	perr_func(type, want_errno, "%s: %d: " fmt, \
		 __func__, __LINE__, ##arg)
#else
#define perr(type, want_errno, fmt, arg...) \
	do {                        \
		if (type > PD)      \
		perr_func(type, want_errno, "%s: %d: " fmt, \
			__func__, __LINE__, ##arg); \
	} while (0)
#endif

/* String manipulation */
size_t strlcpy(char *dst, const char *src, size_t siz);
size_t strlcat(char *dst, const char *src, size_t siz);

#endif	/* _COMMON_H */
