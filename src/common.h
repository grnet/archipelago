/*
Copyright (C) 2010-2014 GRNET S.A.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * vkoukis.h
 */

#define _GNU_SOURCE

#ifndef _COMMON_H
#define _COMMON_H

#ifdef DEBUG
#define p_debug(str, ...)	\
	perr(PD, 0, "%s: " str, __func__ , __VA_ARGS__)
#else
#define p_debug(str, ...)	do {const char *s = __VA_ARGS__} while (0)
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

#define __fmt2(fmt0, arg0, arg1, fmt1, ...) fmt0 fmt1 "%s", arg0, arg1, __VA_ARGS__

#ifdef DEBUG
#define perr(type, want_errno, ...) \
	perr_func(type, want_errno, \
		__fmt2("%s: %d: ", __func__, __LINE__, __VA_ARGS__, ""))
#else
#define perr(type, want_errno, ...) \
	do {                        \
		if (type > PD)      \
		perr_func(type, want_errno, \
			__fmt2("%s: %d: ", __func__, __LINE__, __VA_ARGS__, "")); \
	} while (0)
#endif

/* String manipulation */
size_t strlcpy(char *dst, const char *src, size_t siz);
size_t strlcat(char *dst, const char *src, size_t siz);

#endif	/* _COMMON_H */
