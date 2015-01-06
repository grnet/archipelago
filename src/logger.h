/*
Copyright (C) 2015 GRNET S.A.

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
#ifndef __CLOGGER_H
#define __CLOGGER_H

#include <stdarg.h>

typedef void Logger_t;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Initialize a new logger
 * param conffile: log4cplus configuration file
 * param instance: logger instance name
 * return: logger instance on success, or NULL on fail
 */
Logger_t *logger_new(const char *conffile, const char *instance);

/*
 * Destroy logger instance
 * param logger: logger instance
 */
void logger_destroy(Logger_t *logger);

/*
 * Print formatted output message
 * param logger: logger instance
 * param msg: format string
 */
void flogger_error(const Logger_t *logger, const char *msg, ...);
void flogger_fatal(const Logger_t *logger, const char *msg, ...);
void flogger_info(const Logger_t *logger, const char *msg, ...);
void flogger_debug(const Logger_t *logger, const char *msg, ...);
void flogger_warn(const Logger_t *logger, const char *msg, ...);
void flogger_trace(const Logger_t *logger, const char *msg, ...);

/*
 * Print formatted output message
 * param logger: logger instance
 * param msg: format string
 * param ap: variable argument list
 */
void vflogger_error(const Logger_t *logger, const char *msg, va_list ap);
void vflogger_fatal(const Logger_t *logger, const char *msg, va_list ap);
void vflogger_info(const Logger_t *logger, const char *msg, va_list ap);
void vflogger_debug(const Logger_t *logger, const char *msg, va_list ap);
void vflogger_warn(const Logger_t *logger, const char *msg, va_list ap);
void vflogger_trace(const Logger_t *logger, const char *msg, va_list ap);

#ifdef __cplusplus
}
#endif

#endif
