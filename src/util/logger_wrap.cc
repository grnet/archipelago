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

#include <string>
#include <cstdarg>
#include <stdexcept>
#include <exception>
#include "../logger.h"
#include "../poold/logger.hh"

extern "C" {

Logger_t *logger_new(const char *conffile, const char *instance)
{
    archipelago::Logger *lp;
    std::string cfile;
    if (!instance) {
        return NULL;
    }

    if (conffile) {
        cfile.append(conffile);
    }
    std::string cinst(instance);
    try {
        lp = new archipelago::Logger(cfile, cinst);
        return (Logger_t *) lp;
    } catch (std::bad_alloc&) {
        std::clog << "out of memory" << std::endl;
    } catch (std::exception& x) {
        std::clog << "Exception: " << x.what() << std::endl;
    } catch (...) {
        std::clog << "Unexpected unknown error" << std::endl;
    }
    return NULL;
}

void logger_destroy(Logger_t *logger)
{
    if (logger) {
        archipelago::Logger *lp = (archipelago::Logger *)logger;
        delete lp;
    }
}

void flogger_error(const Logger_t *logger, const char *msg, ...)
{
    if (logger) {
        va_list ap;
        archipelago::Logger *lp = (archipelago::Logger *)logger;
        va_start(ap, msg);
        lp->vflogerror(msg, ap);
        va_end(ap);
    }
}

void flogger_fatal(const Logger_t *logger, const char *msg, ...)
{
    if (logger) {
        va_list ap;
        archipelago::Logger *lp = (archipelago::Logger *)logger;
        va_start(ap, msg);
        lp->vflogfatal(msg, ap);
        va_end(ap);
    }
}

void flogger_info(const Logger_t *logger, const char *msg, ...)
{
    if (logger) {
        va_list ap;
        archipelago::Logger *lp = (archipelago::Logger *)logger;
        va_start(ap, msg);
        lp->vfloginfo(msg, ap);
        va_end(ap);
    }
}

void flogger_debug(const Logger_t *logger, const char *msg, ...)
{
    if (logger) {
        va_list ap;
        archipelago::Logger *lp = (archipelago::Logger *)logger;
        va_start(ap, msg);
        lp->vflogdebug(msg, ap);
        va_end(ap);
    }
}

void flogger_warn(const Logger_t *logger, const char *msg, ...)
{
    if (logger) {
        va_list ap;
        archipelago::Logger *lp = (archipelago::Logger *)logger;
        va_start(ap, msg);
        lp->vflogwarn(msg, ap);
        va_end(ap);
    }
}

void flogger_trace(const Logger_t *logger, const char *msg, ...)
{
    if (logger) {
        va_list ap;
        archipelago::Logger *lp = (archipelago::Logger *)logger;
        va_start(ap, msg);
        lp->vflogfatal(msg, ap);
        va_end(ap);
    }
}

void vflogger_error(const Logger_t *logger, const char *msg, va_list ap)
{
    if (logger) {
        archipelago::Logger *lp = (archipelago::Logger *)logger;
        lp->vflogerror(msg, ap);
    }
}

void vflogger_fatal(const Logger_t *logger, const char *msg, va_list ap)
{
    if (logger) {
        archipelago::Logger *lp = (archipelago::Logger *)logger;
        lp->vflogfatal(msg, ap);
    }
}

void vflogger_info(const Logger_t *logger, const char *msg, va_list ap)
{
    if (logger) {
        archipelago::Logger *lp = (archipelago::Logger *)logger;
        lp->vfloginfo(msg, ap);
    }
}

void vflogger_debug(const Logger_t *logger, const char *msg, va_list ap)
{
    if (logger) {
        archipelago::Logger *lp = (archipelago::Logger *)logger;
        lp->vflogdebug(msg, ap);
    }
}

void vflogger_warn(const Logger_t *logger, const char *msg, va_list ap)
{
    if (logger) {
        archipelago::Logger *lp = (archipelago::Logger *)logger;
        lp->vflogwarn(msg, ap);
    }
}

void vflogger_trace(const Logger_t *logger, const char *msg, va_list ap)
{
    if (logger) {
        archipelago::Logger *lp = (archipelago::Logger *)logger;
        lp->vflogfatal(msg, ap);
    }
}

}
