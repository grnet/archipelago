/*
 * Copyright (C) 2014 GRNET S.A.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <cstdio>
#include <cstdarg>
#include <log4cplus/configurator.h>
#include "logger.hh"

namespace archipelago {

using std::runtime_error;
using namespace log4cplus;

Logger::Logger(const std::string& conffile, const std::string& instance)
{
    if (conffile.empty()) {
        BasicConfigurator config;
        config.configure();
    } else {
        PropertyConfigurator::doConfigure(conffile);
    }
    logger = getInstance(instance);
}

void Logger::logGeneric(int loglevel, const std::string& msg)
{
    switch (loglevel) {
    case FATAL_LOG_LEVEL:
        if (logger.isEnabledFor(FATAL_LOG_LEVEL)) {
            LOG4CPLUS_FATAL(logger, msg);
        }
        break;
    case ERROR_LOG_LEVEL:
        if (logger.isEnabledFor(ERROR_LOG_LEVEL)) {
            LOG4CPLUS_ERROR(logger, msg);
        }
        break;
    case INFO_LOG_LEVEL:
        if (logger.isEnabledFor(INFO_LOG_LEVEL)) {
            LOG4CPLUS_INFO(logger, msg);
        }
        break;
    case DEBUG_LOG_LEVEL:
        if (logger.isEnabledFor(DEBUG_LOG_LEVEL)) {
            LOG4CPLUS_DEBUG(logger, msg);
        }
        break;
    case WARN_LOG_LEVEL:
        if (logger.isEnabledFor(WARN_LOG_LEVEL)) {
            LOG4CPLUS_WARN(logger, msg);
        }
        break;
    case TRACE_LOG_LEVEL:
        if (logger.isEnabledFor(TRACE_LOG_LEVEL)) {
            LOG4CPLUS_TRACE(logger, msg);
        }
        break;
    default:
        throw runtime_error("Unknown loglevel.");
    }
}

std::string Logger::toString(const char *fmt, va_list ap)
{
    va_list args;
    va_copy(args, ap);
    size_t size = ::vsnprintf(NULL, 0, fmt, args);
    std::string buffer;
    buffer.reserve(size + 1);
    buffer.resize(size);
    va_copy(args, ap);
    ::vsnprintf(&buffer[0], size + 1, fmt, args);
    return buffer;
}

void Logger::logerror(const std::string& msg)
{
    logGeneric(ERROR_LOG_LEVEL, msg);
}

void Logger::logfatal(const std::string& msg)
{
    logGeneric(FATAL_LOG_LEVEL, msg);
}

void Logger::loginfo(const std::string& msg)
{
    logGeneric(INFO_LOG_LEVEL, msg);
}

void Logger::logdebug(const std::string& msg)
{
    logGeneric(DEBUG_LOG_LEVEL, msg);
}

void Logger::logwarn(const std::string& msg)
{
    logGeneric(WARN_LOG_LEVEL, msg);
}

void Logger::logtrace(const std::string& msg)
{
    logGeneric(TRACE_LOG_LEVEL, msg);
}

void Logger::vflogerror(const char *msg, va_list ap)
{
    logerror(toString(msg, ap));
}

void Logger::vflogfatal(const char *msg, va_list ap)
{
    logfatal(toString(msg, ap));
}

void Logger::vfloginfo(const char *msg, va_list ap)
{
    loginfo(toString(msg, ap));
}

void Logger::vflogdebug(const char *msg, va_list ap)
{
    logdebug(toString(msg, ap));
}

void Logger::vflogwarn(const char *msg, va_list ap)
{
    logwarn(toString(msg, ap));
}

void Logger::vflogtrace(const char *msg, va_list ap)
{
    logtrace(toString(msg, ap));
}

void Logger::flogerror(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    vflogerror(msg, args);
    va_end(args);
}

void Logger::flogfatal(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    vflogfatal(msg, args);
    va_end(args);
}

void Logger::floginfo(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    vfloginfo(msg, args);
    va_end(args);
}

void Logger::flogdebug(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    vflogdebug(msg, args);
    va_end(args);
}

void Logger::flogwarn(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    vflogwarn(msg, args);
    va_end(args);
}

void Logger::flogtrace(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    vflogtrace(msg, args);
    va_end(args);
}

}
