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

#ifndef LOGGER_HH
#define LOGGER_HH

#include <cstdio>
#include <cstdarg>
#include <log4cplus/configurator.h>
#include <log4cplus/logger.h>

namespace archipelago {

using std::runtime_error;
using namespace log4cplus;

class Logger: public log4cplus::Logger {
public:
    Logger(const std::string& conffile, const std::string& instance)
    {
        if (conffile.empty()) {
            BasicConfigurator config;
            config.configure();
        } else {
            PropertyConfigurator::doConfigure(conffile);
        }
        logger = getInstance(instance);
    }

    void logerror(const std::string& msg);
    void logfatal(const std::string& msg);
    void loginfo(const std::string& msg);
    void logdebug(const std::string& msg);
    void logwarn(const std::string& msg);
    void logtrace(const std::string& msg);

    void flogerror(const char *msg, ...);
    void flogfatal(const char *msg, ...);
    void floginfo(const char *msg, ...);
    void flogdebug(const char *msg, ...);
    void flogwarn(const char *msg, ...);
    void flogtrace(const char *msg, ...);

    void vflogerror(const char *msg, va_list ap);
    void vflogfatal(const char *msg, va_list ap);
    void vfloginfo(const char *msg, va_list ap);
    void vflogdebug(const char *msg, va_list ap);
    void vflogwarn(const char *msg, va_list ap);
    void vflogtrace(const char *msg, va_list ap);

private:
    log4cplus::Logger logger;
    std::string toString(const char *fmt, va_list ap);
};

inline std::string Logger::toString(const char *fmt, va_list ap)
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

inline void Logger::logerror(const std::string& msg)
{
    if (logger.isEnabledFor(ERROR_LOG_LEVEL)) {
        LOG4CPLUS_ERROR(logger, msg);
    }
}

inline void Logger::logfatal(const std::string& msg)
{
    if (logger.isEnabledFor(FATAL_LOG_LEVEL)) {
        LOG4CPLUS_FATAL(logger, msg);
    }
}

inline void Logger::loginfo(const std::string& msg)
{
    if (logger.isEnabledFor(INFO_LOG_LEVEL)) {
        LOG4CPLUS_INFO(logger, msg);
    }
}

inline void Logger::logdebug(const std::string& msg)
{
    if (logger.isEnabledFor(DEBUG_LOG_LEVEL)) {
        LOG4CPLUS_DEBUG(logger, msg);
    }
}

inline void Logger::logwarn(const std::string& msg)
{
    if (logger.isEnabledFor(WARN_LOG_LEVEL)) {
        LOG4CPLUS_WARN(logger, msg);
    }
}

inline void Logger::logtrace(const std::string& msg)
{
    if (logger.isEnabledFor(TRACE_LOG_LEVEL)) {
        LOG4CPLUS_TRACE(logger, msg);
    }
}

inline void Logger::vflogerror(const char *msg, va_list ap)
{
    logerror(toString(msg, ap));
}

inline void Logger::vflogfatal(const char *msg, va_list ap)
{
    logfatal(toString(msg, ap));
}

inline void Logger::vfloginfo(const char *msg, va_list ap)
{
    loginfo(toString(msg, ap));
}

inline void Logger::vflogdebug(const char *msg, va_list ap)
{
    logdebug(toString(msg, ap));
}

inline void Logger::vflogwarn(const char *msg, va_list ap)
{
    logwarn(toString(msg, ap));
}

inline void Logger::vflogtrace(const char *msg, va_list ap)
{
    logtrace(toString(msg, ap));
}

inline void Logger::flogerror(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    vflogerror(msg, args);
    va_end(args);
}

inline void Logger::flogfatal(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    vflogfatal(msg, args);
    va_end(args);
}

inline void Logger::floginfo(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    vfloginfo(msg, args);
    va_end(args);
}

inline void Logger::flogdebug(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    vflogdebug(msg, args);
    va_end(args);
}

inline void Logger::flogwarn(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    vflogwarn(msg, args);
    va_end(args);
}

inline void Logger::flogtrace(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    vflogtrace(msg, args);
    va_end(args);
}

}

#endif
