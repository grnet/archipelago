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

#include "logger.hh"
#include <log4cplus/configurator.h>

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

}
