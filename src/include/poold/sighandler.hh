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

#ifndef SIGHANDLER_HH
#define SIGHANDLER_HH

#include <iostream>
#include <stdexcept>

#include <signal.h>

namespace archipelago {

using std::runtime_error;

class SigException: public std::runtime_error {
private:
    std::string what_;
public:
    explicit SigException(const std::string& msg)
     : runtime_error(msg), what_(msg) {}

    virtual const char* what() const throw()
    {return what_.c_str();}
    virtual ~SigException() throw() {}
};

class SigHandler {
protected:
    static bool bExitSignal;
public:
    SigHandler();
    ~SigHandler();

    static bool gotExitSignal();
    static void setExitSignal(bool flag);
    void setupSignalHandlers();
    static void exitSignalHandler(int ignored);
};

}

#endif
