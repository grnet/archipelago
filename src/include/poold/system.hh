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

#ifndef SYSTEM_HH
#define SYSTEM_HH

#include "logger.hh"

namespace archipelago {

class System: public Logger {
private:
    int cur_uid;
    int cur_gid;
    char *username;
public:
    System(const std::string& logconffile);

    int set_system(bool daemonize, int uid, int gid, mode_t mask,
            const std::string& pidfile);
    int read_pid(const std::string& pidfile);
    int check_pid(const std::string& pidfile);
    int write_pid(const std::string& pidfile);
    int remove_pid(const std::string& pidfile);
};

}

#endif
