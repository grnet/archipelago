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

#include <iostream>

using namespace std;

namespace archipelago {
    class Logger;
}

class archipelago::Logger {
    public:
        Logger();

        void logerror(const string& msg);
        void logfatal(const string& msg);
        void loginfo(const string& msg);
        void logdebug(const string& msg);
        void logwarn(const string& msg);
        void logtrace(const string& msg);

    private:
        void logGeneric(int loglevel, const string& msg);
};
