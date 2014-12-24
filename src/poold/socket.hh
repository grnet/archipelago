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

#ifndef SOCKET_HH
#define SOCKET_HH

#include <iostream>
#include <sys/un.h>

namespace archipelago {

class Socket {
private:
    int msockfd;
    sockaddr_un maddr;
public:
    Socket();
    virtual ~Socket();

    uint32_t events;
    bool create();
    bool bind(const std::string endpoint);
    bool listen(int backlog) const;
    bool accept(Socket&) const;

    bool write(const void *buffer, const size_t size) const;
    int read(void *buffer, size_t size) const;

    const void setnonblocking(const bool flag);
    const bool is_valid() const {return msockfd != -1;}
    const int& get_fd() const {return msockfd;}

    bool operator <(const Socket& other) const;
    bool operator >(const Socket& other) const;
    bool operator ==(const Socket& other) const;
};

}

#endif
