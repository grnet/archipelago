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

#ifndef EPOLL_HH
#define EPOLL_HH

#include <sys/epoll.h>
#include "socket.hh"

namespace archipelago {

class Epoll {
private:
    int epollfd;
public:
    Epoll();
    ~Epoll();

    bool add_socket(Socket& socket, uint32_t events);
    bool add_fd(int fd, uint32_t events);

    bool rm_socket(Socket& socket);
    bool rm_fd(int fd, uint32_t events);

    bool set_socket_pollin(Socket& socket);
    bool reset_socket_pollin(Socket& socket);

    bool set_socket_pollout(Socket& socket);
    bool reset_socket_pollout(Socket& socket);

    bool set_fd_pollin(int fd, uint32_t events);
    bool reset_fd_pollin(int fd, uint32_t events);

    bool set_fd_pollout(int fd, uint32_t events);
    bool reset_fd_pollout(int fd, uint32_t events);

    int wait(struct epoll_event *events, int maxevents, int timeout);

    const int& get_epollfd() const {return epollfd;}
};

}

#endif
