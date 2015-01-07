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

#include <stdexcept>
#include <cstdio>
#include <cstdlib>
#include <cerrno>

#include <unistd.h>
#include "poold/epoll.hh"

namespace archipelago {

using std::runtime_error;

Epoll::Epoll()
{
    epollfd = epoll_create1(0);
    if (epollfd < 0) {
        throw runtime_error("Cannot create epoll file descriptor.");
    }
}

Epoll::~Epoll()
{
    ::close(epollfd);
}

bool Epoll::add_fd(int fd, uint32_t events)
{
    struct epoll_event ev;
    ev.data.fd = fd;
    ev.events = events;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
        return false;
    }
    return true;
}

bool Epoll::add_socket(Socket& socket, uint32_t events)
{
    if (socket.get_fd() == -1) {
        return false;
    }

    if (!add_fd(socket.get_fd(), events)) {
        return false;
    }
    socket.events = events;
    return true;
}

bool Epoll::rm_fd(int fd, uint32_t events)
{
    struct epoll_event ev;
    ev.data.fd = fd;
    ev.events = events;
    if (epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, &ev) == -1) {
        return false;
    }
    return true;
}

bool Epoll::rm_socket(Socket& socket)
{
    if (socket.get_fd() == -1) {
        return false;
    }

    if (!rm_fd(socket.get_fd(), socket.events)) {
        return false;
    }
    socket.events = 0;
    return true;
}

bool Epoll::set_fd_pollin(int fd, uint32_t events)
{
    struct epoll_event ev;
    ev.data.fd = fd;
    ev.events = events | EPOLLIN;
    if (epoll_ctl(epollfd, EPOLL_CTL_MOD, fd, &ev) == -1) {
        return false;
    }
    return true;
}

bool Epoll::reset_fd_pollin(int fd, uint32_t events)
{
    struct epoll_event ev;
    ev.data.fd = fd;
    ev.events = events & ~((short) EPOLLIN);
    if (epoll_ctl(epollfd, EPOLL_CTL_MOD, fd, &ev) == -1) {
        return false;
    }
    return true;
}

bool Epoll::set_fd_pollout(int fd, uint32_t events)
{
    struct epoll_event ev;
    ev.data.fd = fd;
    ev.events  = events | EPOLLOUT;
    if (epoll_ctl(epollfd, EPOLL_CTL_MOD, fd, &ev) == -1) {
        perror("epoll_ctl: fd");
        return false;
    }
    return true;
}

bool Epoll::reset_fd_pollout(int fd, uint32_t events)
{
    struct epoll_event ev;
    ev.data.fd = fd;
    ev.events = events & ~((short) EPOLLOUT);
    if (epoll_ctl(epollfd, EPOLL_CTL_MOD, fd, &ev) == -1) {
        perror("epoll_ctl: fd");
        return false;
    }
    return true;
}

bool Epoll::set_socket_pollin(Socket& socket)
{

    if (!set_fd_pollin(socket.get_fd(), socket.events)) {
        return false;
    }
    socket.events |= EPOLLIN;
    return true;
}

bool Epoll::reset_socket_pollin(Socket& socket)
{
    if (!reset_fd_pollin(socket.get_fd(), socket.events)) {
        return false;
    }
    socket.events &= ~((short) EPOLLIN);
    return true;
}

bool Epoll::set_socket_pollout(Socket& socket)
{
    if (!set_fd_pollout(socket.get_fd(), socket.events)) {
        return false;
    }
    socket.events |= EPOLLOUT;
    return true;
}

bool Epoll::reset_socket_pollout(Socket& socket)
{
    if (!reset_fd_pollout(socket.get_fd(), socket.events)) {
        return false;
    }
    socket.events &= ~((short) EPOLLOUT);
    return true;
}

int Epoll::wait(struct epoll_event *events, int maxevents,
        int timeout)
{
    return epoll_wait(epollfd, events, maxevents, timeout);
}

}
