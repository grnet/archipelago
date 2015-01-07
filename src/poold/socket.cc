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

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

#include "poold/socket.hh"

namespace archipelago {

Socket::Socket(): msockfd(-1)
{
    events = 0;
    memset(&maddr, 0, sizeof(maddr));
}

Socket::~Socket()
{
    if (is_valid()) {
        ::close(msockfd);
    }
}

bool Socket::operator <(const Socket& other) const
{
    return this->msockfd < other.msockfd;
}

bool Socket::operator >(const Socket& other) const
{
    return this->msockfd > other.msockfd;
}

bool Socket::operator ==(const Socket& other) const
{
    return this->msockfd == other.msockfd;
}

bool Socket::create()
{
    msockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (!is_valid()) {
        return false;
    }
    return true;
}

bool Socket::bind(const std::string endpoint)
{
    int len;
    if (!is_valid()) {
        return false;
    }
    setnonblocking(true);

    if (access(endpoint.c_str(), F_OK) != -1) {
        unlink(endpoint.c_str());
    }
    maddr.sun_family = AF_UNIX;
    strcpy(maddr.sun_path, endpoint.c_str());
    len = strlen(maddr.sun_path) + sizeof(maddr.sun_family);

    int bind_rv = ::bind(msockfd, (struct sockaddr *)&maddr, len);
    if (bind_rv == -1) {
        return false;
    }
    return true;
}

bool Socket::listen(int backlog=5) const
{
    if (!is_valid()) {
        return false;
    }
    int listen_rv = ::listen(msockfd, backlog);
    if (listen_rv == -1) {
        return false;
    }
    return true;
}

bool Socket::accept(Socket& socket) const
{
    socklen_t addrlen = sizeof(maddr);
    socket.msockfd = ::accept(msockfd, (struct sockaddr *)&maddr, &addrlen);

    if (socket.msockfd <= 0) {
        return false;
    }
    return true;
}

bool Socket::write(const void *buffer, const size_t size) const
{
    int status = ::write(msockfd, buffer, size);
    if (status == -1) {
        return false;
    }
    return true;
}

int Socket::read(void *buffer, size_t size) const
{
    int status = ::read(msockfd, buffer, size);
    if (status <= 0) {
        return 0;
    }
    return status;
}

const void Socket::setnonblocking(const bool flag)
{
    int opts;
    opts = fcntl(msockfd, F_GETFL);
    if (opts < 0) {
        return;
    }

    if (flag) {
        opts = (opts | O_NONBLOCK);
    } else {
        opts = (opts & ~O_NONBLOCK);
    }
    fcntl(msockfd, F_SETFL, opts);
}

}
