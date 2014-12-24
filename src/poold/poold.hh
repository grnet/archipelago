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

#ifndef POOLD_HH
#define POOLD_HH

#include <cstdio>
#include <cstring>
#include <iostream>
#include <list>
#include <map>
#include <utility>
#include <algorithm>
#include <cstdlib>
#include <stdexcept>
#include <functional>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <pthread.h>
#include <arpa/inet.h>

#include "logger.hh"
#include "socket.hh"

/*
 * message structure
 */
typedef struct poolmsg {
    int type;
    int port;
} poolmsg_t;

/*
 * archipelago namespace
 */
namespace archipelago {

using std::runtime_error;
using namespace std;


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

class SigException: public std::runtime_error {
private:
    string what_;
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

class Poold: public Logger {
private:
    int evfd;
    struct epoll_event events[20];
    string endpoint;
    int startrange;
    int endrange;
    list<int> port_pool;
    map<Socket*, int> socket_connection_state;
    map<Socket*, list<int> > socket_connection_ports;
    bool bRunning;
    pthread_mutex_t mutex;
    pthread_t th;
    Epoll epoll;
    Socket srvsock;
protected:
    enum _poolmsgtype {
        GET_PORT,
        LEAVE_PORT,
        LEAVE_ALL_PORTS,
    } PoolMsgType;

    enum _connstate {
        NONE,
        REPLY_PORT,
        REPLY_LEAVE_PORT_SUCCESS,
        REPLY_LEAVE_PORT_FAIL,
        REPLY_LEAVE_ALL_PORTS,
    } ConnectionState;
private:
    void initialize(const int& start, const int& end,
            const string& uendpoint);
    void serve_forever();
    void create_new_connection(Socket& socket);
    void clear_connection(Socket& socket);
    void handle_request(Socket& socket, poolmsg_t *msg);
    int get_new_port(Socket& socket);
    poolmsg_t *recv_msg(const Socket& socket);
    int send_msg(const Socket& socket, int port);

    Socket *find_socket(int fd);
    void set_socket_pollin(Socket& socket);
    void set_socket_pollout(Socket& socket);

    static void *poold_helper(void *arg) {
        Poold *pool = static_cast<Poold *>(arg);
        pool->serve_forever();
        return NULL;
    }
public:
    Poold(const int& startrange, const int& endrange,
            const string& uendpoint);
    Poold(const int& startrange, const int& endrange,
            const string& endpoint, const string& logconf);
    void server();
    void run();
    void close();
};

}

#endif /* POOLD_HH */
