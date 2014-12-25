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

#include "logger.hh"
#include "socket.hh"
#include "epoll.hh"

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

class Poold: public Logger {
private:
    int evfd;
    struct epoll_event events[20];
    std::string endpoint;
    int startrange;
    int endrange;
    std::list<int> port_pool;
    std::map<Socket*, int> socket_connection_state;
    std::map<Socket*, std::list<int> > socket_connection_ports;
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
            const std::string& uendpoint);
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
            const std::string& uendpoint);
    Poold(const int& startrange, const int& endrange,
            const std::string& endpoint, const std::string& logconf);
    void server();
    void run();
    void close();
};

}

#endif /* POOLD_HH */
