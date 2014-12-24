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

#include "poold.hh"
#include "system.hh"

using namespace std;

namespace archipelago {

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
        perror("epoll_ctl: fd");
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
        perror("epoll_ctl: fd");
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
        perror("epoll_ctl: fd");
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
        perror("epoll_ctl: fd");
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
    int nfds = epoll_wait(epollfd, events, maxevents, timeout);
    if (nfds == -1 && errno != EINTR) {
        perror("epoll_wait");
        exit(EXIT_FAILURE);
    }
    return nfds;
}

bool SigHandler::bExitSignal = false;

SigHandler::SigHandler() {}

SigHandler::~SigHandler() {}

bool SigHandler::gotExitSignal()
{
    return bExitSignal;
}

void SigHandler::setExitSignal(bool flag)
{
    bExitSignal = flag;
}

void SigHandler::exitSignalHandler(int ignored)
{
    SigHandler::bExitSignal = true;
}

void SigHandler::setupSignalHandlers()
{
    if (signal((int) SIGINT, SigHandler::exitSignalHandler) == SIG_ERR) {
        throw SigException("Cannot setup SIGINT signal handler");
    }
    if (signal((int) SIGQUIT, SigHandler::exitSignalHandler) == SIG_ERR) {
        throw SigException("Cannot setup SIGQUIT signal handler");
    }
}

Poold::Poold(const int& startrange, const int& endrange,
        const string& uendpoint)
    : Logger("logging.conf", "Poold")
{
    initialize(startrange, endrange, uendpoint);
}

Poold::Poold(const int& startrange, const int& endrange,
        const string& uendpoint, const string& logconf)
    : Logger(logconf, "Poold")
{
    initialize(startrange, endrange, uendpoint);
}

void Poold::initialize(const int& start, const int& end,
        const string& uendpoint)
{
    bRunning = true;
    endpoint = uendpoint;
    startrange = start;
    endrange  = end;
    for (int i = startrange; i < endrange + 1; i++) {
        port_pool.push_back(i);
    }
    pthread_mutex_init(&mutex, NULL);
}

Socket *Poold::find_socket(int fd)
{
    map<Socket*, int>::iterator it;
    for (it = socket_connection_state.begin();
            it!= socket_connection_state.end(); ++it) {
        if (it->first->get_fd() == fd) {
            break;
        }
    }
    return it->first;
}

void Poold::set_socket_pollin(Socket& socket)
{
    if (!epoll.reset_socket_pollout(socket)) {
        logerror("epoll.reset_socket_pollout error");
    }
    if (!epoll.set_socket_pollin(socket)) {
        logerror("epoll.set_socket_pollin error");
    }
}

void Poold::set_socket_pollout(Socket& socket)
{
    if (!epoll.reset_socket_pollin(socket)) {
        logerror("epoll.reset_socket_pollin error");
    }
    if (!epoll.set_socket_pollout(socket)) {
        logerror("epoll.set_socket_pollout error");
    }
}

void Poold::server() {
    if (!srvsock.create()) {
        logfatal("Could not create server socket. Aborting...");
        exit(EXIT_FAILURE);
    }

    if (!srvsock.bind(endpoint)) {
        logfatal("Could not bind to endpoint. Aborting...");
        exit(EXIT_FAILURE);
    }

    if (!srvsock.listen(5)) {
        logfatal("Could not listen to socket. Aborting...");
        exit(EXIT_FAILURE);
    }

    if (!epoll.add_socket(srvsock, EPOLLIN)) {
        logfatal("Could not add server socket for polling (epoll). Aborting...");
        exit(EXIT_FAILURE);
    }

    evfd = eventfd(0, EFD_NONBLOCK);
    if (!epoll.add_fd(evfd, EPOLLIN | EPOLLET)) {
        logfatal("Could not add eventfd file descriptor for polling (epoll). Aborting...");
        exit(EXIT_FAILURE);
    }

    socket_connection_state[&srvsock] = NONE;
}

void Poold::create_new_connection(Socket& socket) {
    if (socket.get_fd() == -1) {
        logfatal("Socket file descriptor error. Aborting...");
        exit(EXIT_FAILURE);
    }
    socket.setnonblocking(true);
    epoll.add_socket(socket, EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR);
    socket_connection_state[&socket] = NONE;
    logdebug("Accepted new connection");
}

void Poold::clear_connection(Socket& socket) {
    epoll.rm_socket(socket);
    list<int>::iterator i;
    list<int> L = socket_connection_ports[&socket];
    logdebug("Clearing connection");

    pthread_mutex_lock(&mutex);
    for ( i = L.begin(); i != L.end(); i++) {
        port_pool.push_front(*i);
    }

    socket_connection_state.erase(&socket);
    socket_connection_ports[&socket].clear();
    socket_connection_ports.erase(&socket);
    pthread_mutex_unlock(&mutex);
}

poolmsg_t *Poold::recv_msg(const Socket& socket) {
    unsigned int buffer[2];
    poolmsg_t *msg;

    logdebug("Receiving new message.");
    if (!socket.read(&buffer, sizeof(buffer))) {
        logerror("Socket read error.");
    }
    msg = reinterpret_cast<poolmsg_t *>(calloc(1, sizeof(poolmsg_t)));
    msg->type = ntohl(buffer[0]);
    msg->port = ntohl(buffer[1]);
    return msg;
}

int Poold::send_msg(const Socket& socket, int port) {
    const int buffer[1] = {port};
    logdebug("Sending port to client.");

    int n = socket.write(buffer, sizeof(buffer));
    if (n < 0) {
        logerror("Socket write error.");
    }
    return n;
}

int Poold::get_new_port(Socket& socket) {
    if (port_pool.empty()) {
        logdebug("Port pool is empty.");
        return -1;
    }
    pthread_mutex_lock(&mutex);
    int port = port_pool.front();
    port_pool.pop_front();
    socket_connection_ports[&socket].push_front(port);
    pthread_mutex_unlock(&mutex);
    return port;
}

void Poold::handle_request(Socket& socket, poolmsg_t *msg)
{
    list<int>::iterator i;
    list<int> L = socket_connection_ports[&socket];
    logdebug("Handle request.");

    if (msg->type == GET_PORT) {
        socket_connection_state[&socket] = REPLY_PORT;
    } else if (msg->type == LEAVE_PORT) {
        if (find(L.begin(), L.end(), msg->port) != L.end()) {
            socket_connection_ports[&socket].remove(msg->port);
            pthread_mutex_lock(&mutex);
            port_pool.push_front(msg->port);
            pthread_mutex_unlock(&mutex);
            socket_connection_state[&socket] = REPLY_LEAVE_PORT_SUCCESS;
        } else {
            socket_connection_state[&socket] = REPLY_LEAVE_PORT_FAIL;
        }
    } else if (msg->type == LEAVE_ALL_PORTS) {
        for ( i = L.begin(); i != L.end(); i++) {
            socket_connection_ports[&socket].remove(*i);
            pthread_mutex_lock(&mutex);
            port_pool.push_front(*i);
            pthread_mutex_unlock(&mutex);
        }
        socket_connection_state[&socket] = REPLY_LEAVE_ALL_PORTS;
    }
    Poold::set_socket_pollout(socket);
    free(msg);
}

void Poold::serve_forever() {
    poolmsg_t *msg;
    while (Poold::bRunning) {
        int nfds = epoll.wait(events, 20, -1);
        if (!Poold::bRunning) {
            break; //Cleanup
        }

        for (int n = 0; n < nfds; n++) {
            int epfd = events[n].data.fd;
            if (epfd == srvsock.get_fd()) {
                Socket *clientsock = new Socket();
                if (!srvsock.accept(*clientsock)) {
                    logfatal("Could not accept socket. Aborting...");
                    exit(EXIT_FAILURE);
                }
                Poold::create_new_connection(*clientsock);
            } else if (epfd == evfd) {
                /* Exit loop */
                return;
            } else if (events[n].events & EPOLLRDHUP ||
                            events[n].events & EPOLLHUP ||
                            events[n].events & EPOLLERR) {
                Socket *clientsock = Poold::find_socket(epfd);
                Poold::clear_connection(*clientsock);
                delete clientsock;
                ::close(epfd);
            } else if (events[n].events & EPOLLIN) {
                Socket *clientsock = Poold::find_socket(epfd);
                msg = Poold::recv_msg(*clientsock);
                Poold::handle_request(*clientsock, msg);
            } else if (events[n].events & EPOLLOUT) {
                Socket *clientsock = Poold::find_socket(epfd);
                switch (socket_connection_state[clientsock]) {
                case REPLY_PORT:
                    Poold::send_msg(*clientsock, get_new_port(*clientsock));
                    break;
                case REPLY_LEAVE_PORT_SUCCESS:
                    Poold::send_msg(*clientsock, 1);
                    break;
                case REPLY_LEAVE_PORT_FAIL:
                    Poold::send_msg(*clientsock, 0);
                    break;
                case REPLY_LEAVE_ALL_PORTS:
                    Poold::send_msg(*clientsock, 1);
                    break;
                default:
                    Poold::send_msg(*clientsock, 0);
                    logerror("Unknown state.");
                }
                socket_connection_state[clientsock] = NONE;
                Poold::set_socket_pollin(*clientsock);
            }
        }
    }
}

void Poold::run() {
    int rv = pthread_create(&th, NULL, poold_helper, static_cast<void*>(this));
    if (rv != 0) {
        logfatal("Error in thread creation. Aborting...");
        exit(EXIT_FAILURE);
    }
}

void Poold::close() {
    Poold::bRunning = false;
    eventfd_write(evfd, 1);
    pthread_join(th, NULL);
    loginfo("Cleanup.");
    unlink(endpoint.c_str());
}

}

void print_usage(int argc, char **argv, string pidfile, string socketpath)
{
    std::cout << "Usage: " << argv[0] << " [options]\n"
        "\nOptions:\n"
        "-h\tprint this help message\n"
        "-s\tset start of the pool range (default: 1)\n"
        "-e\tset end of the pool range (default: 100)\n"
        "-p\tset socket path (default: '"<< socketpath << "')\n"
        "-c\tset logging configuration file (default: none)\n"
        "-i\tset pidfile (default: '"<< pidfile << "')\n"
        "-u\tset real EUID\n"
        "-g\tset real EGID\n"
        "-m\tset umask (default: 0007)\n"
        "-d\tdaemonize (default: no)\n"
        "\n";
}

int main(int argc, char **argv) {

    int option = 0;
    int uid = -1;
    int gid = -1;
    bool daemonize = false;
    int startpoolrange = 1;
    int endpoolrange = 100;
    mode_t mask = 0007;
    sigset_t tmpsigset;
#ifdef POOLD_SOCKET_PATH
    string socketpath (POOLD_SOCKET_PATH);
#else
    string socketpath ("poold.socket");
#endif
    string logconffile;
#ifdef POOLD_PIDFILE
    string pidfile (POOLD_PIDFILE);
#else
    string pidfile ("poold.pid");
#endif


    while ((option = getopt(argc, argv, "hds:e:p:u:g:i:m:c:")) != -1) {
        switch (option) {
        case 's':
            startpoolrange= atoi(optarg);
            break;
        case 'e':
            endpoolrange= atoi(optarg);
            break;
        case 'p':
            socketpath.assign(optarg, strlen(optarg));
            break;
        case 'c':
            logconffile.assign(optarg, strlen(optarg));
            break;
        case 'd':
            daemonize = true;
            break;
        case 'u':
            uid = atoi(optarg);
            break;
        case 'g':
            gid = atoi(optarg);
            break;
        case 'i':
            pidfile = pidfile.assign(optarg, strlen(optarg));
            break;
        case 'm':
            mask = atol(optarg);
            break;
        case 'h':
            print_usage(argc, argv, pidfile, socketpath);
            exit(EXIT_SUCCESS);
        default:
            print_usage(argc, argv, pidfile, socketpath);
            exit(EXIT_FAILURE);
        }
    }

    archipelago::System system = archipelago::System(logconffile);

    if (system.set_system(daemonize, uid, gid, mask, pidfile) < 0) {
        system.logerror("Cannot set application settings. Aborting...");
        exit(EXIT_FAILURE);
    }

    archipelago::Poold pool = archipelago::Poold(startpoolrange, endpoolrange,
            socketpath, logconffile);
    pool.server();
    pool.loginfo("Running server.");
    pool.run();

    try {
        archipelago::SigHandler sigh;
        sigh.setupSignalHandlers();
        pool.loginfo("Setting up signal handlers.");

        (void) sigemptyset(&tmpsigset);
        while (!sigh.gotExitSignal()) {
            sigsuspend(&tmpsigset);
        }
    } catch (archipelago::SigException& e) {
        pool.logfatal("Signal Handler Exception: " + std::string(e.what()));
    }
    pool.close();
    system.remove_pid(pidfile);
    pool.loginfo("Closing server.");
    return 0;
}
