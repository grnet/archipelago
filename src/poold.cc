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
#include <cstdio>
#include <list>
#include <map>
#include <utility>
#include <algorithm>
#include <cstdlib>
#include <stdexcept>
#include <functional>

#include <log4cplus/configurator.h>
#include <log4cplus/logger.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>
#include <sys/eventfd.h>
#include <pthread.h>
#include <pwd.h>
#include <grp.h>

using namespace std;
using namespace log4cplus;

typedef struct poolmsg {
    int type;
    int port;
} poolmsg_t;

namespace archipelago {
    class Logger;
    class System;
    class Socket;
    class Epoll;
    class SigException;
    class SigHandler;
    class Poold;
}

class archipelago::Logger: public log4cplus::Logger {
    public:
        Logger(const string& conffile, const string& instance);

        void logerror(const string& msg);
        void logfatal(const string& msg);
        void loginfo(const string& msg);
        void logdebug(const string& msg);
        void logwarn(const string& msg);
        void logtrace(const string& msg);

    private:
        log4cplus::Logger logger;
        void logGeneric(int loglevel, const string& msg);
};

archipelago::Logger::Logger(const string& conffile, const string& instance)
{
    if (conffile.empty()) {
        BasicConfigurator config;
        config.configure();
    } else {
        PropertyConfigurator::doConfigure(conffile);
    }
    logger = getInstance(instance);
}

void archipelago::Logger::logGeneric(int loglevel, const string& msg)
{
    switch (loglevel) {
    case FATAL_LOG_LEVEL:
        if (logger.isEnabledFor(FATAL_LOG_LEVEL)) {
            LOG4CPLUS_FATAL(logger, msg);
        }
        break;
    case ERROR_LOG_LEVEL:
        if (logger.isEnabledFor(ERROR_LOG_LEVEL)) {
            LOG4CPLUS_ERROR(logger, msg);
        }
        break;
    case INFO_LOG_LEVEL:
        if (logger.isEnabledFor(INFO_LOG_LEVEL)) {
            LOG4CPLUS_INFO(logger, msg);
        }
        break;
    case DEBUG_LOG_LEVEL:
        if (logger.isEnabledFor(DEBUG_LOG_LEVEL)) {
            LOG4CPLUS_DEBUG(logger, msg);
        }
        break;
    case WARN_LOG_LEVEL:
        if (logger.isEnabledFor(WARN_LOG_LEVEL)) {
            LOG4CPLUS_WARN(logger, msg);
        }
        break;
    case TRACE_LOG_LEVEL:
        if (logger.isEnabledFor(TRACE_LOG_LEVEL)) {
            LOG4CPLUS_TRACE(logger, msg);
        }
        break;
    default:
        throw runtime_error("Unknown loglevel.");
    }
}

void archipelago::Logger::logerror(const string& msg)
{
    logGeneric(ERROR_LOG_LEVEL, msg);
}

void archipelago::Logger::logfatal(const string& msg)
{
    logGeneric(FATAL_LOG_LEVEL, msg);
}

void archipelago::Logger::loginfo(const string& msg)
{
    logGeneric(INFO_LOG_LEVEL, msg);
}

void archipelago::Logger::logdebug(const string& msg)
{
    logGeneric(DEBUG_LOG_LEVEL, msg);
}

void archipelago::Logger::logwarn(const string& msg)
{
    logGeneric(WARN_LOG_LEVEL, msg);
}

void archipelago::Logger::logtrace(const string& msg)
{
    logGeneric(TRACE_LOG_LEVEL, msg);
}

class archipelago::System: public Logger {
    private:
        int cur_uid;
        int cur_gid;
        char *username;

    public:
        System(const string& logconffile);

        int set_system(bool daemonize, int uid, int gid, mode_t mask,
                const string& pidfile);
        int read_pid(const string& pidfile);
        int check_pid(const string& pidfile);
        int write_pid(const string& pidfile);
        int remove_pid(const string& pidfile);
};

archipelago::System::System(const string& logconffile)
            : Logger(logconffile, "System")
{
    cur_uid = cur_gid = -1;
}

int archipelago::System::set_system(bool daemonize, int uid, int gid,
        mode_t mask, const string& pidfile)
{
    if (gid != -1) {
        struct group *gr;
        gr = getgrgid(gid);
        if (!gr) {
            logerror("Cannot find group.");
            return -1;
        }
    }

    if (uid != -1) {
        struct passwd *pw;
        pw = getpwuid(uid);
        if (!pw) {
            logerror("Cannot find user.");
            return -1;
        }
        username = pw->pw_name;
        if (gid == -1) {
            gid = pw->pw_gid;
        }
    }

    cur_uid = geteuid();
    cur_gid = getegid();

    if (gid != -1 && cur_gid != gid && setregid(gid, gid)) {
        logerror("Could not set process gid.");
        return -1;
    }

    if (uid != -1) {
        if ((cur_gid != gid || cur_uid != uid) &&initgroups(username, gid)) {
            logerror("Could not initialize groups.");
            return -1;
        }

        if (cur_uid != uid && setreuid(uid, uid)) {
            logerror("Failed to set process uid.");
            return -1;
        }
    }

    mask &= 0777;
    umask(mask);

    if (close(STDIN_FILENO)) {
        logwarn("Could not close stdin.");
    }

    if (daemonize) {
        loginfo("Becoming daemon.");
        if (daemon(0, 1) < 0) {
            logerror("daemon() error.");
            return -1;
        }
        (void) setpgrp();
    }

    if (write_pid(pidfile) == 0) {
        return -1;
    }
    return 0;
}

int archipelago::System::read_pid(const string& pidfile)
{
    FILE *f;
    int pid;

    if (!(f=fopen(pidfile.c_str(), "r"))) {
        return 0;
    }
    fscanf(f, "%d", &pid);
    fclose(f);
    return pid;
}

int archipelago::System::check_pid(const string& pidfile)
{
    int pid = read_pid(pidfile);

    if ((!pid) || (pid == getpid())) {
        return 0;
    }

    if (kill(pid, 0) && errno == ESRCH) {
        return 0;
    }
    return pid;
}

int archipelago::System::write_pid(const string& pidfile)
{
    FILE *f;
    int fd;
    int pid;

    if (((fd = open(pidfile.c_str(), O_RDWR|O_CREAT, 0644)) == -1)
            || ((f = fdopen(fd, "r+")) == NULL) ) {
        logerror("Can't open or create " + pidfile);
        return 0;
    }

    if (flock(fd, LOCK_EX|LOCK_NB) == -1) {
        ostringstream pidstring;
        fscanf(f, "%d", &pid);
        fclose(f);
        pidstring << pid;
        logerror("Can't lock pidfile, lock is held by pid " + pidstring.str());
    }

    pid = getpid();
    if (!fprintf(f, "%d\n",  pid)) {
        logerror("Can't write pid.");
        close(fd);
        return 0;
    }
    fflush(f);

    if (flock(fd, LOCK_UN) == -1) {
        logerror("Can't unlock pidfile.");
        close(fd);
        return 0;
    }
    close(fd);
    return pid;
}

int archipelago::System::remove_pid(const string& pidfile)
{
    return unlink(pidfile.c_str());
}

class archipelago::Socket {
    private:
        int msockfd;
        sockaddr_un maddr;

    public:
        Socket();
        virtual ~Socket();

        uint32_t events;
        bool create();
        bool bind(const string endpoint);
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

archipelago::Socket::Socket(): msockfd(-1)
{
    events = 0;
    memset(&maddr, 0, sizeof(maddr));
}

archipelago::Socket::~Socket()
{
    if (is_valid()) {
        ::close(msockfd);
    }
}

bool archipelago::Socket::operator <(const Socket& other) const
{
    return this->msockfd < other.msockfd;
}

bool archipelago::Socket::operator >(const Socket& other) const
{
    return this->msockfd > other.msockfd;
}

bool archipelago::Socket::operator ==(const Socket& other) const
{
    return this->msockfd == other.msockfd;
}

bool archipelago::Socket::create()
{
    msockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (!is_valid()) {
        return false;
    }
    return true;
}

bool archipelago::Socket::bind(const string endpoint)
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

bool archipelago::Socket::listen(int backlog=5) const
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

bool archipelago::Socket::accept(Socket& socket) const
{
    socklen_t addrlen = sizeof(maddr);
    socket.msockfd = ::accept(msockfd, (struct sockaddr *)&maddr, &addrlen);

    if (socket.msockfd <= 0) {
        return false;
    }
    return true;
}

bool archipelago::Socket::write(const void *buffer, const size_t size) const
{
    int status = ::write(msockfd, buffer, size);
    if (status == -1) {
        return false;
    }
    return true;
}

int archipelago::Socket::read(void *buffer, size_t size) const
{
    int status = ::read(msockfd, buffer, size);
    if (status <= 0) {
        return 0;
    }
    return status;
}

const void archipelago::Socket::setnonblocking(const bool flag)
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

class archipelago::Epoll {
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

archipelago::Epoll::Epoll()
{
    epollfd = epoll_create1(0);
    if (epollfd < 0) {
        throw runtime_error("Cannot create epoll file descriptor.");
    }
}

archipelago::Epoll::~Epoll()
{
    ::close(epollfd);
}

bool archipelago::Epoll::add_fd(int fd, uint32_t events)
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

bool archipelago::Epoll::add_socket(Socket& socket, uint32_t events)
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

bool archipelago::Epoll::rm_fd(int fd, uint32_t events)
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

bool archipelago::Epoll::rm_socket(Socket& socket)
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

bool archipelago::Epoll::set_fd_pollin(int fd, uint32_t events)
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

bool archipelago::Epoll::reset_fd_pollin(int fd, uint32_t events)
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

bool archipelago::Epoll::set_fd_pollout(int fd, uint32_t events)
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

bool archipelago::Epoll::reset_fd_pollout(int fd, uint32_t events)
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

bool archipelago::Epoll::set_socket_pollin(Socket& socket)
{

    if (!set_fd_pollin(socket.get_fd(), socket.events)) {
        return false;
    }
    socket.events |= EPOLLIN;
    return true;
}

bool archipelago::Epoll::reset_socket_pollin(Socket& socket)
{
    if (!reset_fd_pollin(socket.get_fd(), socket.events)) {
        return false;
    }
    socket.events &= ~((short) EPOLLIN);
    return true;
}

bool archipelago::Epoll::set_socket_pollout(Socket& socket)
{
    if (!set_fd_pollout(socket.get_fd(), socket.events)) {
        return false;
    }
    socket.events |= EPOLLOUT;
    return true;
}

bool archipelago::Epoll::reset_socket_pollout(Socket& socket)
{
    if (!reset_fd_pollout(socket.get_fd(), socket.events)) {
        return false;
    }
    socket.events &= ~((short) EPOLLOUT);
    return true;
}

int archipelago::Epoll::wait(struct epoll_event *events, int maxevents,
        int timeout)
{
    int nfds = epoll_wait(epollfd, events, maxevents, timeout);
    if (nfds == -1 && errno != EINTR) {
        perror("epoll_wait");
        exit(EXIT_FAILURE);
    }
    return nfds;
}

using std::runtime_error;
class archipelago::SigException: public std::runtime_error {
    private:
        string what_;
    public:
        explicit SigException(const std::string& msg)
         : runtime_error(msg), what_(msg) {}

        virtual const char* what() const throw()
        {return what_.c_str();}
        virtual ~SigException() throw() {}
};

class archipelago::SigHandler {
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

bool archipelago::SigHandler::bExitSignal = false;

archipelago::SigHandler::SigHandler() {}

archipelago::SigHandler::~SigHandler() {}

bool archipelago::SigHandler::gotExitSignal()
{
    return bExitSignal;
}

void archipelago::SigHandler::setExitSignal(bool flag)
{
    bExitSignal = flag;
}

void archipelago::SigHandler::exitSignalHandler(int ignored)
{
    SigHandler::bExitSignal = true;
}

void archipelago::SigHandler::setupSignalHandlers()
{
    if (signal((int) SIGINT, SigHandler::exitSignalHandler) == SIG_ERR) {
        throw SigException("Cannot setup SIGINT signal handler");
    }
    if (signal((int) SIGQUIT, SigHandler::exitSignalHandler) == SIG_ERR) {
        throw SigException("Cannot setup SIGQUIT signal handler");
    }
}

class archipelago::Poold: public Logger {
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

archipelago::Poold::Poold(const int& startrange, const int& endrange,
        const string& uendpoint)
    : Logger("logging.conf", "Poold")
{
    initialize(startrange, endrange, uendpoint);
}

archipelago::Poold::Poold(const int& startrange, const int& endrange,
        const string& uendpoint, const string& logconf)
    : Logger(logconf, "Poold")
{
    initialize(startrange, endrange, uendpoint);
}

void archipelago::Poold::initialize(const int& start, const int& end,
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

archipelago::Socket *archipelago::Poold::find_socket(int fd)
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

void archipelago::Poold::set_socket_pollin(Socket& socket)
{
    if (!epoll.reset_socket_pollout(socket)) {
        logerror("epoll.reset_socket_pollout error");
    }
    if (!epoll.set_socket_pollin(socket)) {
        logerror("epoll.set_socket_pollin error");
    }
}

void archipelago::Poold::set_socket_pollout(Socket& socket)
{
    if (!epoll.reset_socket_pollin(socket)) {
        logerror("epoll.reset_socket_pollin error");
    }
    if (!epoll.set_socket_pollout(socket)) {
        logerror("epoll.set_socket_pollout error");
    }
}

void archipelago::Poold::server() {
    if (!srvsock.create()) {
        logfatal("Could not create server socket. Aborting...");
        exit(EXIT_FAILURE);
    }

    if (!srvsock.bind(endpoint)) {
        logfatal("Could not bind to endpoint. Aborting...");
        exit(EXIT_FAILURE);
    }

    if (!srvsock.listen()) {
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

void archipelago::Poold::create_new_connection(Socket& socket) {
    if (socket.get_fd() == -1) {
        logfatal("Socket file descriptor error. Aborting...");
        exit(EXIT_FAILURE);
    }
    socket.setnonblocking(true);
    epoll.add_socket(socket, EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR);
    socket_connection_state[&socket] = NONE;
    logdebug("Accepted new connection");
}

void archipelago::Poold::clear_connection(Socket& socket) {
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

poolmsg_t *archipelago::Poold::recv_msg(const Socket& socket) {
    unsigned int buffer[2];
    poolmsg_t *msg;

    logdebug("Receiving new message.");
    if (!socket.read(&buffer, sizeof(buffer))) {
        logerror("Socket read error.");
    }
    msg = (poolmsg_t *)calloc(1, sizeof(poolmsg_t));
    msg->type = ntohl(buffer[0]);
    msg->port = ntohl(buffer[1]);
    return msg;
}

int archipelago::Poold::send_msg(const Socket& socket, int port) {
    const int buffer[1] = {port};
    logdebug("Sending port to client.");

    int n = socket.write(buffer, sizeof(buffer));
    if (n < 0) {
        logerror("Socket write error.");
    }
    return n;
}

int archipelago::Poold::get_new_port(Socket& socket) {
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

void archipelago::Poold::handle_request(Socket& socket, poolmsg_t *msg)
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

void archipelago::Poold::serve_forever() {
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
