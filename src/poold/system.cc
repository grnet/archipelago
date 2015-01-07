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

#include <cstdio>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>

#include "poold/system.hh"
#include "poold/logger.hh"

namespace archipelago {

System::System(const std::string& logconffile)
            : Logger(logconffile, "System")
{
    cur_uid = cur_gid = -1;
}

int System::set_system(bool daemonize, int uid, int gid,
        mode_t mask, const std::string& pidfile)
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

int System::read_pid(const std::string& pidfile)
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

int System::check_pid(const std::string& pidfile)
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

int System::write_pid(const std::string& pidfile)
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
        std::ostringstream pidstring;
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

int System::remove_pid(const std::string& pidfile)
{
    return unlink(pidfile.c_str());
}

}
