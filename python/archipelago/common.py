#!/usr/bin/env python

# Copyright (C) 2010-2014 GRNET S.A.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#


from xseg.xseg_api import *
from xseg.xprotocol import *
from ctypes import (
    CFUNCTYPE,
    cast,
    c_void_p,
    addressof,
    string_at,
    memmove,
    create_string_buffer,
    pointer,
    sizeof,
    POINTER,
    byref,
    c_int,
    c_char,
    Structure,
    CDLL
)
cb_null_ptrtype = CFUNCTYPE(None, uint32_t)

import os
import sys
import time
import psutil
import errno
import signal
from subprocess import check_call
from collections import namedtuple
import socket
import random
from select import select
import ConfigParser
from grp import getgrnam
from pwd import getpwnam
import stat
import struct

libc = CDLL("libc.so.6")

get_errno_loc = libc.__errno_location
get_errno_loc.restype = POINTER(c_int)


random.seed()
hostname = socket.gethostname()

valid_role_types = ['file_blocker', 'rados_blocker', 'mapperd', 'vlmcd',
                    'poold']
valid_segment_types = ['posix']

peers = dict()
segment = None

BIN_DIR = '/usr/bin/'
DEFAULTS = '/etc/archipelago/archipelago.conf'

#system defaults
ARCHIP_PREFIX = 'archip_'
LOG_SUFFIX = '.log'
PID_SUFFIX = '.pid'
PIDFILE_PATH = "/var/run/archipelago"
VLMC_LOCK_FILE = 'vlmc.lock'
LOGS_PATH = "/var/log/archipelago"
LOCK_PATH = "/var/lock"
DEVICE_PREFIX = "/dev/xen/blktap-2/tapdev"

REQS = 512

FILE_BLOCKER = 'archip-filed'
RADOS_BLOCKER = 'archip-radosd'
MAPPER = 'archip-mapperd'
VLMC = 'archip-vlmcd'
POOLD = 'archip-poold'

def is_power2(x):
    return bool(x != 0 and (x & (x-1)) == 0)

#hack to test green waiting with python gevent.
class posixfd_signal_desc(Structure):
    pass
posixfd_signal_desc._fields_ = [
    ('signal_file', 2 * c_char * sizeof(c_void_p)),
    ('fd', c_int),
    ('flag', c_int),
]

def xseg_wait_signal_green(ctx, sd, timeout):
    posixfd_sd = cast(sd, POINTER(posixfd_signal_desc))
    fd = posixfd_sd.contents.fd
    select([fd], [], [], timeout/1000000.0)
    while True:
        try:
            os.read(fd, 512)
        except OSError as (e, msg):
            if e == 11:
                break
            else:
                raise OSError(e, msg)

def create_posixfd_dirs():
    path = "/dev/shm/posixfd"
    uid = getpwnam(config['USER']).pw_uid
    gid = getgrnam(config['GROUP']).gr_gid

    try:
        os.mkdir(path, stat.S_IRWXU|stat.S_IRWXG)
    except OSError as e:
        if e.errno == errno.EEXIST:
            if os.path.isdir(os.path.dirname(path)):
                    pass
            else:
                raise Error("%s is not a directory" % path)
        else:
            raise Error("Cannot create directory %s" % path)

    os.chown(path, uid, gid)
    st = os.stat(path)
    os.chmod(path, stat.S_IRWXU|stat.S_IRWXG|stat.S_ISGID)

class Peer(object):
    cli_opts = None

    def __init__(self, role=None, daemon=True, nr_ops=16,
                 logfile=None, pidfile=None, portno_start=None,
                 portno_end=None, log_level=0, spec=None, threshold=None,
                 user=None, group=None, umask="0o007"):
        if not role:
            raise Error("Role was not provided")
        self.role = role

        if not user:
            raise Error("User was not provided")

        self.user = user
        if not group:
            raise Error("Group was not provided")

        self.group = group
        self.user_uid = getpwnam(self.user).pw_uid
        self.group_gid = getgrnam(self.group).gr_gid
        self.umask = int(umask, 0)

        self.nr_ops = nr_ops
        if not self.nr_ops > 0:
            raise Error("Invalid nr_ops for %s" % role)

        if not is_power2(self.nr_ops):
            raise Error("nr_ops of %s is not a power of 2" % role)

        if not self.executable:
            raise Error("Executable must be provided for %s" % role)

        if portno_start is None:
            raise Error("Portno_start must be provided for %s" % role)
        self.portno_start = portno_start

        if portno_end is None:
            raise Error("Portno_end must be provided for %s" % role)
        self.portno_end = portno_end

        self.daemon = daemon
        if not spec:
            raise Error("Xseg spec was not provided for %s" % role)
        self.spec = spec

        if logfile:
            self.logfile = logfile
        else:
            self.logfile = os.path.join(LOGS_PATH, role + LOG_SUFFIX)

        if pidfile:
            self.pidfile = pidfile
        else:
            self.pidfile = os.path.join(PIDFILE_PATH, role + PID_SUFFIX)

        try:
            if not os.path.isdir(os.path.dirname(self.logfile)):
                raise Error("Log path %s does not exist" % self.logfile)
        except:
            raise Error("Log path %s does not exist or is not a directory" %
                        self.logfile)

        self.log_level = log_level
        self.threshold = threshold

        if self.log_level < 0 or self.log_level > 3:
            raise Error("%s: Invalid log level %d" %
                        (self.role, self.log_level))

        if self.cli_opts is None:
            self.cli_opts = []
        self.set_cli_options()

    def start(self):

        try:
            os.makedirs(os.path.dirname(self.pidfile))
        except OSError as e:
            if e.errno == errno.EEXIST:
                if os.path.isdir(os.path.dirname(self.pidfile)):
                    pass
                else:
                    raise Error("Pid path %s is not a directory" %
                                os.path.dirname(self.pidfile))
            else:
                raise Error("Cannot create path %s" %
                            os.path.dirname(self.pidfile))

        os.chmod(os.path.dirname(self.pidfile), stat.S_IRWXU|stat.S_IRWXG)
        os.chown(os.path.dirname(self.pidfile), -1, self.group_gid)
        os.chown(os.path.dirname(self.logfile), -1, self.group_gid)


        if self.get_pid():
            raise Error("Peer has valid pidfile")
        cmd = [os.path.join(BIN_DIR, self.executable)] + self.cli_opts
        try:
            check_call(cmd, shell=False)
        except Exception as e:
            raise Error("Cannot start %s: %s" % (self.role, str(e)))

    def stop(self):
        pid = self.get_pid()
        if not pid:
            raise Error("Peer %s not running" % self.role)

        if self.__is_running(pid):
            os.kill(pid, signal.SIGTERM)

    def __is_running(self, pid):
        name = self.executable
        for p in psutil.process_iter():
            if p.name[0:len(name)] == name and pid == p.pid:
                return True

        return False

    def is_running(self):
        pid = self.get_pid()
        if not pid:
            return False

        if not self.__is_running(pid):
            raise Error("Peer %s has valid pidfile but is not running" %
                        self.role)

        return True

    def get_pid(self):
        if not self.pidfile:
            return None

        pf = None
        try:
            pf = open(self.pidfile, "r")
            pid = int(pf.read())
            pf.close()
        except:
            if pf:
                pf.close()
            return None

        return pid

    def set_cli_options(self):
        if self.daemon:
            self.cli_opts.append("-d")
        if self.nr_ops:
            self.cli_opts.append("-n")
            self.cli_opts.append(str(self.nr_ops))
        if self.logfile:
            self.cli_opts.append("-l")
            self.cli_opts.append(self.logfile)
        if self.pidfile:
            self.cli_opts.append("--pidfile")
            self.cli_opts.append(self.pidfile)
        if self.portno_start is not None:
            self.cli_opts.append("-sp")
            self.cli_opts.append(str(self.portno_start))
        if self.portno_end is not None:
            self.cli_opts.append("-ep")
            self.cli_opts.append(str(self.portno_end))
        if self.log_level is not None:
            self.cli_opts.append("-v")
            self.cli_opts.append(str(self.log_level))
        if self.spec:
            self.cli_opts.append("-g")
            self.cli_opts.append(self.spec)
        if self.threshold:
            self.cli_opts.append("--threshold")
            self.cli_opts.append(str(self.threshold))
        if self.user:
            self.cli_opts.append("-uid")
            self.cli_opts.append(str(self.user_uid))
        if self.group:
            self.cli_opts.append("-gid")
            self.cli_opts.append(str(self.group_gid))
        if self.umask:
            self.cli_opts.append("--umask")
            self.cli_opts.append(str(self.umask))


class MTpeer(Peer):
    def __init__(self, nr_threads=1, **kwargs):
        self.nr_threads = nr_threads
        super(MTpeer, self).__init__(**kwargs)

        if self.cli_opts is None:
            self.cli_opts = []
        self.set_mtcli_options()

    def set_mtcli_options(self):
        self.cli_opts.append("-t")
        self.cli_opts.append(str(self.nr_threads))


class Radosd(MTpeer):
    def __init__(self, pool=None, cephx_id=None, **kwargs):
        self.executable = RADOS_BLOCKER
        self.pool = pool
        self.cephx_id = cephx_id
        super(Radosd, self).__init__(**kwargs)

        if self.cli_opts is None:
            self.cli_opts = []
        self.set_radosd_cli_options()

    def set_radosd_cli_options(self):
        if self.pool:
            self.cli_opts.append("--pool")
            self.cli_opts.append(self.pool)
        if self.cephx_id:
            self.cli_opts.append("--cephx-id")
            self.cli_opts.append(self.cephx_id)


class Filed(MTpeer):
    def __init__(self, archip_dir=None, prefix=None, fdcache=None,
                 unique_str=None, nr_threads=1, nr_ops=16, direct=True,
                 pithos_migrate=False, lock_dir=None, **kwargs):
        self.executable = FILE_BLOCKER
        self.archip_dir = archip_dir
        self.prefix = prefix
        self.fdcache = fdcache
        self.unique_str = unique_str
        self.direct = direct
        self.pithos_migrate = pithos_migrate
        self.lock_dir = lock_dir
        nr_threads = nr_ops
        if self.fdcache and fdcache < 2*nr_threads:
            raise Error("Fdcache should be greater than 2*nr_threads")

        super(Filed, self).__init__(nr_threads=nr_threads, nr_ops=nr_ops, **kwargs)

        if not self.archip_dir:
            raise Error("%s: Archip dir must be set" % self.role)
        if not os.path.isdir(self.archip_dir):
            raise Error("%s: Archip dir invalid" % self.role)
        if self.lock_dir and not os.path.isdir(self.lock_dir):
            raise Error("%s: Lock dir invalid" % self.role)
        if not self.fdcache:
            self.fdcache = 2*self.nr_ops
        if not self.unique_str:
            self.unique_str = hostname + '_' + str(self.portno_start)

        if self.cli_opts is None:
            self.cli_opts = []
        self.set_filed_cli_options()

    def set_filed_cli_options(self):
        if self.unique_str:
            self.cli_opts.append("--uniquestr")
            self.cli_opts.append(self.unique_str)
        if self.fdcache:
            self.cli_opts.append("--fdcache")
            self.cli_opts.append(str(self.fdcache))
        if self.archip_dir:
            self.cli_opts.append("--archip")
            self.cli_opts.append(self.archip_dir)
        if self.prefix:
            self.cli_opts.append("--prefix")
            self.cli_opts.append(self.prefix)
        if self.direct:
            self.cli_opts.append("--directio")
        if self.pithos_migrate:
            self.cli_opts.append("--pithos-migrate")
        if self.lock_dir:
            self.cli_opts.append("--lockdir")
            self.cli_opts.append(self.lock_dir)


class Mapperd(Peer):
    def __init__(self, blockerm_port=None, blockerb_port=None, **kwargs):
        self.executable = MAPPER
        if blockerm_port is None:
            raise Error("blockerm_port must be provied for %s" % role)
        self.blockerm_port = blockerm_port

        if blockerb_port is None:
            raise Error("blockerb_port must be provied for %s" % role)
        self.blockerb_port = blockerb_port
        super(Mapperd, self).__init__(**kwargs)

        if self.cli_opts is None:
            self.cli_opts = []
        self.set_mapperd_cli_options()

    def set_mapperd_cli_options(self):
        if self.blockerm_port is not None:
            self.cli_opts.append("-mbp")
            self.cli_opts.append(str(self.blockerm_port))
        if self.blockerb_port is not None:
            self.cli_opts.append("-bp")
            self.cli_opts.append(str(self.blockerb_port))


class Vlmcd(Peer):
    def __init__(self, blocker_port=None, mapper_port=None, **kwargs):
        self.executable = VLMC
        if blocker_port is None:
            raise Error("blocker_port must be provied for %s" % role)
        self.blocker_port = blocker_port

        if mapper_port is None:
            raise Error("mapper_port must be provied for %s" % role)
        self.mapper_port = mapper_port
        super(Vlmcd, self).__init__(**kwargs)

        if self.cli_opts is None:
            self.cli_opts = []
        self.set_vlmcd_cli_opts()

    def set_vlmcd_cli_opts(self):
        if self.blocker_port is not None:
            self.cli_opts.append("-bp")
            self.cli_opts.append(str(self.blocker_port))
        if self.mapper_port is not None:
            self.cli_opts.append("-mp")
            self.cli_opts.append(str(self.mapper_port))


class Poold(object):
    def __init__(self, role=None, daemon=True, logging_conf=None, pidfile=None,
                 portno_start=None, portno_end=None, user=None, group=None,
                 socket_path=None, umask="0o007"):
        self.executable = POOLD
        if not role:
            raise Error("Role was not provided")
        self.role = role

        if not user:
            raise Error("User was not provided")
        self.user = user

        if not group:
            raise Error("Group was not provided")
        self.group = group

        self.user_uid = getpwnam(self.user).pw_uid
        self.group_gid = getgrnam(self.group).gr_gid
        self.umask = int(umask, 0)

        if portno_start is None:
            raise Error("portno_start must be provided for %s" % role)
        self.portno_start = portno_start

        if portno_end is None:
            raise Error("portno_end must be provided for %s" % role)
        self.portno_end = portno_end

        self.daemon = daemon
        self.logging_conf = logging_conf
        if pidfile:
            self.pidfile = pidfile
        else:
            self.pidfile = os.path.join(PIDFILE_PATH, role + PID_SUFFIX)
        self.socket_path = socket_path
        self.set_cli_options()

    def start(self):

        try:
            os.makedirs(os.path.dirname(self.pidfile))
        except OSError as e:
            if e.errno == errno.EEXIST:
                if os.path.isdir(os.path.dirname(self.pidfile)):
                    pass
                else:
                    raise Error("Pid path %s is not a directory" %
                                os.path.dirname(self.pidfile))
            else:
                raise Error("Cannot create path %s" %
                            os.path.dirname(self.pidfile))

        os.chmod(os.path.dirname(self.pidfile), stat.S_IRWXU | stat.S_IRWXG)
        os.chown(os.path.dirname(self.pidfile), -1, self.group_gid)

        if self.get_pid():
            raise Error("Poold daemon has a valid pidfile.")
        cmd = [os.path.join(BIN_DIR, self.executable)] + self.cli_opts
        try:
            check_call(cmd, shell=False)
        except Exception as e:
            raise Error("Cannot start %s: %s" % (self.role, str(e)))

    def stop(self):
        pid = self.get_pid()
        if not pid:
            raise Error("Peer %s not running" % self.role)

        if self.__is_running(pid):
            os.kill(pid, signal.SIGQUIT)

    def __is_running(self, pid):
        name = self.executable
        for p in psutil.process_iter():
            if p.name[0:len(name)] == name and pid == p.pid:
                return True

        return False

    def is_running(self):
        pid = self.get_pid()
        if not pid:
            return False

        if not self.__is_running(pid):
            raise Error("Poold daemon %s has a valid pidfile but is not "
                        "running" % self.role)

        return True

    def get_pid(self):
        if not self.pidfile:
            return None

        pf = None
        try:
            pf = open(self.pidfile, "r")
            pid = int(pf.read())
            pf.close()
        except:
            if pf:
                pf.close()
            return None

        return pid

    def set_cli_options(self):
        self.cli_opts = []
        if self.daemon:
            self.cli_opts.append("-d")
        if self.logging_conf:
            self.cli_opts.append("-c")
            self.cli_opts.append(self.logging_conf)
        if self.pidfile:
            self.cli_opts.append("-i")
            self.cli_opts.append(self.pidfile)
        if self.portno_start is not None:
            self.cli_opts.append("-s")
            self.cli_opts.append(str(self.portno_start))
        if self.portno_end is not None:
            self.cli_opts.append("-e")
            self.cli_opts.append(str(self.portno_end))
        if self.user:
            self.cli_opts.append("-u")
            self.cli_opts.append(str(self.user_uid))
        if self.group:
            self.cli_opts.append("-g")
            self.cli_opts.append(str(self.group_gid))
        if self.umask:
            self.cli_opts.append("-m")
            self.cli_opts.append(str(self.umask))
        if self.socket_path:
            self.cli_opts.append("-p")
            self.cli_opts.append(str(self.socket_path))



config = {
    'CEPH_CONF_FILE': '/etc/ceph/ceph.conf',
    # 'SPEC': "posix:archipelago:1024:5120:12",
    'SEGMENT_TYPE': 'posix',
    'SEGMENT_NAME': 'archipelago',
    'SEGMENT_DYNPORTS': 1024,
    'SEGMENT_PORTS': 2048,
    'SEGMENT_SIZE': 5120,
    'SEGMENT_ALIGNMENT': 12,
    'VTOOL_START': 1003,
    'VTOOL_END': 1003,
    'UMASK': 0o007,
    #RESERVED 1023
}

FIRST_COLUMN_WIDTH = 23
SECOND_COLUMN_WIDTH = 23


def green(s):
    return '\x1b[32m' + str(s) + '\x1b[0m'


def red(s):
    return '\x1b[31m' + str(s) + '\x1b[0m'


def yellow(s):
    return '\x1b[33m' + str(s) + '\x1b[0m'


def pretty_print(cid, status):
    sys.stdout.write(cid.ljust(FIRST_COLUMN_WIDTH))
    sys.stdout.write(status.ljust(SECOND_COLUMN_WIDTH))
    sys.stdout.write('\n')
    return


class Error(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg

class Segment(object):
    type = 'posix'
    name = 'archipelago'
    dyports = 1024
    ports = 2048
    size = 5120
    alignment = 12

    spec = None

    def __init__(self, type, name, dynports, ports, size, align=12):
        initialize_xseg()
        self.type = type
        self.name = name
        self.dynports = dynports
        self.ports = ports
        self.size = size
        self.alignment = align

        if self.type not in valid_segment_types:
            raise Error("Segment type not valid")
        if self.alignment != 12:
            raise Error("Wrong alignemt")
        if self.dynports >= self.ports :
            raise Error("Dynports >= max ports")

        self.spec = self.get_spec()

    def get_spec(self):
        if not self.spec:
            params = [self.type, self.name, str(self.dynports), str(self.ports),
                      str(self.size), str(self.alignment)]
            self.spec = ':'.join(params).encode()
        return self.spec

    def create(self):
        #fixme blocking....
        xconf = xseg_config()
        c_spec = create_string_buffer(self.spec)
        xseg_parse_spec(c_spec, xconf)
        r = xseg_create(xconf)
        if r < 0:
            raise Error("Cannot create segment")

    def destroy(self):
        #fixme blocking....
        try:
            xseg = self.join()
        except:
            return
        try:
            xseg_leave(xseg)
            xseg_destroy(xseg)
        except Exception:
            raise Error("Cannot destroy segment")

    def join(self):

        def errcheck(ret, func, args):
            if not ret:
                e = get_errno_loc()[0]
                raise Error("Cannot join segment '%s': %s"
                                % (config['SEGMENT_NAME'], os.strerror(e)))
            return ret

        xconf = xseg_config()
        spec_buf = create_string_buffer(self.spec)
        xseg_parse_spec(spec_buf, xconf)
        xseg_join.errcheck = errcheck
        ctx = xseg_join(xconf.type, xconf.name, "posixfd",
                        cast(0, cb_null_ptrtype))

        return ctx

def check_conf():
    port_ranges = []

    def isExec(file_path):
        return os.path.isfile(file_path) and os.access(file_path, os.X_OK)

    def validExec(program):
        for path in os.environ["PATH"].split(os.pathsep):
            exe_file = os.path.join(path, program)
            if isExec(exe_file):
                return True
        return False

    def validatePort(portno, limit):
        if portno >= limit:
            raise Error("Portno %d out of range" % portno)

    def validatePortRange(portno_start, portno_end, limit):
        validatePort(portno_start, limit)
        validatePort(portno_end, limit)
        if portno_start > portno_end:
            raise Error("Portno_start > Portno_end: %d > %d " %
                        (portno_start, portno_end))
        for start, end in port_ranges:
            if not (portno_end < start or portno_start > end):
                raise Error("Port range conflict: (%d, %d) confilcts with (%d, %d)" %
                            (portno_start, portno_end,  start, end))
        port_ranges.append((portno_start, portno_end))

    xseg_type = config['SEGMENT_TYPE']
    xseg_name = config['SEGMENT_NAME']
    xseg_dynports = config['SEGMENT_DYNPORTS']
    xseg_ports = config['SEGMENT_PORTS']
    xseg_size = config['SEGMENT_SIZE']
    xseg_align = config['SEGMENT_ALIGNMENT']

    global segment
    segment = Segment(xseg_type, xseg_name, xseg_dynports, xseg_ports, xseg_size,
                      xseg_align)


    try:
        if not config['roles']:
            raise Error("Roles setup must be provided")
    except KeyError:
        raise Error("Roles setup must be provided")

    try:
        getpwnam(config['USER'])
    except KeyError:
        raise Error("User '%s' does not exist" % config['USER'])

    try:
        getgrnam(config['GROUP'])
    except KeyError:
        raise Error("Group '%s' does not exist" % config['GROUP'])

    for role, role_type in config['roles']:
        if role_type not in valid_role_types:
            raise Error("%s is not a valid role" % role_type)
        try:
            role_config = config[role]
            role_config['user'] = config['USER']
            role_config['group'] = config['GROUP']
        except:
            raise Error("No config found for %s" % role)

        if role_type == 'file_blocker':
            peers[role] = Filed(role=role, spec=segment.get_spec(),
                                 prefix=ARCHIP_PREFIX, **role_config)
        elif role_type == 'rados_blocker':
            peers[role] = Radosd(role=role,
                                 spec=segment.get_spec(), **role_config)
        elif role_type == 'mapperd':
            peers[role] = Mapperd(role=role, spec=segment.get_spec(),
                                  **role_config)
        elif role_type == 'vlmcd':
            peers[role] = Vlmcd(role=role, spec=segment.get_spec(),
                                **role_config)
        elif role_type == 'poold':
            peers[role] = Poold(role=role, **role_config)
        else:
            raise Error("No valid peer type: %s" % role_type)
        validatePortRange(peers[role].portno_start, peers[role].portno_end,
                          xseg_ports)

    validatePortRange(config['VTOOL_START'], config['VTOOL_END'], xseg_ports)
    return True

def get_segment():
    return segment

def construct_peers():
    return peers

vtool_port = None
def get_vtool_port():
    global vtool_port
    if vtool_port is None:
        vtool_port = random.randint(config['VTOOL_START'], config['VTOOL_END'])
    return vtool_port

acquired_locks = {}

def get_lock(lock_file, max_time=15):
    elapsed = 0
    while True:
        try:
            fd = os.open(lock_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            break
        except OSError, (err, reason):
            print >> sys.stderr, lock_file, reason
            if err == errno.EEXIST:
                if elapsed < max_time:
                    print >> sys.stderr, "Retrying..."
                    time.sleep(0.2)
                    elapsed += 0.2
                else:
                    raise Error("Could not acquire %s. Tried %d seconds" %
                            (lock_file, max_time))
            else:
                raise OSError(err, lock_file + ' ' + reason)
    return fd

def exclusive(get_port=False):
    def wrap(fn):
        def lock(*args, **kwargs):
            if not os.path.exists(LOCK_PATH):
                try:
                    os.mkdir(LOCK_PATH)
                except OSError, (err, reason):
                    print >> sys.stderr, reason

            if not os.path.isdir(LOCK_PATH):
                raise Error("Locking error: %s is not a directory" % LOCK_PATH)

            if get_port:
                vtool_port = get_vtool_port()
                lock_file = os.path.join(LOCK_PATH, VLMC_LOCK_FILE + '_' + str(vtool_port))
            else:
                lock_file = os.path.join(LOCK_PATH, VLMC_LOCK_FILE)
            try:
                depth = acquired_locks[lock_file]
                if depth == 0:
                    fd = get_lock(lock_file)
            except KeyError:
                acquired_locks[lock_file] = 0
                fd = get_lock(lock_file)

            acquired_locks[lock_file] += 1
            try:
                r = fn(*args, **kwargs)
            finally:
                acquired_locks[lock_file] -= 1
                depth = acquired_locks[lock_file]
                if depth == 0:
                    os.close(fd)
                    os.unlink(lock_file)
            return r

        return lock
    return wrap

def createDict(cfg, section):
    sec_dic = {}
    t = str(cfg.get(section, 'type'))
    if t != 'poold':
        sec_dic['portno_start'] = cfg.getint(section, 'portno_start')
        sec_dic['portno_end'] = cfg.getint(section, 'portno_end')
        sec_dic['nr_ops'] = cfg.getint(section, 'nr_ops')

    if cfg.has_option(section, 'logfile'):
        sec_dic['logfile'] = str(cfg.get(section, 'logfile'))
    if cfg.has_option(section, 'threshold'):
        sec_dic['threshold'] = cfg.getint(section, 'threshold')
    if cfg.has_option(section, 'log_level'):
        sec_dic['log_level'] = cfg.getint(section, 'log_level')
    if cfg.has_option(section, 'umask'):
        sec_dic['umask'] = cfg.get(section, 'umask')

    if t == 'file_blocker':
        sec_dic['nr_threads'] = cfg.getint(section, 'nr_threads')
        sec_dic['archip_dir'] = cfg.get(section, 'archip_dir')
        if cfg.has_option(section, 'lock_dir'):
            sec_dic['lock_dir'] = cfg.get(section, 'lock_dir')
        if cfg.has_option(section, 'fdcache'):
            sec_dic['fdcache'] = cfg.getint(section, 'fdcache')
        if cfg.has_option(section, 'direct'):
            sec_dic['direct'] = cfg.getboolean(section, 'direct')
        if cfg.has_option(section, 'pithos_migrate'):
            sec_dic['pithos_migrate'] = cfg.getboolean(section, 'pithos_migrate')
        if cfg.has_option(section, 'unique_str'):
            sec_dic['unique_str'] = cfg.getint(section, 'unique_str')
        if cfg.has_option(section, 'prefix'):
            sec_dic['prefix'] = cfg.getint(section, 'prefix')
    elif t == 'rados_blocker':
        if cfg.has_option(section, 'nr_threads'):
            sec_dic['nr_threads'] = cfg.getint(section, 'nr_threads')
        if cfg.has_option(section, 'cephx_id'):
            sec_dic['cephx_id'] = cfg.get(section, 'cephx_id')
        sec_dic['pool'] = cfg.get(section, 'pool')
    elif t == 'mapperd':
        sec_dic['blockerb_port'] = cfg.getint(section, 'blockerb_port')
        sec_dic['blockerm_port'] = cfg.getint(section, 'blockerm_port')
    elif t == 'vlmcd':
        sec_dic['blocker_port'] = cfg.getint(section, 'blocker_port')
        sec_dic['mapper_port'] = cfg.getint(section, 'mapper_port')
    elif t == 'poold':
        if cfg.has_option(section, 'portno_start'):
            sec_dic['portno_start'] = cfg.getint(section, 'portno_start')
        if cfg.has_option(section, 'portno_end'):
            sec_dic['portno_end'] = cfg.getint(section, 'portno_end')
        if cfg.has_option(section, 'umask'):
            sec_dic['umask'] = cfg.get(section, 'umask')
        if cfg.has_option(section, 'logging_conf'):
            sec_dic['logging_conf'] = cfg.get(section, 'logging_conf')
        if cfg.has_option(section, 'socket_path'):
            sec_dic['socket_path'] = cfg.get(section, 'socket_path')
        if cfg.has_option(section, 'pidfile'):
            sec_dic['pidfile'] = cfg.get(section, 'pidfile')

    return sec_dic


def loadrc(rc):
    try:
        if rc is None:
            cfg_dir = os.path.expanduser(DEFAULTS)
        else:
            cfg_dir = rc
        cfg_fd = open(cfg_dir)
    except:
        raise Error("Cannot read config file")

    cfg = ConfigParser.ConfigParser()
    cfg.readfp(cfg_fd)
    config['SEGMENT_PORTS'] = cfg.getint('XSEG','SEGMENT_PORTS')
    config['SEGMENT_DYNPORTS'] = cfg.getint('XSEG', 'SEGMENT_DYNPORTS')
    config['SEGMENT_SIZE'] = cfg.getint('XSEG','SEGMENT_SIZE')
    config['VTOOL_START'] = cfg.getint('XSEG','VTOOL_START')
    config['VTOOL_END'] = cfg.getint('XSEG','VTOOL_END')
    config['USER'] = cfg.get('ARCHIPELAGO','USER')
    config['GROUP'] = cfg.get('ARCHIPELAGO','GROUP')
    config['BLKTAP_ENABLED'] = cfg.getboolean('ARCHIPELAGO','BLKTAP_ENABLED')
    if cfg.has_option('ARCHIPELAGO', 'UMASK'):
        config['UMASK'] = int(cfg.get('ARCHIPELAGO', 'UMASK'), 0)
    roles = cfg.get('PEERS', 'ROLES')
    roles = str(roles)
    roles = roles.split(' ')
    config['roles'] = [(r, str(cfg.get(r, 'type'))) for r in roles]
    for r in roles:
        config[r] = createDict(cfg, r)

    if not check_conf():
        raise Error("Invalid conf file")


def loaded_modules():
    lines = open("/proc/modules").read().split("\n")
    modules = [f.split(" ")[0] for f in lines]
    return modules


def loaded_module(name):
    return name in loaded_modules()


def load_module(name, args):
    s = "Loading %s " % name
    sys.stdout.write(s.ljust(FIRST_COLUMN_WIDTH))
    modules = loaded_modules()
    if name in modules:
        sys.stdout.write(yellow("Already loaded".ljust(SECOND_COLUMN_WIDTH)))
        sys.stdout.write("\n")
        return
    cmd = ["modprobe", "%s" % name]
    if args:
        for arg in args:
            cmd.extend(["%s=%s" % (arg)])
    try:
        check_call(cmd, shell=False)
    except Exception:
        sys.stdout.write(red("FAILED".ljust(SECOND_COLUMN_WIDTH)))
        sys.stdout.write("\n")
        raise Error("Cannot load module %s. Check system logs" % name)
    sys.stdout.write(green("OK".ljust(SECOND_COLUMN_WIDTH)))
    sys.stdout.write("\n")


def unload_module(name):
    s = "Unloading %s " % name
    sys.stdout.write(s.ljust(FIRST_COLUMN_WIDTH))
    modules = loaded_modules()
    if name not in modules:
        sys.stdout.write(yellow("Not loaded".ljust(SECOND_COLUMN_WIDTH)))
        sys.stdout.write("\n")
        return
    cmd = ["modprobe -r %s" % name]
    try:
        check_call(cmd, shell=True)
    except Exception:
        sys.stdout.write(red("FAILED".ljust(SECOND_COLUMN_WIDTH)))
        sys.stdout.write("\n")
        raise Error("Cannot unload module %s. Check system logs" % name)
    sys.stdout.write(green("OK".ljust(SECOND_COLUMN_WIDTH)))
    sys.stdout.write("\n")

xseg_initialized = False


def initialize_xseg():
    global xseg_initialized
    if not xseg_initialized:
        xseg_initialize()
        xseg_initialized = True


def check_running(name, pid=None):
    for p in psutil.process_iter():
        if p.name[0:len(name)] == name:
            if pid:
                if pid == p.pid:
                    return pid
            else:
                return pid
    return None


def check_pidfile(name):
    pidfile = os.path.join(PIDFILE_PATH, name + PID_SUFFIX)
    pf = None
    try:
        pf = open(pidfile, "r")
        pid = int(pf.read())
        pf.close()
    except:
        if pf:
            pf.close()
        return -1

    return pid

class Xseg_ctx(object):
    ctx = None
    port = None
    portno = None
    signal_desc = None
    dynalloc = False

    def __init__(self, segment, portno=None):
        ctx = segment.join()
        if not ctx:
            raise Error("Cannot join segment")
        if portno == None:
            port = xseg_bind_dynport(ctx)
            portno = xseg_portno_nonstatic(ctx, port)
            dynalloc = True
        else:
            port = xseg_bind_port(ctx, portno, c_void_p(0))
            dynalloc = False

        if not port:
            raise Error("Cannot bind to port")

        sd = xseg_get_signal_desc_nonstatic(ctx, port)
        if not sd:
            raise Error("Cannot get signal descriptor")

        xseg_init_local_signal(ctx, portno)
        self.ctx = ctx
        self.port = port
        self.portno = portno
        self.dynalloc = dynalloc
        self.signal_desc = sd

    def __del__(self):
        return

    def __enter__(self):
        if not self.ctx:
            raise Error("No segment")
        return self

    def __exit__(self, type_, value, traceback):
        self.shutdown()
        return False

    def shutdown(self):
        if self.port is not None and self.dynalloc:
                xseg_leave_dynport(self.ctx, self.port)
        if self.ctx:
            xseg_quit_local_signal(self.ctx, self.portno)
            xseg_leave(self.ctx)
        self.ctx = None

    def wait_request(self):
        xseg_prepare_wait(self.ctx, self.portno)
        while True:
            received = xseg_receive(self.ctx, self.portno, 0)
            if received:
                xseg_cancel_wait(self.ctx, self.portno)
                return received
            else:
                xseg_wait_signal_green(self.ctx, self.signal_desc, 10000000)

    def wait_requests(self, requests):
        while True:
            received = self.wait_request()
            for req in requests:
                xseg_req = req.req
                if addressof(received.contents) == \
                            addressof(xseg_req.contents):
                    return req
            p = xseg_respond(self.ctx, received, self.portno, X_ALLOC)
            if p == NoPort:
                xseg_put_request(self.ctx, received, self.portno)
            else:
                xseg_signal(self.ctx, p)


class Request(object):
    xseg_ctx = None
    req = None

    def __init__(self, xseg_ctx, dst_portno, target, datalen=0, size=0, op=None,
                 data=None, flags=0, offset=0, v0_size=-1):
        if not target:
            raise Error("No target")
        targetlen = len(target)
        if not datalen and data:
            if isinstance(data, basestring):
                datalen = len(data)
            else:
                datalen = sizeof(data)

        ctx = xseg_ctx.ctx
        if not ctx:
            raise Error("No context")
        req = xseg_get_request(ctx, xseg_ctx.portno, dst_portno, X_ALLOC)
        if not req:
            raise Error("Cannot get request")
        r = xseg_prep_request(ctx, req, targetlen, datalen)
        if r < 0:
            xseg_put_request(ctx, req, xseg_ctx.portno)
            raise Error("Cannot prepare request")
        self.req = req
        self.xseg_ctx = xseg_ctx

        if not self.set_target(target):
            self.put()
            raise Error("Cannot set target")

        if (data):
            if not self.set_data(data):
                self.put()
                raise Error("Cannot set data")

        self.set_size(size)
        self.set_op(op)
        self.set_flags(flags)
        self.set_offset(offset)
        self.set_v0_size(v0_size)

        return

    def __enter__(self):
        if not self.req:
            raise Error("xseg request not set")
        return self

    def __exit__(self, type_, value, traceback):
        self.put()
        self.req = None
        return False

    def put(self, force=False):
        if not self.req:
            return False
        if not force:
            if xq_count(byref(self.req.contents.path)) > 0:
                return False
        xseg_put_request(self.xseg_ctx.ctx, self.req, self.xseg_ctx.portno)
        self.req = None
        return True

    def get_datalen(self):
        return self.req.contents.datalen

    def set_op(self, op):
        self.req.contents.op = op

    def get_op(self):
        return self.req.contents.op

    def set_offset(self, offset):
        self.req.contents.offset = offset

    def get_offset(self):
        return self.req.contents.offset

    def get_size(self):
        return self.req.contents.size

    def set_size(self, size):
        self.req.contents.size = size

    def get_v0_size(self):
        return self.req.contents.v0_size

    def set_v0_size(self, size):
        self.req.contents.v0_size = size

    def get_serviced(self):
        return self.req.contents.serviced

    def set_serviced(self, serviced):
        self.req.contents.serviced = serviced

    def set_flags(self, flags):
        self.req.contents.flags = flags

    def get_flags(self):
        return self.req.contents.flags

    def set_target(self, target):
        """Sets the target of the request, respecting request's targetlen"""
        if len(target) != self.req.contents.targetlen:
            return False
        c_target = xseg_get_target_nonstatic(self.xseg_ctx.ctx, self.req)
        p_target = create_string_buffer(target)
#        print hex(addressof(c_target.contents))
        memmove(c_target, p_target, len(target))
        return True

    def get_target(self):
        """Return a string to the target of the request"""
        c_target = xseg_get_target_nonstatic(self.xseg_ctx.ctx, self.req)
#        print "target_addr " + str(addressof(c_target.contents))
        return string_at(c_target, self.req.contents.targetlen)

    def set_data(self, data):
        """Sets requests data. Data should be a xseg protocol structure"""
        if isinstance(data, basestring):
            if len(data) != self.req.contents.datalen:
                return False
            p_data = create_string_buffer(data)
            c_data = xseg_get_data_nonstatic(self.xseg_ctx.ctx, self.req)
            memmove(c_data, p_data, self.req.contents.datalen)
        elif isinstance(data, xseg_request_create):
            size = sizeof(uint32_t) * 3 + data.cnt * sizeof(xseg_create_map_scatterlist)
            if size != self.req.contents.datalen:
                return False
            p = struct.pack("=LLL", data.cnt, data.blocksize, data.create_flags)
            p_data = create_string_buffer(p)
            c_data = xseg_get_data_nonstatic(self.xseg_ctx.ctx, self.req)
            memmove(c_data, p_data, sizeof(uint32_t)*3)
            c_data = addressof(c_data.contents)
            c_data += sizeof(uint32_t) * 3
            c_data = cast(c_data, POINTER(c_char))
            for i in range(0, data.cnt):
                p = struct.pack("=256sLL", data.segs[i].target, data.segs[i].targetlen,
                         data.segs[i].flags)
                p_data = create_string_buffer(p)
                memmove(c_data, p_data, sizeof(xseg_create_map_scatterlist))
                c_data = addressof(c_data.contents)
                c_data += sizeof(xseg_create_map_scatterlist)
                c_data = cast(c_data, POINTER(c_char))
        else:
            if sizeof(data) != self.req.contents.datalen:
                return False
            p_data = pointer(data)
            c_data = xseg_get_data_nonstatic(self.xseg_ctx.ctx, self.req)
            memmove(c_data, p_data, self.req.contents.datalen)

        return True

    def get_data(self, _type=None):
        """return a pointer to the data buffer of the request, casted to the
        selected type"""
#        print "data addr " + str(addressof(xseg_get_data_nonstatic(\
#            self.xseg_ctx.ctx, self.req).contents))
#        ret = cast(xseg_get_data_nonstatic(self.xseg_ctx.ctx, self.req),
#                   _type)
#        print addressof(ret.contents)
#        return ret
        if _type:
            return cast(xseg_get_data_nonstatic(self.xseg_ctx.ctx, self.req),
                        POINTER(_type))
        else:
            return cast(xseg_get_data_nonstatic(self.xseg_ctx.ctx, self.req),
                        c_void_p)

    def submit(self):
        """Submit the associated xseg_request"""
        p = xseg_submit(self.xseg_ctx.ctx, self.req, self.xseg_ctx.portno,
                        X_ALLOC)
        if p == NoPort:
            raise Exception
        xseg_signal(self.xseg_ctx.ctx, p)

    def wait(self):
        """Wait until the associated xseg_request is responded, discarding any
        other requests that may be received in the meantime"""
        self.xseg_ctx.wait_requests([self])

    def success(self):
        if not bool(self.req.contents.state & XS_SERVED) and not \
            bool(self.req.contents.state & XS_FAILED):
            raise Error("Request not completed, nor Failed")
        return bool((self.req.contents.state & XS_SERVED) and not \
                   (self.req.contents.state & XS_FAILED))

    @classmethod
    def get_write_request(cls, xseg, dst, target, data=None, offset=0,
            datalen=0, flags=0):
        if data is None:
            data = ""
        size = len(data)
        if not datalen:
            datalen = size

        return cls(xseg, dst, target, op=X_WRITE, data=data, offset=offset,
                   size=size, datalen=datalen, flags=flags)

    @classmethod
    def get_read_request(cls, xseg, dst, target, size=0, offset=0, datalen=0):
        if not datalen:
            datalen=size
        return cls(xseg, dst, target, op=X_READ, offset=offset, size=size,
                   datalen=datalen)

    @classmethod
    def get_info_request(cls, xseg, dst, target):
        return cls(xseg, dst, target, op=X_INFO)

    @classmethod
    def get_copy_request(cls, xseg, dst, target, copy_target=None, size=0, offset=0):
        datalen = sizeof(xseg_request_copy)
        xcopy = xseg_request_copy()
        xcopy.target = target
        xcopy.targetlen = len(target)
        return cls(xseg, dst, copy_target, op=X_COPY, data=xcopy, datalen=datalen,
                size=size, offset=offset)
    @classmethod
    def get_acquire_request(cls, xseg, dst, target, wait=False):
        flags = 0
        if not wait:
            flags = XF_NOSYNC
        return cls(xseg, dst, target, op=X_ACQUIRE, flags=flags)

    @classmethod
    def get_release_request(cls, xseg, dst, target, force=False):
        flags = 0
        if force:
            flags = XF_FORCE
        return cls(xseg, dst, target, op=X_RELEASE, flags=flags)

    @classmethod
    def get_delete_request(cls, xseg, dst, target):
        return cls(xseg, dst, target, op=X_DELETE)

    @classmethod
    def get_update_request(cls, xseg, dst, target):
        return cls(xseg, dst, target, op=X_UPDATE)

    @classmethod
    def get_clone_request(cls, xseg, dst, target, clone=None, clone_size=0):
        datalen = sizeof(xseg_request_clone)
        xclone = xseg_request_clone()
        xclone.target = target
        xclone.targetlen= len(target)
        xclone.size = clone_size

        return cls(xseg, dst, clone, op=X_CLONE, data=xclone, datalen=datalen)

    @classmethod
    def get_open_request(cls, xseg, dst, target):
        return cls(xseg, dst, target, op=X_OPEN)

    @classmethod
    def get_close_request(cls, xseg, dst, target):
        return cls(xseg, dst, target, op=X_CLOSE)

    @classmethod
    def get_snapshot_request(cls, xseg, dst, target, snap=None):
        datalen = sizeof(xseg_request_snapshot)
        xsnapshot = xseg_request_snapshot()
        xsnapshot.target = snap
        xsnapshot.targetlen= len(snap)

        return cls(xseg, dst, target, op=X_SNAPSHOT, data=xsnapshot,
                datalen=datalen)

    @classmethod
    def get_mapr_request(cls, xseg, dst, target, offset=0, size=0):
        return cls(xseg, dst, target, op=X_MAPR, offset=offset, size=size,
                datalen=0)

    @classmethod
    def get_mapw_request(cls, xseg, dst, target, offset=0, size=0):
        return cls(xseg, dst, target, op=X_MAPW, offset=offset, size=size,
                datalen=0)

    @classmethod
    def get_hash_request(cls, xseg, dst, target, size=0, offset=0):
        return cls(xseg, dst, target, op=X_HASH, size=size, offset=offset)

    @classmethod
    def get_rename_request(cls, xseg, dst, target, newname=None):
        """
        Return a new request, formatted as a rename request with the given
        arguments
        """
        datalen = sizeof(xseg_request_rename)
        xrename = xseg_request_rename()
        xrename.target = newname
        xrename.targetlen= len(newname)

        return cls(xseg, dst, target, op=X_RENAME, data=xrename, datalen=datalen)

    @classmethod
    def get_create_request(cls, xseg, dst, target, size=0, mapflags=None,
            objects=None, blocksize=None):
        """
        Return a new request, formatted as a create request with the given
        arguments
        """
        if blocksize is None:
            raise Error("Blocksize not supplied")
        if objects is None:
            raise Error("Objects not supplied")
        if mapflags is None:
            mapflags = 0

        xcreate = xseg_request_create()
        xcreate.blocksize = blocksize
        xcreate.create_flags = mapflags
        xcreate.cnt = len(objects)
        SegsArray = xseg_create_map_scatterlist * xcreate.cnt
        xcreate.segs = SegsArray()
        for i in range(0, xcreate.cnt):
            xcreate.segs[i].target = objects[i]['name']
            xcreate.segs[i].targetlen = len(xcreate.segs[i].target)
            xcreate.segs[i].flags = objects[i]['flags']

        datalen = sizeof(uint32_t) * 3 + sizeof(SegsArray)

        return cls(xseg, dst, target, op=X_CREATE, size=size, data=xcreate,
                datalen=datalen)


class PoolClient(object):
    def __init__(self, endpoint="/var/run/archipelago/poold.socket"):
        self.request = {'GET_PORT': 0, "LEAVE_PORT": 1, "LEAVE_ALL_PORTS": 2}
        self.socket = None
        self.endpoint = endpoint

    def __send_msg(self, msg):
        self.socket.send(msg)

    def __recv_msg(self):
        tmp = self.socket.recv(struct.calcsize("i"))
        port = struct.unpack("i", tmp)[0]
        return port

    def __create_msg(self, code, port):
        return struct.pack("!II", code, port)

    def __create_socket(self):
        if self.socket is None:
            self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    def __send_and_recv_msg(self, msg):
        self.__send_msg(msg)
        return self.__recv_msg()

    def connect(self):
        self.__create_socket()
        self.socket.settimeout(5)
        self.socket.connect(self.endpoint)
        self.socket.settimeout(None)

    def get_port(self):
        msg = self.__create_msg(self.request['GET_PORT'], 0)
        port = self.__send_and_recv_msg(msg)
        return int(port)

    def leave_port(self, port):
        msg = self.__create_msg(self.request['LEAVE_PORT'], port)
        return bool(self.__send_and_recv_msg(msg))

    def leave_all_ports(self):
        msg = self.__create_msg(self.request['LEAVE_ALL_PORTS'], 0)
        return bool(self.__send_and_recv_msg(msg))

    def alive(self):
        if select([self.socket], [], [], 0)[0]:
            return False
        return True

    def close(self):
        self.socket.shutdown(socket.SHUT_RDWR)
        self.socket.close()
        self.socket = None


class ArchipelagoPoolClient(PoolClient):
    """Archipelago connection pool client

    The class can be instantiated without any argument, the default
    configuration file which is used is '/etc/archipelago/archipelago.conf':

        pool = ArchipelagoPoolClient()

    or using another configuration file:

        pool = ArchipelagoPoolClient(conffile='local.conf')

    or using another connection endpoint for the connection pooler:

        pool = ArchipelagoPoolClient(endpoint='poold.socket')

        or

        pool = ArchipelagoPoolClient(conffile='local.conf',
                                     endpoint='poold.socket')

    or using a set of keyword arguments describing the full segment
    characteristics:

        pool = ArchipelagoPoolClient(segtype='posix', segname='archipelago',
                                     dynports=1024, ports=2048, segsize=2048,
                                     segalign=12)

    The basic segment parameters are:

    - *segname*: the segment name
    - *segtype*: the segment type
    - *dynports*: the dynamic ports range
    - *ports*: the total ports range
    - *segsize*: the segmen size
    - *segalign*: the segment alignment

    Any other keyword parameter will be passed to the underlying client
    libraries: the list of supported parameters depends on the library version.

    The following functionality is provided:

    - Connect to connection pooler

        pool.connect()

    - Get an Archipelago port

        portctx = pool.get_port()

    - Return Archipelago port back to connection pool

        pool.leave_port(portctx)

    - Check if connection is alive

        pool.alive()

    - Return all ports the instantiated object holds back to the
      connection pool

        pool.leave_all_ports()

    """
    def __init__(self, conffile=None, endpoint=None, segname=None, # NOQA
                 segtype=None, dynports=None, ports=None, segsize=None,
                 segalign=None, **kwargs):
        self.__segargs = ['segname', 'segtype', 'dynports', 'ports', 'segsize',
                          'segalign']
        self.__segment = None
        self.__xsegctx = dict()
        self.conffile = conffile

        items = []
        if segname is not None:
            items.append(('segname', segname))
        if segtype is not None:
            items.append(('segtype', segtype))
        if dynports is not None:
            items.append(('dynports', dynports))
        if ports is not None:
            items.append(('ports', ports))
        if segsize is not None:
            items.append(('segsize', segsize))
        if segalign is not None:
            items.append(('segalign', segalign))

        items.extend([k, v] for (k, v) in kwargs.iteritems() if v is not None)

        if conffile is not None and items:
            raise TypeError(
                "'%s' is an invalid keyword argument when the conffile is "
                "specified" % items[0][0])

        if conffile is None:
            if not items:
                self.conffile = '/etc/archipelago/archipelago.conf'
                self.__parse_conffile()
            else:
                createargs = {k: v for (k, v) in items if k in self.__segargs}
                for k in self.__segargs:
                    if k not in createargs:
                        raise TypeError("'%s' argument is missing" % k)
                self.__create_segment(**createargs)
        else:
            self.__parse_conffile()

        if endpoint:
            super(ArchipelagoPoolClient, self).__init__(endpoint=endpoint)
        else:
            super(ArchipelagoPoolClient, self).__init__()

    def __parse_conffile(self):
        cfg = ConfigParser.ConfigParser()
        cfg.readfp(open(self.conffile))
        try:
            segtype = cfg.get('xseg', 'segment_type')
        except ConfigParser.NoOptionError:
            segtype = 'posix'
        try:
            segname = cfg.get('xseg', 'segment_name')
        except ConfigParser.NoOptionError:
            segname = 'archipelago'
        try:
            segalign = cfg.get('xseg', 'segment_alignment')
        except ConfigParser.NoOptionError:
            segalign = 12
        dynports = cfg.getint('xseg', 'segment_dynports')
        ports = cfg.getint('xseg', 'segment_ports')
        segsize = cfg.getint('xseg', 'segment_size')

        self.__create_segment(segtype, segname, dynports, ports, segsize,
                              segalign)

    def __create_segment(self, segtype=None, segname=None, dynports=None,
                         ports=None, segsize=None, segalign=None):
        if dynports >= ports:
            raise TypeError("Wrong dynports or ports argument.")
        self.__segment = Segment(segtype, segname, dynports, ports, segsize,
                                 segalign)

    def connect(self):
        """Connect to Archipelago connection pooler"""
        super(ArchipelagoPoolClient, self).connect()

    def get_port(self):
        """Retrieve an Archipelago port

        :returns: a new Archipelago port on success, None on fail
        """
        portno = super(ArchipelagoPoolClient, self).get_port()
        if portno != -1:
            xsegctx = Xseg_ctx(self.__segment, portno)
            self.__xsegctx[xsegctx] = portno
            return xsegctx
        return None

    def leave_port(self, port):
        """Return Archipelago port back to connection pool

        :param xsegctx: the port to return to connection pool

        :returns: True on success, False on fail

        :raises: Exception
        """
        if isinstance(port, Xseg_ctx) and port in self.__xsegctx:
            portno = self.__xsegctx[port]
            port.shutdown()
            del self.__xsegctx[port]
            return super(ArchipelagoPoolClient, self).leave_port(portno)
        raise TypeError('Wrong port context.')

    def leave_all_ports(self):
        """Return all retrieved Archipelago ports back to connection pool

        :returns: True on success, False on fail
        """
        for xsegctx in self.__xsegctx.keys():
            xsegctx.shutdown()
        self.__xsegctx.clear()
        return super(ArchipelagoPoolClient, self).leave_all_ports()

    def alive(self):
        """Check if connection is alive

        :returns: True on success, False on fail
        """
        return super(ArchipelagoPoolClient, self).alive()

    def close(self):
        """Close connection to Archipelago connection pooler"""
        # Try to leave all ports before closing
        self.leave_all_ports()
        super(ArchipelagoPoolClient, self).close()
