#!/usr/bin/env python

# Copyright 2012 GRNET S.A. All rights reserved.
#
# Redistribution and use in source and binary forms, with or
# without modification, are permitted provided that the following
# conditions are met:
#
#   1. Redistributions of source code must retain the above
#      copyright notice, this list of conditions and the following
#      disclaimer.
#   2. Redistributions in binary form must reproduce the above
#      copyright notice, this list of conditions and the following
#      disclaimer in the documentation and/or other materials
#      provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY GRNET S.A. ``AS IS'' AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL GRNET S.A OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
# USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and
# documentation are those of the authors and should not be
# interpreted as representing official policies, either expressed
# or implied, of GRNET S.A.
#


from xseg.xseg_api import *
from xseg.xprotocol import *
from ctypes import CFUNCTYPE, cast, c_void_p, addressof, string_at, memmove, \
    create_string_buffer, pointer, sizeof, POINTER, byref

cb_null_ptrtype = CFUNCTYPE(None, uint32_t)

import os
import sys
import time
import psutil
import errno
from subprocess import check_call
from collections import namedtuple

#archipelago peer roles. Order matters!
roles = ['blockerb', 'blockerm', 'mapperd', 'vlmcd']
Peer = namedtuple('Peer', ['executable', 'opts', 'role'])

peers = dict()
xsegbd_args = []
modules = ['xseg', 'segdev', 'xseg_posix', 'xseg_pthread', 'xseg_segdev']
xsegbd = 'xsegbd'

DEFAULTS = '/etc/default/archipelago'

#system defaults
ARCHIP_PREFIX = 'archip_'
LOG_SUFFIX = '.log'
PID_SUFFIX = '.pid'
PIDFILE_PATH = "/var/run/archipelago"
VLMC_LOCK_FILE = 'vlmc.lock'
LOGS_PATH = "/var/log/archipelago"
LOCK_PATH = "/var/lock"
DEVICE_PREFIX = "/dev/xsegbd"
XSEGBD_SYSFS = "/sys/bus/xsegbd/"

CHARDEV_NAME = "/dev/segdev"
CHARDEV_MAJOR = 60
CHARDEV_MINOR = 0

REQS = 512

FILE_BLOCKER = 'mt-pfiled'
RADOS_BLOCKER = 'mt-sosd'
MAPPER = 'mt-mapperd'
VLMC = 'st-vlmcd'
BLOCKER = ''

available_storage = {'files': FILE_BLOCKER, 'rados': RADOS_BLOCKER}


config = {
    'CEPH_CONF_FILE': '/etc/ceph/ceph.conf',
    'XSEGBD_START': 0,
    'XSEGBD_END': 499,
    'VPORT_START': 500,
    'VPORT_END': 999,
    'BPORT': 1000,
    'MPORT': 1001,
    'MBPORT': 1002,
    'VTOOL': 1003,
    #RESERVED 1023
    #default config
    'SPEC': "segdev:xsegbd:1024:5120:12",
    'NR_OPS_BLOCKERB': "",
    'NR_OPS_BLOCKERM': "",
    'NR_OPS_VLMC': "",
    'NR_OPS_MAPPER': "",
    #'VERBOSITY_BLOCKERB': "",
    #'VERBOSITY_BLOCKERM': "",
    #'VERBOSITY_MAPPER': "",
    #'VERBOSITY_VLMC': "",
    #mt-pfiled specific options,
    'FILED_IMAGES': "",
    'FILED_MAPS': "",
    'PITHOS': "",
    'PITHOSMAPS': "",
    #mt-sosd specific options,
    'RADOS_POOL_MAPS': "",
    'RADOS_POOL_BLOCKS': ""
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


def check_conf():
    def isExec(file_path):
        return os.path.isfile(file_path) and os.access(file_path, os.X_OK)

    def validExec(program):
        for path in os.environ["PATH"].split(os.pathsep):
            exe_file = os.path.join(path, program)
            if isExec(exe_file):
                return True
        return False

    def validPort(port, limit, name):
        try:
            if int(port) >= limit:
                print red(str(port) + " >= " + limit)
                return False
        except:
            print red("Invalid port "+name+" : " + str(port))
            return False

        return True

    if not LOGS_PATH:
        print red("LOGS_PATH is not set")
        return False
    if not PIDFILE_PATH:
        print red("PIDFILE_PATH is not set")
        return False

    try:
        if not os.path.isdir(str(LOGS_PATH)):
            print red("LOGS_PATH "+str(LOGS_PATH)+" does not exist")
            return False
    except:
        print red("LOGS_PATH doesn't exist or is not a directory")
        return False

    try:
        os.makedirs(str(PIDFILE_PATH))
    except OSError as e:
        if e.errno == errno.EEXIST:
            if os.path.isdir(str(PIDFILE_PATH)):
                pass
            else:
                print red(str(PIDFILE_PATH) + " is not a directory")
                return False
        else:
            print red("Cannot create " + str(PIDFILE_PATH))
            return False
    except:
        print red("PIDFILE_PATH is not set")
        return False

    splitted_spec = str(config['SPEC']).split(':')
    if len(splitted_spec) < 5:
        print red("Invalid spec")
        return False

    xseg_type = splitted_spec[0]
    xseg_name = splitted_spec[1]
    xseg_ports = int(splitted_spec[2])
    xseg_heapsize = int(splitted_spec[3])
    xseg_align = int(splitted_spec[4])

    if xseg_type != "segdev":
        print red("Segment type not segdev")
        return False
    if xseg_name != "xsegbd":
        print red("Segment name not equal xsegbd")
        return False
    if xseg_align != 12:
        print red("Wrong alignemt")
        return False

    for v in [config['VERBOSITY_BLOCKERB'],
              config['VERBOSITY_BLOCKERM'],
              config['VERBOSITY_MAPPER'],
              config['VERBOSITY_VLMC']
              ]:
        if v is None:
            print red("Verbosity missing")
        try:
            if (int(v) > 3 or int(v) < 0):
                print red("Invalid verbosity " + str(v))
                return False
        except:
            print red("Invalid verbosity " + str(v))
            return False

    for n in [config['NR_OPS_BLOCKERB'],
              config['NR_OPS_BLOCKERM'],
              config['NR_OPS_VLMC'],
              config['NR_OPS_MAPPER']
              ]:
        if n is None:
            print red("Nr ops missing")
        try:
            if (int(n) <= 0):
                print red("Invalid nr_ops " + str(n))
                return False
        except:
            print red("Invalid nr_ops " + str(n))
            return False

    if not validPort(config['VTOOL'], xseg_ports, "VTOOL"):
        return False
    if not validPort(config['MPORT'], xseg_ports, "MPORT"):
        return False
    if not validPort(config['BPORT'], xseg_ports, "BPORT"):
        return False
    if not validPort(config['MBPORT'], xseg_ports, "MBPORT"):
        return False
    if not validPort(config['VPORT_START'], xseg_ports, "VPORT_START"):
        return False
    if not validPort(config['VPORT_END'], xseg_ports, "VPORT_END"):
        return False
    if not validPort(config['XSEGBD_START'], xseg_ports, "XSEGBD_START"):
        return False
    if not validPort(config['XSEGBD_END'], xseg_ports, "XSEGBD_END"):
        return False

    if not config['XSEGBD_START'] < config['XSEGBD_END']:
        print red("XSEGBD_START should be less than XSEGBD_END")
        return False
    if not config['VPORT_START'] < config['VPORT_END']:
        print red("VPORT_START should be less than VPORT_END")
        return False
#TODO check than no other port is set in the above ranges

    global BLOCKER
    try:
        BLOCKER = available_storage[str(config['STORAGE'])]
    except:
        print red("Invalid storage " + str(config['STORAGE']))
        print "Available storage: \"" + ', "'.join(available_storage) + "\""
        return False

    if config['STORAGE'] == "files":
        if config['FILED_IMAGES'] and not \
                os.path.isdir(str(config['FILED_IMAGES'])):
            print red("FILED_IMAGES invalid")
            return False
        if config['FILED_MAPS'] and not \
                os.path.isdir(str(config['FILED_MAPS'])):
            print red("FILED_PATH invalid")
            return False
        if config['PITHOS'] and not os.path.isdir(str(config['PITHOS'])):
            print red("PITHOS invalid ")
            return False
        if config['PITHOSMAPS'] and not \
                os.path.isdir(str(config['PITHOSMAPS'])):
            print red("PITHOSMAPS invalid")
            return False
    elif config['STORAGE'] == "RADOS":
        #TODO use rados.py to check for pool existance
        pass

    for p in [BLOCKER, MAPPER, VLMC]:
        if not validExec(p):
            print red(p + "is not a valid executable")
            return False

    return True


def construct_peers():
    #these must be in sync with roles
    executables = dict()
    config_opts = dict()
    executables['blockerb'] = BLOCKER
    executables['blockerm'] = BLOCKER
    executables['mapperd'] = MAPPER
    executables['vlmcd'] = VLMC

    if BLOCKER == "pfiled":
        config_opts['blockerb'] = [
            "-p", str(config['BPORT']), "-g",
            str(config['SPEC']).encode(), "-n",
            str(config['NR_OPS_BLOCKERB']),
            str(config['PITHOS']), str(config['FILED_IMAGES']), "-d",
            "-f", os.path.join(PIDFILE_PATH, "blockerb" + PID_SUFFIX)
        ]
        config_opts['blockerm'] = [
            "-p", str(config['MBPORT']), "-g",
            str(config['SPEC']).encode(), "-n",
            str(config['NR_OPS_BLOCKERM']),
            str(config['PITHOSMAPS']), str(config['FILED_MAPS']), "-d",
            "-f", os.path.join(PIDFILE_PATH, "blockerm" + PID_SUFFIX)
        ]
    elif BLOCKER == "mt-sosd":
        config_opts['blockerb'] = [
            "-p", str(config['BPORT']), "-g",
            str(config['SPEC']).encode(), "-n",
            str(config['NR_OPS_BLOCKERB']),
            "--pool", str(config['RADOS_POOL_BLOCKS']), "-v",
            str(config['VERBOSITY_BLOCKERB']),
            "-d",
            "--pidfile", os.path.join(PIDFILE_PATH, "blockerb" + PID_SUFFIX),
            "-l", os.path.join(str(LOGS_PATH), "blockerb" + LOG_SUFFIX),
            "-t", "3"
        ]
        config_opts['blockerm'] = [
            "-p", str(config['MBPORT']), "-g",
            str(config['SPEC']).encode(), "-n",
            str(config['NR_OPS_BLOCKERM']),
            "--pool", str(config['RADOS_POOL_MAPS']), "-v",
            str(config['VERBOSITY_BLOCKERM']),
            "-d",
            "--pidfile", os.path.join(PIDFILE_PATH, "blockerm" + PID_SUFFIX),
            "-l", os.path.join(str(LOGS_PATH), "blockerm" + LOG_SUFFIX),
            "-t", "3"
        ]
    elif BLOCKER == "mt-pfiled":
        config_opts['blockerb'] = [
            "-p", str(config['BPORT']), "-g",
            str(config['SPEC']).encode(), "-n",
            str(config['NR_OPS_BLOCKERB']),
            "--pithos", str(config['PITHOS']), "--archip",
            str(config['FILED_IMAGES']),
            "-v", str(config['VERBOSITY_BLOCKERB']),
            "-d",
            "--pidfile", os.path.join(PIDFILE_PATH, "blockerb" + PID_SUFFIX),
            "-l", os.path.join(str(LOGS_PATH), "blockerb" + LOG_SUFFIX),
            "-t", str(config['NR_OPS_BLOCKERB']), "--prefix", ARCHIP_PREFIX
        ]
        config_opts['blockerm'] = [
            "-p", str(config['MBPORT']), "-g",
            str(config['SPEC']).encode(), "-n",
            str(config['NR_OPS_BLOCKERM']),
            "--pithos", str(config['PITHOSMAPS']), "--archip",
            str(config['FILED_MAPS']),
            "-v", str(config['VERBOSITY_BLOCKERM']),
            "-d",
            "--pidfile", os.path.join(PIDFILE_PATH, "blockerm" + PID_SUFFIX),
            "-l", os.path.join(str(LOGS_PATH), "blockerm" + LOG_SUFFIX),
            "-t", str(config['NR_OPS_BLOCKERM']), "--prefix", ARCHIP_PREFIX
        ]
    else:
            sys.exit(-1)

    config_opts['mapperd'] = [
        "-t", "1", "-p",  str(config['MPORT']), "-mbp",
        str(config['MBPORT']),
        "-g", str(config['SPEC']).encode(), "-n",
        str(config['NR_OPS_MAPPER']), "-bp", str(config['BPORT']),
        "--pidfile", os.path.join(PIDFILE_PATH, "mapperd" + PID_SUFFIX),
        "-v", str(config['VERBOSITY_MAPPER']), "-d",
        "-l", os.path.join(str(LOGS_PATH), "mapperd" + LOG_SUFFIX)
    ]
    config_opts['vlmcd'] = [
        "-t", "1", "-sp",  str(config['VPORT_START']), "-ep",
        str(config['VPORT_END']),
        "-g", str(config['SPEC']).encode(), "-n",
        str(config['NR_OPS_VLMC']), "-bp", str(config['BPORT']),
        "-mp", str(config['MPORT']), "-d", "-v",
        str(config['VERBOSITY_VLMC']),
        "--pidfile", os.path.join(PIDFILE_PATH, "vlmcd" + PID_SUFFIX),
        "-l", os.path.join(str(LOGS_PATH), "vlmcd" + LOG_SUFFIX)
    ]

    for r in roles:
        peers[r] = Peer(executable=executables[r], opts=config_opts[r],
                        role=r)

    return peers


def exclusive(fn):
    def exclusive_args(**kwargs):
        if not os.path.exists(LOCK_PATH):
            try:
                os.mkdir(LOCK_PATH)
            except OSError, (err, reason):
                print >> sys.stderr, reason
        if not os.path.isdir(LOCK_PATH):
            sys.stderr.write("Locking error: ")
            print >> sys.stderr, LOCK_PATH + " is not a directory"
            return -1
        lock_file = os.path.join(LOCK_PATH, VLMC_LOCK_FILE)
        while True:
            try:
                fd = os.open(lock_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                break
            except OSError, (err, reason):
                print >> sys.stderr, reason
                if err == errno.EEXIST:
                    time.sleep(0.2)
                else:
                    raise OSError(err, lock_file + ' ' + reason)
        try:
            r = fn(**kwargs)
        finally:
            os.close(fd)
            os.unlink(lock_file)
        return r

    return exclusive_args


def loadrc(rc):
    try:
        if rc is None:
            execfile(os.path.expanduser(DEFAULTS), config)
        else:
            execfile(rc, config)
    except:
        raise Error("Cannot read config file")

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


def create_segment():
    #fixme blocking....
    initialize_xseg()
    xconf = xseg_config()
    xseg_parse_spec(str(config['SPEC']), xconf)
    r = xseg_create(xconf)
    if r < 0:
        raise Error("Cannot create segment")


def destroy_segment():
    #fixme blocking....
    try:
        initialize_xseg()
        xconf = xseg_config()
        xseg_parse_spec(str(config['SPEC']), xconf)
        xseg = xseg_join(xconf.type, xconf.name, "posix",
                         cast(0, cb_null_ptrtype))
        if not xseg:
            raise Error("Cannot join segment")
        xseg_leave(xseg)
        xseg_destroy(xseg)
    except Exception:
        raise Error("Cannot destroy segment")


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

    def __init__(self, spec, portno):
        initialize_xseg()
        xconf = xseg_config()
        xseg_parse_spec(create_string_buffer(spec), xconf)
        ctx = xseg_join(xconf.type, xconf.name, "posix",
                        cast(0, cb_null_ptrtype))
        if not ctx:
            raise Error("Cannot join segment")
        port = xseg_bind_port(ctx, portno, c_void_p(0))
        if not port:
            raise Error("Cannot bind to port")
        xseg_init_local_signal(ctx, portno)
        self.ctx = ctx
        self.port = port
        self.portno = portno

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
        if self.ctx:
            xseg_quit_local_signal(self.ctx, self.portno)
            xseg_leave(self.ctx)
        self.ctx = None


class Request(object):
    xseg_ctx = None
    req = None

    def __init__(self, xseg_ctx, dst_portno, targetlen, datalen):
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
#        print hex(addressof(req.contents))
        self.req = req
        self.xseg_ctx = xseg_ctx
        return

    def __del__(self):
        if self.req:
            if xq_count(byref(self.req.contents.path)) == 0:
                xseg_put_request(self.xseg_ctx.ctx, self.req,
                                 self.xseg_ctx.portno)
        self.req = None
        return False

    def __enter__(self):
        if not self.req:
            raise Error("xseg request not set")
        return self

    def __exit__(self, type_, value, traceback):
        if self.req:
            if xq_count(byref(self.req.contents.path)) == 0:
                xseg_put_request(self.xseg_ctx.ctx, self.req,
                                 self.xseg_ctx.portno)
        self.req = None
        return False

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
        if sizeof(data) != self.req.contents.datalen:
            return False
        c_data = xseg_get_data_nonstatic(self.xseg_ctx.ctx, self.req)
        p_data = pointer(data)
        memmove(c_data, p_data, self.req.contents.datalen)

        return True

    def get_data(self, _type):
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
        while True:
            received = xseg_receive(self.xseg_ctx.ctx, self.xseg_ctx.portno, 0)
            if received:
#                print addressof(cast(self.req, c_void_p))
#                print addressof(cast(received, c_void_p))
#                print addressof(self.req.contents)
#                print addressof(received.contents)
                if addressof(received.contents) == \
                        addressof(self.req.contents):
#                if addressof(cast(received, c_void_p)) == \
#                        addressof(cast(self.req, c_void_p)):
                    break
                else:
                    p = xseg_respond(self.xseg_ctx.ctx, received,
                                     self.xseg_ctx.portno, X_ALLOC)
                    if p == NoPort:
                        xseg_put_request(self.xseg_ctx.ctx, received,
                                         self.xseg_ctx.portno)
                    else:
                        xseg_signal(self.xseg_ctx.ctx, p)
            else:
                xseg_prepare_wait(self.xseg_ctx.ctx, self.xseg_ctx.portno)
                xseg_wait_signal(self.xseg_ctx.ctx, 10000000)
                xseg_cancel_wait(self.xseg_ctx.ctx, self.xseg_ctx.portno)
        return True

    def success(self):
        return bool((self.req.contents.state & XS_SERVED) and not
                   (self.req.contents.state & XS_FAILED))
