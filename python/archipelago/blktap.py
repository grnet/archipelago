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
import os
import subprocess

def cmd_open(cmd, bufsize=-1, env=None):
    inst = subprocess.Popen(cmd, shell=False, bufsize=bufsize,
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, close_fds=True)
    return inst


def doexec(args, inputtext=None):
    proc = cmd_open(args)
    if inputtext is not None:
        proc.stdin.write(inputtext)
    stdout = proc.stdout
    stderr = proc.stderr
    rc = proc.wait()
    return (rc, stdout, stderr)

class TDFlags:
    TD_DEAD                 = 0x0001
    TD_CLOSED               = 0x0002
    TD_QUIESCE_REQUESTED    = 0x0004
    TD_QUIESCED             = 0x0008
    TD_PAUSE_REQUESTED      = 0x0010
    TD_PAUSED               = 0x0020
    TD_SHUTDOWN_REQUESTED   = 0x0040
    TD_LOCKING              = 0x0080
    TD_LOG_DROPPED          = 0x0100
    TD_PAUSE_MASK           = TD_PAUSE_REQUESTED|TD_PAUSED


class VlmcTapdiskException(Exception):
    pass


class VlmcTapdisk(object):
    '''Tapdisk operations'''
    TAP_CTL = 'tap-ctl'
    TAP_DEV = '/dev/xen/blktap-2/tapdev'

    class Tapdisk(object):
        def __init__(self, pid=None, minor=-1, state=None, volume=None,
                     device=None, mport=None, vport=None, assume_v0=False,
                     v0_size=-1):
            self.pid = pid
            self.minor = minor
            self.state = state
            self.volume = volume
            self.device = device
            self.mport = mport
            self.vport = vport
            self.assume_v0 = assume_v0
            self.v0_size = v0_size

        def __str__(self):
            return 'volume=%s pid=%s minor=%s state=%s device=%s mport=%s ' \
                   'vport=%s, assume_v0=%s v0_size=%s' \
                    % (self.volume, self.pid, self.minor, self.state,
                       self.device, self.mport, self.vport, self.assume_v0,
                       self.v0_size)

    @staticmethod
    def exc(*args):
        rc, stdout, stderr = doexec([VlmcTapdisk.TAP_CTL] + list(args))
        out, err = stdout.read().strip(), stderr.read().strip()
        stdout.close()
        stderr.close()
        if rc:
            raise VlmcTapdiskException('%s failed (%s %s %s)' % \
                                   (args, rc, out, err))
        return out

    @staticmethod
    def check():
        try:
            VlmcTapdisk.exc('check')
            return 0
        except Exception, e:
            print "'tap-ctl check' failed: %s" % e
            return -1

    @staticmethod
    def list():
        tapdisks = []
        _list = VlmcTapdisk.exc('list')
        if not _list:
            return []

        for line in _list.split('\n'):
            tapdisk = VlmcTapdisk.Tapdisk()

            for pair in line.split():
                key, value = pair.split('=', 1)
                if key == 'pid':
                    tapdisk.pid = value
                elif key == 'minor':
                    tapdisk.minor = int(value)
                    if tapdisk.minor >= 0:
                        tapdisk.device = '%s%s' % \
                                        (VlmcTapdisk.TAP_DEV, tapdisk.minor)
                elif key == 'state':
                    tapdisk.state = int(value, 16)
                elif key == 'args' and value.find(':') != -1:
                    args = value.split(':')
                    tapdisk.volume = args[1]
                    args = args[1:]
                    for arg in args:
                        if arg.startswith('mport='):
                            tapdisk.mport = int(arg[len('mport='):])
                        if arg.startswith('vport='):
                            tapdisk.vport = int(arg[len('vport='):])
                        if arg.startswith('v0_size='):
                            tapdisk.v0_size= int(arg[len('v0_size='):])
                        if arg.startswith('assume_v0'):
                            tapdisk.assume_v0 = True

            tapdisks.append(tapdisk)

        return tapdisks

    @staticmethod
    def fromDevice(device):
        if device.startswith(VlmcTapdisk.TAP_DEV):
            minor = os.minor(os.stat(device).st_rdev)
            tapdisks = filter(lambda x: x.minor == minor, VlmcTapdisk.list())
            if len(tapdisks) == 1:
                return tapdisks[0]
        return None

    @staticmethod
    def create(volume, mport=None, vport=None, assume_v0=False, v0_size=-1,
               readonly=False):
        uri = "%s:%s" % ('archipelago', volume)
        if mport is not None:
            uri = "%s:mport=%s" % (uri, str(mport))
        if vport is not None:
            uri = "%s:vport=%s" % (uri, str(vport))
        if assume_v0:
            uri = "%s:%s" % (uri, 'assume_v0')
            if v0_size != -1:
                uri = "%s:v0_size=%s" % (uri, str(v0_size))

        if readonly:
            return VlmcTapdisk.exc('create', "-a%s" % uri, '-R')
        else:
            return VlmcTapdisk.exc('create', "-a%s" % uri)

    @staticmethod
    def destroy(device):
        tapdisk = VlmcTapdisk.fromDevice(device)
        if tapdisk:
            if tapdisk.pid:
                VlmcTapdisk.exc('destroy',
                                '-p%s' % tapdisk.pid,
                                '-m%s' % tapdisk.minor)
            else:
                VlmcTapdisk.exc('free', '-m%s' % tapdisk.minor)

    @staticmethod
    def pause(device):
        tapdisk = VlmcTapdisk.fromDevice(device)
        if tapdisk and tapdisk.pid:
            VlmcTapdisk.exc('pause',
                            '-p%s' % tapdisk.pid,
                            '-m%s' % tapdisk.minor)

    @staticmethod
    def unpause(device):
        tapdisk = VlmcTapdisk.fromDevice(device)
        if tapdisk and tapdisk.pid:
            VlmcTapdisk.exc('unpause',
                            '-p%s' % tapdisk.pid,
                            '-m%s' % tapdisk.minor)

    @staticmethod
    def stats(device):
        tapdisk = VlmcTapdisk.fromDevice(device)
        if tapdisk and tapdisk.pid:
            import json
            stats = VlmcTapdisk.exc('stats',
                            '-p%s' % tapdisk.pid,
                            '-m%s' % tapdisk.minor)
            return json.loads(stats)
        return None

    @staticmethod
    def busy_pid(device):
        rc, stdout, stderr = doexec(['fuser', device])
        out = stdout.read().strip()
        stderr.close()
        stdout.close()
        return out

    @staticmethod
    def is_mounted(device):
        fd = open("/proc/mounts", "r")
        for line in fd.readlines():
            if device == line.split()[0]:
                return True
        fd.close()
        return False

    @staticmethod
    def is_paused(device):
        tapdisk = VlmcTapdisk.fromDevice(device)
        if tapdisk:
            return not not (tapdisk.state & TDFlags.TD_PAUSED)
        return None

    @staticmethod
    def is_running(device):
        tapdisk = VlmcTapdisk.fromDevice(device)
        if tapdisk:
            return not (tapdisk.state & TDFlags.TD_PAUSE_MASK)
        return None

    @staticmethod
    def query_state(device):
        tapdisk = VlmcTapdisk.fromDevice(device)
        if tapdisk:
            if tapdisk.state & TDFlags.TD_PAUSED:
                return "paused"
            if tapdisk.state & TDFlags.TD_PAUSE_REQUESTED:
                return "pausing"
            return "running"
