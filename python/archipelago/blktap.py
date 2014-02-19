# Copyright 2014 GRNET S.A. All rights reserved.
#
# Redistribution and use in source and binary forms, with or
# without modification, are permitted provided that the following
# conditions are met:
#
#   1. Redistributions of source code must retain the above
#      copyright notice, this list of conditions and the following
#      disclaimer.
#
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
import os
import subprocess


def cmd_open(cmd, bufsize=-1, env=None):
    inst = subprocess.Popen(cmd, shell=True, bufsize=bufsize,
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, close_fds=True)
    return inst

def doexec(args, inputtext=None):
    proc = cmd_open(" ".join(args))
    if inputtext != None:
        proc.stdin.write(inputtext)
    stdout = proc.stdout
    stderr = proc.stderr
    rc = proc.wait()
    return (rc, stdout, stderr)

class VlmcTapdiskException(Exception):
    pass

class VlmcTapdisk(object):
    '''Tapdisk operations'''
    TAP_CTL = 'tap-ctl'
    TAP_DEV = '/dev/xen/blktap-2/tapdev'

    class Tapdisk(object):
        def __init__(self, pid=None, minor=-1, state=None, volume=None,
                     device=None):
            self.pid = pid
            self.minor = minor
            self.state = state
            self.volume = volume
            self.device = device

        def __str__(self):
            return 'volume=%s pid=%s minor=%s state=%s device=%s' \
                    % (self.volume, self.pid, self.minor, self.state, self.device)

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
                key, value = pair.split('=')
                if key == 'pid':
                    tapdisk.pid = value
                elif key == 'minor':
                    tapdisk.minor = int(value)
                    if tapdisk.minor >= 0:
                        tapdisk.device = '%s%s' % \
                                        (VlmcTapdisk.TAP_DEV, tapdisk.minor)
                elif key == 'state':
                    tapdisk.state = value
                elif key == 'args' and value.find(':') != -1:
                    _, tapdisk.volume = value.split(':')

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
    def create(volume):
        return VlmcTapdisk.exc('create', '-a%s:%s' % ('archipelago', volume))

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
            VlmcTapdisk.exc('pause',
                            '-p%s' % tapdisk.pid,
                            '-m%s' % tapdisk.minor)

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
