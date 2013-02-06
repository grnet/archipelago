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


import os, sys, subprocess, argparse, time, psutil, signal, errno
from subprocess import check_call
from .common import *
from .vlmc import showmapped as vlmc_showmapped

def start_peer(peer):
    if check_pidfile(peer.role) > 0:
        raise Error("Cannot start peer %s. Peer already running" % peer.role)
    cmd = [peer.executable]+ peer.opts
    s = "Starting %s " % peer.role
    sys.stdout.write(s.ljust(FIRST_COLUMN_WIDTH))
    try:
        check_call(cmd, shell=False);
    except Exception as e:
        print e
        sys.stdout.write(red("FAILED".ljust(SECOND_COLUMN_WIDTH)))
        sys.stdout.write("\n")
        raise Error("Cannot start %s" % peer.role)

    pid = check_pidfile(peer.role)
    if pid < 0 or not check_running(peer.executable, pid):
        sys.stdout.write(red("FAILED".ljust(SECOND_COLUMN_WIDTH)))
        sys.stdout.write("\n")
        raise Error("Couldn't start %s" % peer.role)

    sys.stdout.write(green("OK".ljust(SECOND_COLUMN_WIDTH)))
    sys.stdout.write("\n")

def stop_peer(peer):
    pid = check_pidfile(peer.role)
    if pid < 0:
        pretty_print(peer[2], yellow("not running"))
        return

    s = "Stopping %s " % peer.role
    sys.stdout.write(s.ljust(FIRST_COLUMN_WIDTH))
    i = 0
    while check_running(peer.executable, pid):
        os.kill(pid, signal.SIGTERM)
        time.sleep(0.1)
        i += 1
        if i > 150:
            sys.stdout.write(red("FAILED".ljust(SECOND_COLUMN_WIDTH)))
            sys.stdout.write("\n")
            raise Error("Failed to stop peer %s." % peer.role)
    sys.stdout.write(green("OK".ljust(SECOND_COLUMN_WIDTH)))
    sys.stdout.write("\n")

def peer_running(peer):
    pid = check_pidfile(peer.role)
    if pid < 0:
        pretty_print(peer.role, red('not running'))
        return False

    if not check_running(peer.executable, pid):
        pretty_print(peer.role, yellow("Has valid pidfile but does not seem to be active"))
        return False
    pretty_print(peer.role, green('running'))
    return True


def make_segdev():
    try:
        os.stat(str(CHARDEV_NAME))
        raise Error("Segdev already exists")
    except Error as e:
        raise e
    except:
        pass
    cmd = ["mknod", str(CHARDEV_NAME), "c", str(CHARDEV_MAJOR), str(CHARDEV_MINOR)]
    print ' '.join(cmd)
    try:
        check_call(cmd, shell=False);
    except Exception:
        raise Error("Segdev device creation failed.")

def remove_segdev():
    try:
        os.stat(str(CHARDEV_NAME))
    except OSError, (err, reason):
        if err == errno.ENOENT:
            return
        raise OSError(str(CHARDEV_NAME) + ' ' + reason)
    try:
        os.unlink(str(CHARDEV_NAME))
    except:
        raise Error("Segdev device removal failed.")

def start_peers(peers):
    for m in modules:
        if not loaded_module(m):
            raise Error("Cannot start userspace peers. " + m + " module not loaded")
    for r in roles:
        p = peers[r]
        start_peer(p)

def stop_peers(peers):
    for r in reversed(roles):
        p = peers[r]
        stop_peer(p)

def start(args):
    if args.peer:
        try:
            p = peers[args.peer]
        except KeyError:
            raise Error("Invalid peer %s" % str(args.peer))
        return start_peer(p)

    if args.user:
        return start_peers(peers)

    if status(args) > 0:
        raise Error("Cannot start. Try stopping first")

    try:
        for m in modules:
            load_module(m, None)
        time.sleep(0.5)
        make_segdev()
        time.sleep(0.5)
        create_segment()
        time.sleep(0.5)
        start_peers(peers)
        load_module(xsegbd, xsegbd_args)
    except Exception as e:
        print red(e)
        stop(args)
        raise e


def stop(args):
    if args.peer:
        try:
            p = peers[args.peer]
        except KeyError:
            raise Error("Invalid peer %s" % str(args.peer))
        return stop_peer(p)
    if args.user:
        return stop_peers(peers)
    #check devices
    if vlmc_showmapped(args) > 0:
        raise Error("Cannot stop archipelago. Mapped volumes exist")
    unload_module(xsegbd)
    stop_peers(peers)
    remove_segdev()
    for m in reversed(modules):
        unload_module(m)
        time.sleep(0.3)

def status(args):
    r = 0
    if vlmc_showmapped(args) > 0:
        r += 1
    if loaded_module(xsegbd):
        pretty_print(xsegbd, green('Loaded'))
        r += 1
    else:
        pretty_print(xsegbd, red('Not loaded'))
    for m in reversed(modules):
        if loaded_module(m):
            pretty_print(m, green('Loaded'))
            r += 1
        else:
            pretty_print(m, red('Not loaded'))
    for role in reversed(roles):
        p = peers[role]
        if peer_running(p):
            r += 1
    return r

def restart(args):
    stop(args)
    start(args)


