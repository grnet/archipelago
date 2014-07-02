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


import os
import sys
import time
import errno
from subprocess import check_call

from .common import *
from .vlmc import showmapped as vlmc_showmapped
from .vlmc import get_mapped as vlmc_get_mapped
from blktap import VlmcTapdisk

def start_peer(peer, cli=False):
    if peer.is_running():
        raise Error("Cannot start peer %s. Peer already running" % peer.role)
    if cli:
        s = "Starting %s " % peer.role
        sys.stdout.write(s.ljust(FIRST_COLUMN_WIDTH))
    try:
        peer.start()
    except Error as e:
        if cli:
            sys.stdout.write(red("FAILED".ljust(SECOND_COLUMN_WIDTH)))
            sys.stdout.write("\n")
        raise e
    except Exception as e:
        if cli:
            print e
            sys.stdout.write(red("FAILED".ljust(SECOND_COLUMN_WIDTH)))
            sys.stdout.write("\n")
        raise Error("Cannot start %s" % peer.role)

#TODO configurable
    i = 0
    while not peer.is_running():
        time.sleep(0.1)
        i += 1
        if i > 30: #3secs
            if cli:
                sys.stdout.write(red("FAILED".ljust(SECOND_COLUMN_WIDTH)))
                sys.stdout.write("\n")
            raise Error("Couldn't start %s" % peer.role)

    if cli:
        sys.stdout.write(green("OK".ljust(SECOND_COLUMN_WIDTH)))
        sys.stdout.write("\n")


def stop_peer(peer, cli=False):
    try:
        peer.stop()
    except Error:
        if cli:
            pretty_print(peer.role, yellow("Not running"))
        return
    if cli:
        s = "Stopping %s " % peer.role
        sys.stdout.write(s.ljust(FIRST_COLUMN_WIDTH))

    i = 0
    while peer.get_pid():
        time.sleep(0.1)
        i += 1
        if i > 150:
            if cli:
                sys.stdout.write(red("FAILED".ljust(SECOND_COLUMN_WIDTH)))
                sys.stdout.write("\n")
            raise Error("Failed to stop peer %s." % peer.role)
    if cli:
        sys.stdout.write(green("OK".ljust(SECOND_COLUMN_WIDTH)))
        sys.stdout.write("\n")


def peer_running(peer, cli):
    try:
        if peer.is_running():
            if cli:
                pretty_print(peer.role, green('running'))
            return True
        else:
            if cli:
                pretty_print(peer.role, red('not running'))
            return False
    except Error:
        if cli:
            pretty_print(peer.role, yellow("Has valid pidfile but does not "
                                           "seem to be active"))
        return False


def start_peers(peers, cli=False):
    for r, _ in config['roles']:
        p = peers[r]
        start_peer(p, cli)


def stop_peers(peers, cli=False):
    for r, _ in reversed(config['roles']):
        p = peers[r]
        stop_peer(p, cli)


def start(user=False, role=None, cli=False, **kwargs):
    if role:
        try:
            p = peers[role]
        except KeyError:
            raise Error("Invalid peer %s" % role)
        return start_peer(p, cli)

    if user:
        #get_segment().create()
        start_peers(peers, cli)
        mapped = vlmc_get_mapped()
        if mapped:
            for m in mapped:
                if VlmcTapdisk.is_paused(m.device):
                    VlmcTapdisk.unpause(m.device)
        return

    if status() > 0:
        raise Error("Cannot start. Try stopping first")

    if cli:
        print "===================="
        print "Starting archipelago"
        print "===================="
        print ""
    try:
        #get_segment().create()
        #time.sleep(0.5)
        start_peers(peers, cli)
        load_module("blktap", None)
    except Exception as e:
        if cli:
            print red(e)
        stop(user, role, cli)


def stop(user=False, role=None, cli=False, **kwargs):
    if role:
        try:
            p = peers[role]
        except KeyError:
            raise Error("Invalid peer %s" % role)
        return stop_peer(p, cli)
    if user:
        mapped = vlmc_get_mapped()
        if mapped:
            for m in mapped:
                if not VlmcTapdisk.is_paused(m.device):
                    VlmcTapdisk.pause(m.device)
        stop_peers(peers, cli)
        return get_segment().destroy()
    #check devices
    if cli:
        print "===================="
        print "Stoping archipelago"
        print "===================="
        print ""
    if not loaded_module("blktap"):
        stop_peers(peers, cli)
        time.sleep(0.5)
        get_segment().destroy()
        return

    if cli:
        if vlmc_showmapped() > 0:
            raise Error("Cannot stop archipelago. Mapped volumes exist")
    else:
        mapped = vlmc_get_mapped()
        if mapped and len(mapped) > 0:
            raise Error("Cannot stop archipelago. Mapped volumes exist")
    stop_peers(peers, cli)
    time.sleep(0.5)
    get_segment().destroy()


def status(cli=False, **kwargs):
    r = 0
    if not loaded_module("blktap"):
        for role, _ in reversed(config['roles']):
            p = peers[role]
            if peer_running(p, cli):
                r += 1
        if cli:
            pretty_print("blktap", red('Not loaded'))
        return r

    if cli:
        if vlmc_showmapped() > 0:
            r += 1
    else:
        mapped = vlmc_get_mapped()
        if mapped and len(mapped) > 0:
            r += 1
    if loaded_module("blktap"):
        if cli:
            pretty_print("blktap", green('Loaded'))
        #r += 1
    else:
        if cli:
            pretty_print("blktap", red('Not loaded'))
    for role, _ in reversed(config['roles']):
        p = peers[role]
        if peer_running(p, cli):
            r += 1
    return r


def restart(**kwargs):
    stop(**kwargs)
    start(**kwargs)
