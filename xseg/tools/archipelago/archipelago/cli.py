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


import os, sys, argparse
from .common import *

def vlmc_parser():
    import vlmc
    parser = argparse.ArgumentParser(description='vlmc tool')
    parser.add_argument('-c', '--config', type=str, nargs='?', help='config file')
    subparsers = parser.add_subparsers()

    create_parser = subparsers.add_parser('create', help='Create volume')
    #group = create_parser.add_mutually_exclusive_group(required=True)
    create_parser.add_argument('-s', '--size', type=int, nargs='?', help='requested size in MB for create')
    create_parser.add_argument('--snap', type=str, nargs='?', help='create from snapshot')
    create_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')
    create_parser.add_argument('name', type=str, nargs=1, help='volume/device name')
    create_parser.set_defaults(func=vlmc.create)

    remove_parser = subparsers.add_parser('remove', help='Delete volume')
    remove_parser.add_argument('name', type=str, nargs=1, help='volume/device name')
    remove_parser.set_defaults(func=vlmc.remove)
    remove_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')

    rm_parser = subparsers.add_parser('rm', help='Delete volume')
    rm_parser.add_argument('name', type=str, nargs=1, help='volume/device name')
    rm_parser.set_defaults(func=vlmc.remove)
    rm_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')

    map_parser = subparsers.add_parser('map', help='Map volume')
    map_parser.add_argument('name', type=str, nargs=1, help='volume/device name')
    map_parser.set_defaults(func=vlmc.map_volume)
    map_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')

    unmap_parser = subparsers.add_parser('unmap', help='Unmap volume')
    unmap_parser.add_argument('name', type=str, nargs=1, help='volume/device name')
    unmap_parser.set_defaults(func=vlmc.unmap_volume)
    unmap_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')

    showmapped_parser = subparsers.add_parser('showmapped', help='Show mapped volumes')
    showmapped_parser.set_defaults(func=vlmc.showmapped_wrapper)
    showmapped_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')

    list_parser = subparsers.add_parser('list', help='List volumes')
    list_parser.set_defaults(func=vlmc.list_volumes)
    list_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')

    snapshot_parser = subparsers.add_parser('snapshot', help='snapshot volume')
    #group = snapshot_parser.add_mutually_exclusive_group(required=True)
    snapshot_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')
    snapshot_parser.add_argument('name', type=str, nargs=1, help='volume/device name')
    snapshot_parser.set_defaults(func=vlmc.snapshot)

    ls_parser = subparsers.add_parser('ls', help='List volumes')
    ls_parser.set_defaults(func=vlmc.list_volumes)
    ls_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')

    resize_parser = subparsers.add_parser('resize', help='Resize volume')
    resize_parser.add_argument('-s', '--size', type=int, nargs=1, help='requested size in MB for resize')
    resize_parser.add_argument('name', type=str, nargs=1, help='volume/device name')
    resize_parser.set_defaults(func=vlmc.resize)
    resize_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')

    open_parser = subparsers.add_parser('open', help='open volume')
    open_parser.add_argument('name', type=str, nargs=1, help='volume/device name')
    open_parser.set_defaults(func=vlmc.open_volume)
    open_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')

    close_parser = subparsers.add_parser('close', help='close volume')
    close_parser.add_argument('name', type=str, nargs=1, help='volume/device name')
    close_parser.set_defaults(func=vlmc.close_volume)
    close_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')

    lock_parser = subparsers.add_parser('lock', help='lock volume')
    lock_parser.add_argument('name', type=str, nargs=1, help='volume/device name')
    lock_parser.set_defaults(func=vlmc.lock)
    lock_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')

    unlock_parser = subparsers.add_parser('unlock', help='unlock volume')
    unlock_parser.add_argument('name', type=str, nargs=1, help='volume/device name')
    unlock_parser.add_argument('-f', '--force',  action='store_true', default=False , help='break lock')
    unlock_parser.set_defaults(func=vlmc.unlock)
    unlock_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')

    info_parser = subparsers.add_parser('info', help='Show volume info')
    info_parser.add_argument('name', type=str, nargs=1, help='volume name')
    info_parser.set_defaults(func=vlmc.info)
    info_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')

    map_info_parser = subparsers.add_parser('mapinfo', help='Show volume map_info')
    map_info_parser.add_argument('name', type=str, nargs=1, help='volume name')
    map_info_parser.set_defaults(func=vlmc.mapinfo)
    map_info_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')
    map_info_parser.add_argument('-v', '--verbose',  action='store_true', default=False , help='')

    return parser

def archipelago_parser():
    import archipelago
    parser = argparse.ArgumentParser(description='Archipelago tool')
    parser.add_argument('-c', '--config', type=str, nargs='?', help='config file')
    parser.add_argument('-u', '--user',  action='store_true', default=False , help='affect only userspace peers')
    subparsers = parser.add_subparsers()

    start_parser = subparsers.add_parser('start', help='Start archipelago')
    start_parser.set_defaults(func=archipelago.start)
    start_parser.add_argument('peer', type=str, nargs='?',  help='peer to start')

    stop_parser = subparsers.add_parser('stop', help='Stop archipelago')
    stop_parser.set_defaults(func=archipelago.stop)
    stop_parser.add_argument('peer', type=str, nargs='?', help='peer to stop')

    status_parser = subparsers.add_parser('status', help='Archipelago status')
    status_parser.set_defaults(func=archipelago.status)

    restart_parser = subparsers.add_parser('restart', help='Restart archipelago')
    restart_parser.set_defaults(func=archipelago.restart)
    restart_parser.add_argument('peer', type=str, nargs='?', help='peer to restart')

    return parser

def main():
    # parse arguments and discpatch to the correct func
    try:
        parser_func = {
            'archipelago' : archipelago_parser,
            'vlmc'        : vlmc_parser,
        }[os.path.basename(sys.argv[0])]
        parser = parser_func()
    except Exception as e:
        sys.stderr.write("Invalid basename\n")
        return -1

    args = parser.parse_args()
    loadrc(args.config)
    if parser_func == archipelago_parser:
        peers = construct_peers()
        xsegbd_args = [('start_portno', str(config['XSEGBD_START'])), ('end_portno',
    		str(config['XSEGBD_END']))]
        kwargs=vars(args)
        try:
            args.func(**kwargs)
            return 0
        except Error as e:
            print red(e)
            return -1

    try:
        args.func(args)
        return 0
    except Error as e:
        print red(e)
        return -1
