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
import argparse
from .common import *


def vlmc_parser():
    import vlmc
    parser = argparse.ArgumentParser(description='vlmc tool')
    parser.add_argument('-c', '--config', type=str, nargs='?',
                        help='config file')
    subparsers = parser.add_subparsers()

    create_parser = subparsers.add_parser('create', help='Create volume')
    #group = create_parser.add_mutually_exclusive_group(required=True)
    create_parser.add_argument('-s', '--size', type=int, nargs='?',
                               help='requested size in MB for create')
    create_parser.add_argument('--snap', type=str, nargs='?',
                               help='create from snapshot')
    create_parser.add_argument('-v0', '--assume_v0',  action='store_true',
                               default=False,
                               help='Assume snapshot as version 0 if necessary')
    create_parser.add_argument('--v0_size', type=int, nargs='?', default=-1,
                               help='Size of snapshot to be assumed, if found as version 0.')
    create_parser.add_argument('name', type=str,  help='volume/device name')
    create_parser.set_defaults(func=vlmc.create)

    remove_parser = subparsers.add_parser('remove', help='Delete volume')
    remove_parser.add_argument('name', type=str,  help='volume/device name')
    remove_parser.add_argument('-v0', '--assume_v0',  action='store_true',
                               default=False,
                               help='Assume target volume as version 0 if necessary')
    remove_parser.add_argument('--v0_size', type=int, nargs='?', default=-1,
                               help='Size of target volume to be assumed, if found as version 0.')
    remove_parser.set_defaults(func=vlmc.remove)

    rm_parser = subparsers.add_parser('rm', help='Delete volume')
    rm_parser.add_argument('name', type=str,  help='volume/device name')
    rm_parser.set_defaults(func=vlmc.remove)

    map_parser = subparsers.add_parser('map', help='Map volume')
    map_parser.add_argument('name', type=str,  help='volume/device name')
    map_parser.add_argument('-v0', '--assume_v0',  action='store_true',
                               default=False,
                               help='Assume target volume as version 0 if necessary')
    map_parser.add_argument('--v0_size', type=int, nargs='?', default=-1,
                               help='Size of target volume to be assumed, if found as version 0.')
    map_parser.add_argument('-ro', '--readonly',  action='store_true',
                               default=False, help='Map target as readonly')
    map_parser.set_defaults(func=vlmc.map_volume)

    unmap_parser = subparsers.add_parser('unmap', help='Unmap volume')
    unmap_parser.add_argument('name', type=str,  help='volume/device name')
    unmap_parser.set_defaults(func=vlmc.unmap_volume)

    showmapped_parser = subparsers.add_parser('showmapped',
                                              help='Show mapped volumes')
    showmapped_parser.set_defaults(func=vlmc.showmapped_wrapper)

    list_parser = subparsers.add_parser('list', help='List volumes')
    list_parser.set_defaults(func=vlmc.list_volumes)

    snapshot_parser = subparsers.add_parser('snapshot', help='snapshot volume')
    #group = snapshot_parser.add_mutually_exclusive_group(required=True)
    snapshot_parser.add_argument('name', type=str,  help='volume name')
    snapshot_parser.add_argument('snap_name', type=str,  help='Snapshot name')
    snapshot_parser.add_argument('-v0', '--assume_v0',  action='store_true',
                               default=False,
                               help='Assume target volume as version 0 if necessary')
    snapshot_parser.add_argument('--v0_size', type=int, nargs='?', default=-1,
                               help='Size of target volume to be assumed, if found as version 0.')
    snapshot_parser.set_defaults(func=vlmc.snapshot)

    rename_parser = subparsers.add_parser('rename', help='rename volume')
    #group = rename_parser.add_mutually_exclusive_group(required=True)
    rename_parser.add_argument('name', type=str,  help='volume name')
    rename_parser.add_argument('newname', type=str,  help='new name')
    rename_parser.add_argument('-v0', '--assume_v0',  action='store_true',
                               default=False,
                               help='Assume target volume as version 0 if necessary')
    rename_parser.add_argument('--v0_size', type=int, nargs='?', default=-1,
                               help='Size of target volume to be assumed, if found as version 0.')
    rename_parser.set_defaults(func=vlmc.rename)

    ls_parser = subparsers.add_parser('ls', help='List volumes')
    ls_parser.set_defaults(func=vlmc.list_volumes)

    resize_parser = subparsers.add_parser('resize', help='Resize volume')
    resize_parser.add_argument('-s', '--size', type=int,
                               help='requested size in MB for resize')
    resize_parser.add_argument('name', type=str,  help='volume/device name')
    resize_parser.add_argument('-v0', '--assume_v0',  action='store_true',
                               default=False,
                               help='Assume target volume as version 0 if necessary')
    resize_parser.add_argument('--v0_size', type=int, nargs='?', default=-1,
                               help='Size of target volume to be assumed, if found as version 0.')
    resize_parser.set_defaults(func=vlmc.resize)

    open_parser = subparsers.add_parser('open', help='open volume')
    open_parser.add_argument('name', type=str,  help='volume/device name')
    open_parser.add_argument('-v0', '--assume_v0',  action='store_true',
                               default=False,
                               help='Assume target volume as version 0 if necessary')
    open_parser.add_argument('--v0_size', type=int, nargs='?', default=-1,
                               help='Size of target volume to be assumed, if found as version 0.')
    open_parser.set_defaults(func=vlmc.open_volume)

    close_parser = subparsers.add_parser('close', help='close volume')
    close_parser.add_argument('name', type=str,  help='volume/device name')
    close_parser.add_argument('-v0', '--assume_v0',  action='store_true',
                               default=False,
                               help='Assume target volume as version 0 if necessary')
    close_parser.add_argument('--v0_size', type=int, nargs='?', default=-1,
                               help='Size of target volume to be assumed, if found as version 0.')
    close_parser.set_defaults(func=vlmc.close_volume)

    lock_parser = subparsers.add_parser('lock', help='lock volume')
    lock_parser.add_argument('name', type=str,  help='volume/device name')
    lock_parser.set_defaults(func=vlmc.lock)

    unlock_parser = subparsers.add_parser('unlock', help='unlock volume')
    unlock_parser.add_argument('name', type=str,  help='volume/device name')
    unlock_parser.add_argument('-f', '--force',  action='store_true',
                               default=False, help='break lock')
    unlock_parser.set_defaults(func=vlmc.unlock)

    info_parser = subparsers.add_parser('info', help='Show volume info')
    info_parser.add_argument('name', type=str,  help='volume name')
    info_parser.add_argument('-v0', '--assume_v0',  action='store_true',
                               default=False,
                               help='Assume target volume as version 0 if necessary')
    info_parser.add_argument('--v0_size', type=int, nargs='?', default=-1,
                               help='Size of target volume to be assumed, if found as version 0.')
    info_parser.set_defaults(func=vlmc.info)

#    map_info_parser = subparsers.add_parser('mapinfo',
#                                            help='Show volume map_info')
#    map_info_parser.add_argument('name', type=str,  help='volume name')
#    map_info_parser.set_defaults(func=vlmc.mapinfo)
#    map_info_parser.add_argument('-v', '--verbose',  action='store_true',
#                                 default=False, help='')

    hash_parser = subparsers.add_parser('hash', help='Hash snapshot')
    #group = hash_parser.add_mutually_exclusive_group(required=True)
    hash_parser.add_argument('name', type=str,  help='Snapshot name')
    hash_parser.add_argument('-v0', '--assume_v0',  action='store_true',
                               default=False,
                               help='Assume target volume as version 0 if necessary')
    hash_parser.add_argument('--v0_size', type=int, nargs='?', default=-1,
                               help='Size of target volume to be assumed, if found as version 0.')
    hash_parser.set_defaults(func=vlmc.hash)

    return parser


def archipelago_parser():
    import archipelago
    parser = argparse.ArgumentParser(description='Archipelago tool')
    parser.add_argument('-c', '--config', type=str, nargs='?',
                        help='config file')
    subparsers = parser.add_subparsers()

    start_parser = subparsers.add_parser('start', help='Start archipelago')
    start_parser.set_defaults(func=archipelago.start)
    start_parser.add_argument('role', type=str, nargs='?',
                              help='peer to start')

    stop_parser = subparsers.add_parser('stop', help='Stop archipelago')
    stop_parser.set_defaults(func=archipelago.stop)
    stop_parser.add_argument('role', type=str, nargs='?', help='peer to stop')
    stop_parser.add_argument('-f', '--force',  action='store_true', default=False,
                        help='Stop archipelago even if mapped volumes exist')

    status_parser = subparsers.add_parser('status', help='Archipelago status')
    status_parser.set_defaults(func=archipelago.status)

    restart_parser = subparsers.add_parser('restart',
                                           help='Restart archipelago')
    restart_parser.set_defaults(func=archipelago.restart)
    restart_parser.add_argument('role', type=str, nargs='?',
                                help='peer to restart')

    return parser


def main():
    # parse arguments and discpatch to the correct func
    try:
        parser_func = {
            'archipelago': archipelago_parser,
            'vlmc': vlmc_parser,
        }[os.path.basename(sys.argv[0])]
        parser = parser_func()
    except Exception as e:
        sys.stderr.write("Invalid basename\n")
        return -1

    try:
        args = parser.parse_args()
        loadrc(args.config)
        kwargs = vars(args)
        # if parser_func == archipelago_parser:
            # peers = construct_peers()
        if parser_func == vlmc_parser:
            if config['BLKTAP_ENABLED'] is False:
                print red("Blktap module is disabled.")
                return -1
            os.umask(config['UMASK'])

        args.func(cli=True, **kwargs)
        return 0
    except Error as e:
        print red(e)
        return -1
