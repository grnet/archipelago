#!/usr/bin/env python2.7
#
# vlmc tool for filed

from vlmc_shared import *
import os, sys, subprocess, argparse

def vlmc_map(args):
    xsegbd_loaded()
    name = args.name[0]
    prev = 0
    try:
        result = [int(open(XSEGBD_SYSFS + "devices/" + f + "/srcport").read().strip()) for f in os.listdir(XSEGBD_SYSFS + "devices/")]
        result.sort()

        for p in result:
            if p - prev > 1:
               break
            else:
               prev = p

        port = prev + 1
        fd = os.open(XSEGBD_SYSFS + "add", os.O_WRONLY)
        os.write(fd, "%s %d:%d:%d" % (name, port, FILED_PORT, REQS))
        os.close(fd)
    except Exception, reason:
        print >> sys.stderr, reason
        sys.exit(-1)

def vlmc_unmap(args):
    xsegbd_loaded()
    device = args.name[0]
    try:
        for f in os.listdir(XSEGBD_SYSFS + "devices/"):
            d_id = open(XSEGBD_SYSFS + "devices/" + f + "/id").read().strip()
            name = open(XSEGBD_SYSFS + "devices/"+ f + "/name").read().strip()
            if device == DEVICE_PREFIX + d_id:
                fd = os.open(XSEGBD_SYSFS + "remove", os.O_WRONLY)
                os.write(fd, d_id)
                os.close(fd)

                sys.exit(0)
        print >> sys.stderr, "Device %s doesn't exist" % device
        sys.exit(-1)
    except Exception, reason:
        print >> sys.stderr, reason
        sys.exit(-1)

def vlmc_showmapped(args):
    xsegbd_loaded()
    print "id\tpool\timage\tsnap\tdevice"
    try:
        for f in os.listdir(XSEGBD_SYSFS + "devices/"):
            d_id = open(XSEGBD_SYSFS + "devices/" + f + "/id").read().strip()
            name = open(XSEGBD_SYSFS + "devices/"+ f + "/name").read().strip()

            print "%s\t%s\t%s\t%s\t%s" % (d_id, '-', name, '-', DEVICE_PREFIX +
            d_id)
    except Exception, reason:
        print >> sys.stderr, reason
        sys.exit(-1)

if __name__ == "__main__":
    # parse arguments and discpatch to the correct func
    parser = argparse.ArgumentParser(description='vlmc tool')
    parser.add_argument('-c', '--config', type=str, nargs='?', help='config file')
    subparsers = parser.add_subparsers()

    create_parser = subparsers.add_parser('create', help='Create volume')
    #group = create_parser.add_mutually_exclusive_group(required=True)
    create_parser.add_argument('-s', '--size', type=int, nargs='?', help='requested size in MB for create')
    create_parser.add_argument('--snap', type=str, nargs='?', help='create from snapshot')
    create_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')
    create_parser.add_argument('name', type=str, nargs=1, help='volume/device name')
    create_parser.set_defaults(func=vlmc_create)

    remove_parser = subparsers.add_parser('remove', help='Delete volume')
    remove_parser.add_argument('name', type=str, nargs=1, help='volume/device name')
    remove_parser.set_defaults(func=vlmc_remove)
    remove_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')

    rm_parser = subparsers.add_parser('rm', help='Delete volume')
    rm_parser.add_argument('name', type=str, nargs=1, help='volume/device name')
    rm_parser.set_defaults(func=vlmc_remove)
    rm_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')

    map_parser = subparsers.add_parser('map', help='Map volume')
    map_parser.add_argument('name', type=str, nargs=1, help='volume/device name')
    map_parser.set_defaults(func=vlmc_map)
    map_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')

    unmap_parser = subparsers.add_parser('unmap', help='Unmap volume')
    unmap_parser.add_argument('name', type=str, nargs=1, help='volume/device name')
    unmap_parser.set_defaults(func=vlmc_unmap)
    unmap_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')

    showmapped_parser = subparsers.add_parser('showmapped', help='Show mapped volumes')
    showmapped_parser.set_defaults(func=vlmc_showmapped)
    showmapped_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')

    list_parser = subparsers.add_parser('list', help='List volumes')
    list_parser.set_defaults(func=vlmc_list)
    list_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')

    ls_parser = subparsers.add_parser('ls', help='List volumes')
    ls_parser.set_defaults(func=vlmc_list)
    ls_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')

    args = parser.parse_args()    

    loadrc(args.config)

    args.func(args)
