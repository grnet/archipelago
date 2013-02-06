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
from struct import unpack
from binascii import hexlify

from archipelago.common import *

@exclusive
def vlmc_showmapped(args):
    try:
        devices = os.listdir(os.path.join(XSEGBD_SYSFS, "devices/"))
    except:
        if loaded_module(xsegbd):
            raise Error("Cannot list %s/devices/" % XSEGBD_SYSFS)
        else:
            return 0

    print "id\tpool\timage\tsnap\tdevice"
    if not devices:
        print "No volumes mapped\n"
        return 0
    try:
        for f in devices:
            d_id = open(XSEGBD_SYSFS + "devices/" + f + "/id").read().strip()
            target = open(XSEGBD_SYSFS + "devices/"+ f + "/target").read().strip()

            print "%s\t%s\t%s\t%s\t%s" % (d_id, '-', target, '-', DEVICE_PREFIX +
            d_id)
    except Exception, reason:
        raise Error(reason)
    return len(devices)

def vlmc_showmapped_wrapper(args):
    vlmc_showmapped(args)


@exclusive
def vlmc_create(args):
    name = args.name[0]
    size = args.size
    snap = args.snap

    if len(name) < 6:
        raise Error("Name should have at least len 6")
    if size == None and snap == None:
        raise Error("At least one of the size/snap args must be provided")

    ret = False
    xseg_ctx = Xseg_ctx(SPEC, VTOOL)
    with Request(xseg_ctx, MPORT, len(name), sizeof(xseg_request_clone)) as req:
        req.set_op(X_CLONE)
        req.set_size(sizeof(xseg_request_clone))
        req.set_offset(0)
        req.set_target(name)

        xclone = xseg_request_clone()
        if snap:
            xclone.target = snap
            xclone.targetlen = len(snap)
        else:
            xclone.target = ""
            xclone.targetlen = 0
        if size:
            xclone.size = size << 20
        else:
            xclone.size = -1

        req.set_data(xclone)
        req.submit()
        req.wait()
        ret = req.success()
    xseg_ctx.shutdown()
    if not ret:
        raise Error("vlmc creation failed")

@exclusive
def vlmc_snapshot(args):
    # snapshot
    name = args.name[0]

    if len(name) < 6:
        raise Error("Name should have at least len 6")

    ret = False
    xseg_ctx = Xseg_ctx(SPEC, VTOOL)
    with Request(xseg_ctx, VPORT_START, len(name), sizeof(xseg_request_snapshot)) as req:
        req.set_op(X_SNAPSHOT)
        req.set_size(sizeof(xseg_request_snapshot))
        req.set_offset(0)
        req.set_target(name)

        xsnapshot = xseg_request_snapshot()
        xsnapshot.target = ""
        xsnapshot.targetlen = 0
        req.set_data(xsnapshot)
        req.submit()
        req.wait()
        ret = req.success()
        if ret:
            reply = string_at(req.get_data(xseg_reply_snapshot).contents.target, 64)
    xseg_ctx.shutdown()
    if not ret:
        raise Error("vlmc snapshot failed")
    sys.stdout.write("Snapshot name: %s\n" % reply)


def vlmc_list(args):
    if STORAGE == "rados":
        import rados
        cluster = rados.Rados(conffile='/etc/ceph/ceph.conf')
        cluster.connect()
        ioctx = cluster.open_ioctx(RADOS_POOL_MAPS)
        oi = rados.ObjectIterator(ioctx)
        for o in oi :
            name = o.key
            if name.startswith(ARCHIP_PREFIX) and not name.endswith('_lock'):
		    print name[len(ARCHIP_PREFIX):]
    elif STORAGE == "files":
        raise Error("Vlmc list not supported for files yet")
    else:
        raise Error("Invalid storage")


@exclusive
def vlmc_remove(args):
    name = args.name[0]

    try:
        for f in os.listdir(XSEGBD_SYSFS + "devices/"):
            d_id = open(XSEGBD_SYSFS + "devices/" + f + "/id").read().strip()
            target = open(XSEGBD_SYSFS + "devices/"+ f + "/target").read().strip()
            if target == name:
                raise Error("Volume mapped on device %s%s" % (DEVICE_PREFIX,
								d_id))

    except Exception, reason:
        raise Error(name + ': ' + str(reason))

    ret = False
    xseg_ctx = Xseg_ctx(SPEC, VTOOL)
    with Request(xseg_ctx, MPORT, len(name), 0) as req:
        req.set_op(X_DELETE)
        req.set_size(0)
        req.set_offset(0)
        req.set_target(name)
        req.submit()
        req.wait()
        ret = req.success()
    xseg_ctx.shutdown()
    if not ret:
        raise Error("vlmc removal failed")


@exclusive
def vlmc_map(args):
    if not loaded_module(xsegbd):
        raise Error("Xsegbd module not loaded")
    name = args.name[0]
    prev = XSEGBD_START
    try:
        result = [int(open(XSEGBD_SYSFS + "devices/" + f + "/srcport").read().strip()) for f in os.listdir(XSEGBD_SYSFS + "devices/")]
        result.sort()

        for p in result:
            if p - prev > 1:
               break
            else:
               prev = p

        port = prev + 1
        if port > XSEGBD_END:
            raise Error("Max xsegbd devices reached")
        fd = os.open(XSEGBD_SYSFS + "add", os.O_WRONLY)
        print >> sys.stderr, "write to %s : %s %d:%d:%d" %( XSEGBD_SYSFS +
			"add", name, port, port - XSEGBD_START + VPORT_START, REQS )
        os.write(fd, "%s %d:%d:%d" % (name, port, port - XSEGBD_START + VPORT_START, REQS))
        os.close(fd)
    except Exception, reason:
        raise Error(name + ': ' + str(reason))

@exclusive
def vlmc_unmap(args):
    if not loaded_module(xsegbd):
        raise Error("Xsegbd module not loaded")
    device = args.name[0]
    try:
        for f in os.listdir(XSEGBD_SYSFS + "devices/"):
            d_id = open(XSEGBD_SYSFS + "devices/" + f + "/id").read().strip()
            name = open(XSEGBD_SYSFS + "devices/"+ f + "/target").read().strip()
            if device == DEVICE_PREFIX + d_id:
                fd = os.open(XSEGBD_SYSFS + "remove", os.O_WRONLY)
                os.write(fd, d_id)
                os.close(fd)
                return
        raise Error("Device %s doesn't exist" % device)
    except Exception, reason:
        raise Error(device + ': ' + str(reason))

# FIXME:
def vlmc_resize(args):
    if not loaded_module(xsegbd):
        raise Error("Xsegbd module not loaded")

    name = args.name[0]
    size = args.size[0]

    try:

        for f in os.listdir(XSEGBD_SYSFS + "devices/"):
            d_id = open(XSEGBD_SYSFS + "devices/" + f + "/id").read().strip()
            d_name = open(XSEGBD_SYSFS + "devices/"+ f + "/name").read().strip()
            if name == d_name:
                fd = os.open(XSEGBD_SYSFS + "devices/" +  d_id +"/refresh", os.O_WRONLY)
                os.write(fd, "1")
                os.close(fd)

    except Exception, reason:
        raise Error(name + ': ' + str(reason))

@exclusive
def vlmc_lock(args):
    name = args.name[0]

    if len(name) < 6:
        raise Error("Name should have at least len 6")

    name = ARCHIP_PREFIX + name

    ret = False
    xseg_ctx = Xseg_ctx(SPEC, VTOOL)
    with Request(xseg_ctx, MBPORT, len(name), 0) as req:
        req.set_op(X_ACQUIRE)
        req.set_size(0)
        req.set_offset(0)
        req.set_flags(XF_NOSYNC)
        req.set_target(name)
        req.submit()
        req.wait()
        ret = req.success()
    xseg_ctx.shutdown()
    if not ret:
        raise Error("vlmc lock failed")
    else:
        sys.stdout.write("Volume locked\n")

@exclusive
def vlmc_unlock(args):
    name = args.name[0]
    force = args.force

    if len(name) < 6:
        raise Error("Name should have at least len 6")

    name = ARCHIP_PREFIX + name

    ret = False
    xseg_ctx = Xseg_ctx(SPEC, VTOOL)
    with Request(xseg_ctx, MBPORT, len(name), 0) as req:
        req.set_op(X_RELEASE)
        req.set_size(0)
        req.set_offset(0)
        req.set_target(name)
        if force:
            req.set_flags(XF_NOSYNC|XF_FORCE)
        else:
            req.set_flags(XF_NOSYNC)
        req.submit()
        req.wait()
        ret = req.success()
    xseg_ctx.shutdown()
    if not ret:
        raise Error("vlmc unlock failed")
    else:
        sys.stdout.write("Volume unlocked\n")

@exclusive
def vlmc_open(args):
    name = args.name[0]

    if len(name) < 6:
        raise Error("Name should have at least len 6")

    ret = False
    xseg_ctx = Xseg_ctx(SPEC, VTOOL)
    with Request(xseg_ctx, VPORT_START, len(name), 0) as req:
        req.set_op(X_OPEN)
        req.set_size(0)
        req.set_offset(0)
        req.set_target(name)
        req.submit()
        req.wait()
        ret = req.success()
    xseg_ctx.shutdown()
    if not ret:
        raise Error("vlmc open failed")
    else:
        sys.stdout.write("Volume opened\n")

@exclusive
def vlmc_close(args):
    name = args.name[0]

    if len(name) < 6:
        raise Error("Name should have at least len 6")

    ret = False
    xseg_ctx = Xseg_ctx(SPEC, VTOOL)
    with Request(xseg_ctx, VPORT_START, len(name), 0) as req:
        req.set_op(X_CLOSE)
        req.set_size(0)
        req.set_offset(0)
        req.set_target(name)
        req.submit()
        req.wait()
        ret = req.success()
    xseg_ctx.shutdown()
    if not ret:
        raise Error("vlmc close failed")
    else:
        sys.stdout.write("Volume closed\n")

@exclusive
def vlmc_info(args):
    name = args.name[0]

    if len(name) < 6:
        raise Error("Name should have at least len 6")

    ret = False
    xseg_ctx = Xseg_ctx(SPEC, VTOOL)
    with Request(xseg_ctx, MPORT, len(name), 0) as req:
        req.set_op(X_INFO)
        req.set_size(0)
        req.set_offset(0)
        req.set_target(name)
        req.submit()
        req.wait()
        ret = req.success()
        if ret:
            size = req.get_data(xseg_reply_info).contents.size
    xseg_ctx.shutdown()
    if not ret:
        raise Error("vlmc info failed")
    else:
        sys.stdout.write("Volume %s: size: %d\n" % (name, size) )

def vlmc_mapinfo(args):
    name = args.name[0]

    if len(name) < 6:
        raise Error("Name should have at least len 6")

    if STORAGE == "rados":
        import rados
        cluster = rados.Rados(conffile=CEPH_CONF_FILE)
        cluster.connect()
        ioctx = cluster.open_ioctx(RADOS_POOL_MAPS)
        BLOCKSIZE = 4*1024*1024
        try:
            mapdata = ioctx.read(ARCHIP_PREFIX + name, length=BLOCKSIZE)
        except Exception:
            raise Error("Cannot read map data")
        if not  mapdata:
            raise Error("Cannot read map data")
        pos = 0
        size_uint32t = sizeof(c_uint32)
        version = unpack("<L", mapdata[pos:pos+size_uint32t])[0]
        pos += size_uint32t
        size_uint64t = sizeof(c_uint64)
        size = unpack("Q", mapdata[pos:pos+size_uint64t])[0]
        pos += size_uint64t
        blocks = size / BLOCKSIZE
        nr_exists = 0
        print ""
        print "Volume: " + name
        print "Version: " + str(version)
        print "Size: " + str(size)
        for i in range(blocks):
            exists = bool(unpack("B", mapdata[pos:pos+1])[0])
            if exists:
                nr_exists += 1
            pos += 1
            block = hexlify(mapdata[pos:pos+32])
            pos += 32
            if args.verbose:
                print block, exists
        print "Actual disk usage: " + str(nr_exists * BLOCKSIZE),
        print '(' + str(nr_exists) + '/' + str(blocks) + ' blocks)'

    elif STORAGE=="files":
        raise Error("Mapinfo for file storage not supported")
    else:
        raise Error("Invalid storage")

def vlmc():
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
    showmapped_parser.set_defaults(func=vlmc_showmapped_wrapper)
    showmapped_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')

    list_parser = subparsers.add_parser('list', help='List volumes')
    list_parser.set_defaults(func=vlmc_list)
    list_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')

    snapshot_parser = subparsers.add_parser('snapshot', help='snapshot volume')
    #group = snapshot_parser.add_mutually_exclusive_group(required=True)
    snapshot_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')
    snapshot_parser.add_argument('name', type=str, nargs=1, help='volume/device name')
    snapshot_parser.set_defaults(func=vlmc_snapshot)

    ls_parser = subparsers.add_parser('ls', help='List volumes')
    ls_parser.set_defaults(func=vlmc_list)
    ls_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')

    resize_parser = subparsers.add_parser('resize', help='Resize volume')
    resize_parser.add_argument('-s', '--size', type=int, nargs=1, help='requested size in MB for resize')
    resize_parser.add_argument('name', type=str, nargs=1, help='volume/device name')
    resize_parser.set_defaults(func=vlmc_resize)
    resize_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')

    open_parser = subparsers.add_parser('open', help='open volume')
    open_parser.add_argument('name', type=str, nargs=1, help='volume/device name')
    open_parser.set_defaults(func=vlmc_open)
    open_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')

    close_parser = subparsers.add_parser('close', help='close volume')
    close_parser.add_argument('name', type=str, nargs=1, help='volume/device name')
    close_parser.set_defaults(func=vlmc_close)
    close_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')

    lock_parser = subparsers.add_parser('lock', help='lock volume')
    lock_parser.add_argument('name', type=str, nargs=1, help='volume/device name')
    lock_parser.set_defaults(func=vlmc_lock)
    lock_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')

    unlock_parser = subparsers.add_parser('unlock', help='unlock volume')
    unlock_parser.add_argument('name', type=str, nargs=1, help='volume/device name')
    unlock_parser.add_argument('-f', '--force',  action='store_true', default=False , help='break lock')
    unlock_parser.set_defaults(func=vlmc_unlock)
    unlock_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')

    info_parser = subparsers.add_parser('info', help='Show volume info')
    info_parser.add_argument('name', type=str, nargs=1, help='volume name')
    info_parser.set_defaults(func=vlmc_info)
    info_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')

    map_info_parser = subparsers.add_parser('mapinfo', help='Show volume map_info')
    map_info_parser.add_argument('name', type=str, nargs=1, help='volume name')
    map_info_parser.set_defaults(func=vlmc_mapinfo)
    map_info_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')
    map_info_parser.add_argument('-v', '--verbose',  action='store_true', default=False , help='')

    return parser
