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
import sys
from struct import unpack
from binascii import hexlify
from ctypes import c_uint32, c_uint64

from .common import *


@exclusive()
def get_mapped():
    try:
        devices = os.listdir(os.path.join(XSEGBD_SYSFS, "devices/"))
    except:
        if loaded_module(xsegbd):
            raise Error("Cannot list %s/devices/" % XSEGBD_SYSFS)
        else:
            return None
    try:
        mapped = []
        for f in devices:
            d_id = open(XSEGBD_SYSFS + "devices/" + f + "/id")
            d_id = d_id.read().strip()
            target = open(XSEGBD_SYSFS + "devices/" + f + "/target")
            target = target.read().strip()
            mapped.append((d_id, target))

    except Exception, reason:
        raise Error(reason)

    return mapped


def showmapped():
    mapped = get_mapped()
    if not mapped:
        print "No volumes mapped"
        print ""
        return 0

    print "id\timage\t\tdevice"
    for m in mapped:
        print "%s\t%s\t%s" % (m[0], m[1], DEVICE_PREFIX + m[0])

    return len(mapped)


def showmapped_wrapper(**kwargs):
    showmapped()


def is_mapped(volume):
    mapped = get_mapped()
    if not mapped:
        return None

    for m in mapped:
        d_id = m[0]
        target = m[1]
        if target == volume:
            return d_id
    return None


@exclusive(get_port=True)
def create(name, size=None, snap=None, contaddr=False, **kwargs):
    if len(name) < 6:
        raise Error("Name should have at least len 6")
    if size is None and snap is None:
        raise Error("At least one of the size/snap args must be provided")

    if not snap:
        snap = ""
    if not size:
        size = 0
    else:
        size = size << 20

    ret = False
    vtool_port = get_vtool_port()
    xseg_ctx = Xseg_ctx(get_segment(), vtool_port)
    mport = peers['mapperd'].portno_start
    req = Request.get_clone_request(xseg_ctx, mport, snap, clone=name,
            clone_size=size, cont_addr=contaddr)
    req.submit()
    req.wait()
    ret = req.success()
    req.put()
    xseg_ctx.shutdown()
    if not ret:
        raise Error("vlmc creation failed")


@exclusive(get_port=True)
def snapshot(name, snap_name=None, cli=False, **kwargs):
    if len(name) < 6:
        raise Error("Name should have at least len 6")

    vtool_port = get_vtool_port()
    xseg_ctx = Xseg_ctx(get_segment(), vtool_port)
    vport = peers['vlmcd'].portno_start
    req = Request.get_snapshot_request(xseg_ctx, vport, name, snap=snap_name)
    req.submit()
    req.wait()
    ret = req.success()
    req.put()
    xseg_ctx.shutdown()

    if not ret:
        raise Error("vlmc snapshot failed")
    if cli:
        sys.stdout.write("Snapshot name: %s\n" % snap_name)

@exclusive(get_port=True)
def hash(name, cli=False, **kwargs):
    if len(name) < 6:
        raise Error("Name should have at least len 6")

    vtool_port = get_vtool_port()
    xseg_ctx = Xseg_ctx(get_segment(), vtool_port)
    mport = peers['mapperd'].portno_start
    req = Request.get_hash_request(xseg_ctx, mport, name)
    req.submit()
    req.wait()
    ret = req.success()
    if ret:
        xhash = req.get_data(xseg_reply_hash).contents
        hash_name = ctypes.string_at(xhash.target, xhash.targetlen)
    req.put()
    xseg_ctx.shutdown()

    if not ret:
        raise Error("vlmc hash failed")
    if cli:
        sys.stdout.write("Hash name: %s\n" % hash_name)
        return hash_name

def list_volumes(**kwargs):
    if isinstance(peers['blockerm'], Sosd):
        import rados
        cluster = rados.Rados(conffile=config['CEPH_CONF_FILE'])
        cluster.connect()
        ioctx = cluster.open_ioctx(peers['blockerm'].pool)
        oi = rados.ObjectIterator(ioctx)
        for o in oi:
            name = o.key
            if name.startswith(ARCHIP_PREFIX) and not name.endswith('_lock'):
                print name[len(ARCHIP_PREFIX):]
    elif config['STORAGE'] == "files":
        raise Error("Vlmc list not supported for files yet")
    else:
        raise Error("Invalid storage")


@exclusive(get_port=True)
def remove(name, **kwargs):
    device = is_mapped(name)
    if device is not None:
        raise Error("Volume %s mapped on device %s%s" % (name, DEVICE_PREFIX,
                    device))

    ret = False
    vtool_port = get_vtool_port()
    xseg_ctx = Xseg_ctx(get_segment(), vtool_port)
    mport = peers['mapperd'].portno_start
    req = Request.get_delete_request(xseg_ctx, mport, name)
    req.submit()
    req.wait()
    ret = req.success()
    xseg_ctx.shutdown()
    if not ret:
        raise Error("vlmc removal failed")


@exclusive()
def map_volume(name, **kwargs):
    vport = peers['vlmcd'].portno_start
    if not loaded_module(xsegbd):
        raise Error("Xsegbd module not loaded")

    device = is_mapped(name)
    if device is not None:
        raise Error("Volume %s already mapped on device %s%s" % (name,
            DEVICE_PREFIX, device))

    prev = config['XSEGBD_START']
    try:
        result = [int(open(XSEGBD_SYSFS + "devices/" + f + "/srcport").read().
                  strip()) for f in os.listdir(XSEGBD_SYSFS + "devices/")]
        result.sort()

        for p in result:
            if p - prev > 1:
                break
            else:
                prev = p

        port = prev + 1
        if port > config['XSEGBD_END']:
            raise Error("Max xsegbd devices reached")
        fd = os.open(XSEGBD_SYSFS + "add", os.O_WRONLY)
        print >> sys.stderr, "write to %s : %s %d:%d:%d" % (XSEGBD_SYSFS +
                             "add", name, port, port - config['XSEGBD_START'] +
                             vport, REQS)
        os.write(fd, "%s %d:%d:%d" % (name, port, port - config['XSEGBD_START']
                                      + vport, REQS))
        os.close(fd)
        return port
    except Exception, reason:
        raise Error(name + ': ' + str(reason))


@exclusive()
def unmap_volume(name, **kwargs):
    if not loaded_module(xsegbd):
        raise Error("Xsegbd module not loaded")
    device = name
    try:
        for f in os.listdir(XSEGBD_SYSFS + "devices/"):
            d_id = open(XSEGBD_SYSFS + "devices/" + f + "/id")
            d_id = d_id.read().strip()
            target = open(XSEGBD_SYSFS + "devices/" + f + "/target")
            target = target.read().strip()
            if device == DEVICE_PREFIX + d_id:
                fd = os.open(XSEGBD_SYSFS + "remove", os.O_WRONLY)
                os.write(fd, d_id)
                os.close(fd)
                return
        raise Error("Device %s doesn't exist" % device)
    except Exception, reason:
        raise Error(device + ': ' + str(reason))


# FIXME:
def resize(name, size, **kwargs):
    if not loaded_module(xsegbd):
        raise Error("Xsegbd module not loaded")

    try:

        for f in os.listdir(XSEGBD_SYSFS + "devices/"):
            d_id = open(XSEGBD_SYSFS + "devices/" + f + "/id")
            d_id = d_id.read().strip()
            target = open(XSEGBD_SYSFS + "devices/" + f + "/target")
            target = target.read().strip()
            if name == target:
                fd = os.open(XSEGBD_SYSFS + "devices/" + d_id + "/refresh",
                             os.O_WRONLY)
                os.write(fd, "1")
                os.close(fd)

    except Exception, reason:
        raise Error(name + ': ' + str(reason))


@exclusive(get_port=True)
def lock(name, cli=False, **kwargs):
    if len(name) < 6:
        raise Error("Name should have at least len 6")

    name = ARCHIP_PREFIX + name

    vtool_port = get_vtool_port()
    xseg_ctx = Xseg_ctx(get_segment(), vtool_port)
    mbport = peers['blockerm'].portno_start
    ret = Request.get_acquire_request(xseg_ctx, mbport, name)
    req.submit()
    req.wait()
    ret = req.success()
    xseg_ctx.shutdown()
    if not ret:
        raise Error("vlmc lock failed")
    if cli:
        sys.stdout.write("Volume locked\n")


@exclusive(get_port=True)
def unlock(name, force=False, cli=False, **kwargs):
    if len(name) < 6:
        raise Error("Name should have at least len 6")

    name = ARCHIP_PREFIX + name

    vtool_port = get_vtool_port()
    xseg_ctx = Xseg_ctx(get_segment(), vtool_port)
    mbport = peers['blockerm'].portno_start
    req = Request.get_release_request(xseg_ctx, mbport, name, force=force)
    req.submit()
    req.wait()
    ret = req.success()
    xseg_ctx.shutdown()
    if not ret:
        raise Error("vlmc unlock failed")
    if cli:
        sys.stdout.write("Volume unlocked\n")


@exclusive(get_port=True)
def open_volume(name, cli=False, **kwargs):
    if len(name) < 6:
        raise Error("Name should have at least len 6")

    ret = False
    vtool_port = get_vtool_port()
    xseg_ctx = Xseg_ctx(get_segment(), vtool_port)
    vport = peers['vlmcd'].portno_start
    ret = Request.get_open_request(xseg_ctx, vport, name)
    req.submit()
    req.wait()
    ret = req.success()
    xseg_ctx.shutdown()
    if not ret:
        raise Error("vlmc open failed")
    if cli:
        sys.stdout.write("Volume opened\n")


@exclusive(get_port=True)
def close_volume(name, cli=False, **kwargs):
    if len(name) < 6:
        raise Error("Name should have at least len 6")

    ret = False
    vtool_port = get_vtool_port()
    xseg_ctx = Xseg_ctx(get_segment(), vtool_port)
    vport = peers['vlmcd'].portno_start
    ret = Request.get_close_request(xseg_ctx, vport, name)
    req.submit()
    req.wait()
    ret = req.success()
    xseg_ctx.shutdown()
    if not ret:
        raise Error("vlmc close failed")
    if cli:
        sys.stdout.write("Volume closed\n")


@exclusive(get_port=True)
def info(name, cli=False, **kwargs):
    if len(name) < 6:
        raise Error("Name should have at least len 6")

    ret = False
    vtool_port = get_vtool_port()
    xseg_ctx = Xseg_ctx(get_segment(), vtool_port)
    mport = peers['mapperd'].portno_start
    req = Request.get_info_request(xseg_ctx, mport, name)
    req.submit()
    req.wait()
    ret = req.success()
    if ret:
        size = req.get_data(xseg_reply_info).contents.size
    xseg_ctx.shutdown()
    if not ret:
        raise Error("vlmc info failed")
    if cli:
        sys.stdout.write("Volume %s: size: %d\n" % (name, size))


def mapinfo(name, verbose=False, **kwargs):
    if len(name) < 6:
        raise Error("Name should have at least len 6")

    if config['STORAGE'] == "rados":
        import rados
        cluster = rados.Rados(conffile=config['CEPH_CONF_FILE'])
        cluster.connect()
        ioctx = cluster.open_ioctx(config['RADOS_POOL_MAPS'])
        BLOCKSIZE = 4*1024*1024
        try:
            mapdata = ioctx.read(ARCHIP_PREFIX + name, length=BLOCKSIZE)
        except Exception:
            raise Error("Cannot read map data")
        if not mapdata:
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
            if verbose:
                print block, exists
        print "Actual disk usage: " + str(nr_exists * BLOCKSIZE),
        print '(' + str(nr_exists) + '/' + str(blocks) + ' blocks)'

    elif STORAGE == "files":
        raise Error("Mapinfo for file storage not supported")
    else:
        raise Error("Invalid storage")
