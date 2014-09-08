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
import re
from struct import pack, unpack
from binascii import hexlify
from ctypes import c_uint32, c_uint64

from .common import *
from blktap import VlmcTapdisk


@exclusive()
def get_mapped():
    return VlmcTapdisk.list()


def showmapped():
    mapped = get_mapped()
    if not mapped:
        print "No volumes mapped"
        print ""
        return 0

    print "id\timage\t\tdevice"
    for m in mapped:
        print "%s\t%s\t%s" % (m.minor, m.volume, m.device)

    return len(mapped)


def showmapped_wrapper(**kwargs):
    showmapped()


def is_mapped(volume):
    mapped = get_mapped()
    if not mapped:
        return None

    for m in mapped:
        d_id = m.minor
        target = m.volume
        if target == volume:
            return d_id
    return None


def is_device_mapped(device):
    mapped = get_mapped()
    if not mapped:
        return None

    for m in mapped:
        d_id = m.minor
        target = m.device
        if target == device:
            return d_id
    return None

def parse_assume_v0(req, assume_v0, v0_size):
    if assume_v0:
        flags = req.get_flags()
        flags |= XF_ASSUMEV0
        req.set_flags(flags)
        if v0_size != -1:
            req.set_v0_size(v0_size)

def is_valid_name(name):
    """Validates a resource name"""
    if name.startswith(ARCHIP_PREFIX) or name.endswith('_lock') or \
       re.match('.*_(\d|[a-f]){16}', name):
        return False

    return True

def create(name, size=None, snap=None, assume_v0=False, v0_size=-1, **kwargs):
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

    if not is_valid_name(name):
        raise Error("Invalid volume name")

    ret = False
    xseg_ctx = Xseg_ctx(get_segment())
    mport = peers['mapperd'].portno_start
    req = Request.get_clone_request(xseg_ctx, mport, snap, clone=name,
            clone_size=size)
    parse_assume_v0(req, assume_v0, v0_size)
    req.submit()
    req.wait()
    ret = req.success()
    req.put()
    xseg_ctx.shutdown()
    if not ret:
        raise Error("vlmc creation failed")


def snapshot(name, snap_name=None, cli=False, assume_v0=False, v0_size=-1, **kwargs):
    if len(name) < 6:
        raise Error("Name should have at least len 6")

    if not is_valid_name(name):
        raise Error("Invalid volume name")

    if not is_valid_name(snap_name):
        raise Error("Invalid snapshot name")

    xseg_ctx = Xseg_ctx(get_segment())
    vport = peers['vlmcd'].portno_start
    req = Request.get_snapshot_request(xseg_ctx, vport, name, snap=snap_name)
    parse_assume_v0(req, assume_v0, v0_size)
    req.submit()
    req.wait()
    ret = req.success()
    req.put()
    xseg_ctx.shutdown()

    if not ret:
        raise Error("vlmc snapshot failed")
    if cli:
        sys.stdout.write("Snapshot name: %s\n" % snap_name)

def rename(name, newname=None, cli=False, assume_v0=False, v0_size=-1, **kwargs):
    if len(name) < 6:
        raise Error("Name should have at least len 6")

    if len(newname) < 6:
        raise Error("New name should have at least len 6")

    if is_mapped(name) is not None:
        raise Error("Cannot rename a mapped resource")

    if not is_valid_name(name):
        raise Error("Invalid volume name")

    if not is_valid_name(newname):
        raise Error("Invalid new name")

    xseg_ctx = Xseg_ctx(get_segment())
    mport = peers['mapperd'].portno_start
    req = Request.get_rename_request(xseg_ctx, mport, name, newname=newname)
    parse_assume_v0(req, assume_v0, v0_size)
    req.submit()
    req.wait()
    ret = req.success()
    req.put()
    xseg_ctx.shutdown()

    if not ret:
        raise Error("vlmc rename failed")
    if cli:
        sys.stdout.write("Renamed %s to %s\n" % (name, newname))


def hash(name, cli=False, assume_v0=False, v0_size=-1, **kwargs):
    if len(name) < 6:
        raise Error("Name should have at least len 6")

    if not is_valid_name(name):
        raise Error("Invalid volume name")

    xseg_ctx = Xseg_ctx(get_segment())
    mport = peers['mapperd'].portno_start
    req = Request.get_hash_request(xseg_ctx, mport, name)
    parse_assume_v0(req, assume_v0, v0_size)
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


def list_volumes(cli=False, **kwargs):
    """
    Quick 'n dirty way to list volumes. This bypasses the archipelago
    infrastructure and goes directly to storage.
    """

    MAX_HEADER_SIZE = 32

    def parse_header(name, header):
        size_uint32t = sizeof(c_uint32)
        size_uint64t = sizeof(c_uint64)

        readonly = False
        deleted = False
        version1_on_disk = pack("<L", 1)
        signature_on_disk = pack(">L", int(hexlify(b'AMF.'), base=16))

        if (header[0:size_uint32t] != signature_on_disk):
            if header[0:size_uint32t] == version1_on_disk:
                version = 1
            elif len(name) == 64 and re.match('(\d|[abcdef])+', name):
                version = 0
                readonly = True
            else:
                return None
        else:
            _, version, _, _, flags = unpack(">LLQLL",
                                        header[:4*size_uint32t + size_uint64t])
            if flags & 1:
                readonly = True
            if flags & 2:
                deleted = True

        return (version, readonly, deleted)


    def get_volumes():
        Volume = namedtuple('Volume', ['name', 'version', 'header_object',
                                       'readonly', 'deleted'])
        if isinstance(peers['blockerm'], Radosd):
            import rados
            cluster = rados.Rados(rados_id=peers['blockerm'].cephx_id,
                                  conffile=config['CEPH_CONF_FILE'])
            cluster.connect()
            ioctx = cluster.open_ioctx(peers['blockerm'].pool)
            oi = rados.ObjectIterator(ioctx)
            for o in oi:
                name = o.key
                try:
                    header = ioctx.read(name, length=MAX_HEADER_SIZE)
                    ph = parse_header(name, header)
                    if ph is None:
                        continue
                    (version, readonly, deleted) = ph
                    volume = name
                    if volume.startswith(ARCHIP_PREFIX):
                        volume = volume[len(ARCHIP_PREFIX):]
                    yield Volume(name=volume, version=version,
                            header_object=name, deleted=deleted,
                            readonly=readonly)
                except:
                    pass
        elif isinstance(peers['blockerm'], Filed):
            path = peers['blockerm'].archip_dir
            for root, dirs, files in os.walk(path):
                for f in files:
                    name = f
                    try:
                        f = open(os.path.join(root, f), 'r')
                        header = f.read(MAX_HEADER_SIZE)
                        f.close()
                        ph = parse_header(name, header)
                        if ph is None:
                            continue
                        (version, readonly, deleted) = ph
                        volume = name
                        if volume.startswith(ARCHIP_PREFIX):
                            volume = volume[len(ARCHIP_PREFIX):]
                        yield Volume(name=volume, version=version,
                            header_object=name, deleted=deleted,
                            readonly=readonly)
                    except:
                        pass
        else:
            raise Error("Invalid storage")

    if not cli:
        return get_volumes()

    for v in get_volumes():
        if v.deleted:
            continue
        print v.name


def remove(name, assume_v0=False, v0_size=-1, **kwargs):

    if not is_valid_name(name):
        raise Error("Invalid volume name")

    device = is_mapped(name)
    if device is not None:
        raise Error("Volume %s mapped on device %s%s" % (name, DEVICE_PREFIX,
                    device))

    ret = False
    xseg_ctx = Xseg_ctx(get_segment())
    mport = peers['vlmcd'].portno_start
    req = Request.get_delete_request(xseg_ctx, mport, name)
    parse_assume_v0(req, assume_v0, v0_size)
    req.submit()
    req.wait()
    ret = req.success()
    req.put()
    xseg_ctx.shutdown()
    if not ret:
        raise Error("vlmc removal failed")


@exclusive()
def map_volume(name, assume_v0=False, v0_size=-1, readonly=False, **kwargs):
    if not loaded_module("blktap"):
        raise Error("blktap module not loaded")

    if not is_valid_name(name):
        raise Error("Invalid volume name")

    device = is_mapped(name)
    if device is not None:
        raise Error("Volume %s already mapped on device %s%s" % (name,
                    '/dev/xen/blktap-2/tapdev', device))

    try:
        device = VlmcTapdisk.create(name, vport=peers['vlmcd'].portno_start,
                                    mport=peers['mapperd'].portno_start,
                                    assume_v0=assume_v0, v0_size=v0_size,
                                    readonly=readonly)
        if device:
            sys.stderr.write(device + '\n')
            return device.split(DEVICE_PREFIX)[1]
        raise Error("Cannot map volume '%s'.\n" % name)
    except Exception, reason:
        raise Error(name + ': ' + str(reason))


@exclusive()
def unmap_volume(name, **kwargs):
    if not loaded_module("blktap"):
        raise Error("blktap module not loaded")
    device = name
    try:
        if is_device_mapped(device) is not None:
            busy = VlmcTapdisk.busy_pid(device)
            mounted = VlmcTapdisk.is_mounted(device)
            if not busy and not mounted:
                VlmcTapdisk.destroy(device)
            else:
                if busy:
                    raise Error("Device is busy (PID: %s)." % busy)
                elif mounted:
                    raise Error("Device is mounted. Cannot unmap device.")
            return
        raise Error("Device doesn't exist")
    except Exception, reason:
        raise Error(device + ': ' + str(reason))


# FIXME:
def resize(name, size, **kwargs):
    raise NotImplementedError()


def lock(name, cli=False, **kwargs):
    if len(name) < 6:
        raise Error("Name should have at least len 6")

    if not is_valid_name(name):
        raise Error("Invalid volume name")

    xseg_ctx = Xseg_ctx(get_segment())
    mbport = peers['blockerm'].portno_start
    req = Request.get_acquire_request(xseg_ctx, mbport, name)
    req.submit()
    req.wait()
    ret = req.success()
    req.put()
    xseg_ctx.shutdown()
    if not ret:
        raise Error("vlmc lock failed")
    if cli:
        sys.stdout.write("Volume locked\n")


def unlock(name, force=False, cli=False, **kwargs):
    if len(name) < 6:
        raise Error("Name should have at least len 6")

    if not is_valid_name(name):
        raise Error("Invalid volume name")

    xseg_ctx = Xseg_ctx(get_segment())
    mbport = peers['blockerm'].portno_start
    req = Request.get_release_request(xseg_ctx, mbport, name, force=force)
    req.submit()
    req.wait()
    ret = req.success()
    req.put()
    xseg_ctx.shutdown()
    if not ret:
        raise Error("vlmc unlock failed")
    if cli:
        sys.stdout.write("Volume unlocked\n")


def open_volume(name, cli=False, assume_v0=False, v0_size=-1, **kwargs):
    if len(name) < 6:
        raise Error("Name should have at least len 6")

    if not is_valid_name(name):
        raise Error("Invalid volume name")

    ret = False
    xseg_ctx = Xseg_ctx(get_segment())
    vport = peers['vlmcd'].portno_start
    req = Request.get_open_request(xseg_ctx, vport, name)
    parse_assume_v0(req, assume_v0, v0_size)
    req.submit()
    req.wait()
    ret = req.success()
    req.put()
    xseg_ctx.shutdown()
    if not ret:
        raise Error("vlmc open failed")
    if cli:
        sys.stdout.write("Volume opened\n")


def close_volume(name, cli=False, assume_v0=False, v0_size=-1, **kwargs):
    if len(name) < 6:
        raise Error("Name should have at least len 6")

    if not is_valid_name(name):
        raise Error("Invalid volume name")

    ret = False
    xseg_ctx = Xseg_ctx(get_segment())
    vport = peers['vlmcd'].portno_start
    req = Request.get_close_request(xseg_ctx, vport, name)
    parse_assume_v0(req, assume_v0, v0_size)
    req.submit()
    req.wait()
    ret = req.success()
    req.put()
    xseg_ctx.shutdown()
    if not ret:
        raise Error("vlmc close failed")
    if cli:
        sys.stdout.write("Volume closed\n")


def info(name, cli=False, assume_v0=False, v0_size=-1, **kwargs):
    if len(name) < 6:
        raise Error("Name should have at least len 6")

    if not is_valid_name(name):
        raise Error("Invalid volume name")

    ret = False
    xseg_ctx = Xseg_ctx(get_segment())
    mport = peers['mapperd'].portno_start
    req = Request.get_info_request(xseg_ctx, mport, name)
    parse_assume_v0(req, assume_v0, v0_size)
    req.submit()
    req.wait()
    ret = req.success()
    if ret:
        size = req.get_data(xseg_reply_info).contents.size
    req.put()
    xseg_ctx.shutdown()
    if not ret:
        raise Error("vlmc info failed")
    if cli:
        sys.stdout.write("Volume %s: size: %d\n" % (name, size))


def mapinfo(name, verbose=False, **kwargs):
    raise Error("Unimplemented")
