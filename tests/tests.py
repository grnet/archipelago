# Copyright 2013 GRNET S.A. All rights reserved.
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

import archipelago
from archipelago.common import Xseg_ctx, Request, Filed, Mapperd, Vlmcd, Radosd, \
        Error, Segment
from archipelago.archipelago import start_peer, stop_peer
import random as rnd
import unittest2 as unittest
from xseg.xprotocol import *
from xseg.xseg_api import *
import ctypes
import os
from copy import copy
from sets import Set
from binascii import hexlify, unhexlify
from hashlib import sha256
from struct import pack

def get_random_string(length=64, repeat=16):
    nr_repeats = length//repeat

    l = []
    for i in range(repeat):
        l.append(chr(ord('a') + rnd.randint(0,25)))
    random_string = ''.join(l)

    l = []
    for i in range(nr_repeats):
        l.append(random_string)
    rem = length % repeat
    l.append(random_string[0:rem])

    return ''.join(l)

def recursive_remove(path):
    for root, dirs, files in os.walk(path, topdown=False):
        for name in files:
            os.remove(os.path.join(root, name))
        for name in dirs:
            os.rmdir(os.path.join(root, name))

def merkle_hash(hashes):
    if len(hashes) == 0:
        return sha256('').digest()
    if len(hashes) == 1:
        return hashes[0]

    s = 2
    while s < len(hashes):
        s = s * 2
    hashes += [('\x00' * len(hashes[0]))] * (s - len(hashes))
    while len(hashes) > 1 :
        hashes = [sha256(hashes[i] + hashes[i + 1]).digest() for i in range (0, len(hashes), 2)]
    return hashes[0]
    

def init():
    rnd.seed()
    archipelago.common.BIN_DIR=os.path.join(os.getcwd(), '/tmp/build/src')
    archipelago.common.LOGS_PATH=os.path.join(os.getcwd(), 'logs')
    archipelago.common.PIDFILE_PATH=os.path.join(os.getcwd(), 'pids')
    if not os.path.isdir(archipelago.common.LOGS_PATH):
        os.makedirs(archipelago.common.LOGS_PATH)
    if not os.path.isdir(archipelago.common.PIDFILE_PATH):
        os.makedirs(archipelago.common.PIDFILE_PATH)

    recursive_remove(archipelago.common.LOGS_PATH)

class XsegTest(unittest.TestCase):
    spec = "posix:testsegment:8:16:256:12".encode()
    blocksize = 4*1024*1024
    segment = None

    def setUp(self):
        self.segment = Segment('posix', 'testsegment', 8, 16, 256, 12)
        try:
            self.segment.create()
        except Exception as e:
            self.segment.destroy()
            self.segment.create()
        self.xseg = Xseg_ctx(self.segment)

    def tearDown(self):
        if self.xseg:
            self.xseg.shutdown()
        if self.segment:
            self.segment.destroy()

    @staticmethod
    def get_reply_info(size):
        xinfo = xseg_reply_info()
        xinfo.size = size
        return xinfo

    @staticmethod
    def get_hash_reply(hashstring):
        xhash = xseg_reply_hash()
        xhash.target = hashstring
        xhash.targetlen = len(hashstring)
        return xhash

    @staticmethod
    def get_object_name(volume, epoch, index):
        epoch_64_str = pack(">Q", epoch)
        index_64_str = pack(">Q", index)
        epoch_hex = hexlify(epoch_64_str)
        index_hex = hexlify(index_64_str)
        return volume + "_" + epoch_hex + "_" + index_hex

    @staticmethod
    def get_map_reply(offset, size):
        blocksize = XsegTest.blocksize
        ret = xseg_reply_map()
        cnt = (offset+size)//blocksize - offset//blocksize
        if (offset+size) % blocksize > 0 :
            cnt += 1
        ret.cnt = cnt
        SegsArray = xseg_reply_map_scatterlist * cnt
        segs = SegsArray()
        rem_size = size
        offset = offset % blocksize
        for i in range(0, cnt):
            segs[i].offset = offset
            segs[i].size = blocksize - offset
            if segs[i].size > rem_size:
                segs[i].size = rem_size
            offset = 0
            rem_size -= segs[i].size
            if rem_size < 0 :
                raise Error("Calculation error")
        ret.segs = segs

        return ret

    @staticmethod
    def get_list_of_hashes(xreply, from_segment=False):
        hashes = []
        cnt = xreply.cnt
        segs = xreply.segs
        if from_segment:
            SegsArray = xseg_reply_map_scatterlist * cnt
            array = SegsArray.from_address(ctypes.addressof(segs))
            segs = array
        for i in range(0, cnt):
            hashes.append(ctypes.string_at(segs[i].target, segs[i].targetlen))
        return hashes

    @staticmethod
    def get_zero_map_reply(offset, size):
        ret = XsegTest.get_map_reply(offset, size);
        cnt = ret.cnt
        for i in range(0, cnt):
            ret.segs[i].target = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            ret.segs[i].targetlen = len(ret.segs[i].target)
        return ret

    @staticmethod
    def get_copy_map_reply(volume, offset, size, epoch):
        blocksize = XsegTest.blocksize
        objidx_start = offset//blocksize
        ret = XsegTest.get_map_reply(offset, size);
        cnt = ret.cnt
        for i in range(0, cnt):
            ret.segs[i].target = MapperdTest.get_object_name(volume, epoch,
                    objidx_start+i)
            ret.segs[i].targetlen = len(ret.segs[i].target)
        return ret

    def get_req(self, op, dst, target, data=None, size=0, offset=0, datalen=0,
            flags=0):
        return Request(self.xseg, dst, target, data=data, size=size,
                offset=offset, datalen=datalen, flags=flags, op=op)

    def assert_equal_xseg(self, req, expected_data):
        if isinstance(expected_data, xseg_reply_info):
            datasize = ctypes.sizeof(expected_data)
            self.assertEqual(datasize, req.get_datalen())
            data = req.get_data(type(expected_data)).contents
            self.assertEqual(data.size, expected_data.size)
        elif isinstance(expected_data, xseg_reply_map):
            #since xseg_reply_map uses a flexible array for the
            #xseg_reply_map_scatterlist reply, we calculate the size of the
            #reply in the segment, by subtracting the size of the pointer to
            #the array, in the python object
            datasize = ctypes.sizeof(expected_data)
            datasize -= ctypes.sizeof(expected_data.segs)
            datasize += expected_data.cnt*ctypes.sizeof(xseg_reply_map_scatterlist)
            self.assertEqual(datasize, req.get_datalen())
            data = req.get_data(type(expected_data)).contents
            cnt = data.cnt
            self.assertEqual(data.cnt, expected_data.cnt)
            segs = data.segs
            SegsArray = xseg_reply_map_scatterlist * cnt
            array = SegsArray.from_address(ctypes.addressof(segs))
            expected_array = expected_data.segs
            for i in range(0, cnt):
                t = ctypes.string_at(array[i].target, array[i].targetlen)
                self.assertEqual(array[i].targetlen, expected_array[i].targetlen)
                self.assertEqual(t, expected_array[i].target)
                self.assertEqual(array[i].offset, expected_array[i].offset)
                self.assertEqual(array[i].size, expected_array[i].size)
        elif isinstance(expected_data, xseg_reply_hash):
            datasize = ctypes.sizeof(expected_data)
            self.assertEqual(datasize, req.get_datalen())
            data = req.get_data(type(expected_data)).contents
            self.assertEqual(data.targetlen, expected_data.targetlen)
            t = ctypes.string_at(data.target, data.targetlen)
            et = ctypes.string_at(expected_data.target, expected_data.targetlen)
            self.assertEqual(t, et)
        else:
            raise Error("Unknown data type")

    def evaluate_req(self, req, success=True, serviced=None, data=None):
        if not success:
            self.assertFalse(req.success())
            return

        self.assertTrue(req.success())
        if serviced is not None:
            self.assertEqual(req.get_serviced(), serviced)
        if data is not None:
            if isinstance(data, basestring):
                datalen = len(data)
                self.assertEqual(datalen, req.get_datalen())
                self.assertEqual(data, ctypes.string_at(req.get_data(None), datalen))
            else:
                self.assert_equal_xseg(req, data)

    def evaluate(send_func):
        def send_and_evaluate(self, dst, target, expected=True, serviced=None,
                expected_data=None, **kwargs):
            req = send_func(self, dst, target, **kwargs)
            req.wait()
            self.evaluate_req(req, success=expected, serviced=serviced,
                    data=expected_data)
            self.assertTrue(req.put())
        return send_and_evaluate

    def send_write(self, dst, target, data=None, offset=0, datalen=0, flags=0):
        #assert datalen >= size
#        req = self.get_req(X_WRITE, dst, target, data, size=size, offset=offset, datalen=datalen)
        req = Request.get_write_request(self.xseg, dst, target, data=data,
                offset=offset, datalen=datalen, flags=flags)
        req.submit()
        return req

    send_and_evaluate_write = evaluate(send_write)

    def send_read(self, dst, target, size=0, datalen=0, offset=0):
        #assert datalen >= size
#        req = self.get_req(X_READ, dst, target, data=None, size=size, offset=offset, datalen=datalen)
        req = Request.get_read_request(self.xseg, dst, target, size=size,
                offset=offset, datalen=datalen)
        req.submit()
        return req

    send_and_evaluate_read = evaluate(send_read)

    def send_info(self, dst, target):
        #req = self.get_req(X_INFO, dst, target, data=None, size=0)
        req = Request.get_info_request(self.xseg, dst, target)
        req.submit()
        return req

    send_and_evaluate_info = evaluate(send_info)

    def send_copy(self, dst, src_target, dst_target=None, size=0, offset=0):
        #datalen = ctypes.sizeof(xseg_request_copy)
        #xcopy = xseg_request_copy()
        #xcopy.target = src_target
        #xcopy.targetlen = len(src_target)
#        req = self.get_req(X_COPY, dst, dst_target, data=xcopy, datalen=datalen,
#                offset=offset, size=size)
        req = Request.get_copy_request(self.xseg, dst, src_target,
                copy_target=dst_target, size=size, offset=offset)
        req.submit()
        return req

    send_and_evaluate_copy = evaluate(send_copy)

    def send_acquire(self, dst, target):
        #req = self.get_req(X_ACQUIRE, dst, target, flags=XF_NOSYNC)
        req = Request.get_acquire_request(self.xseg, dst, target)
        req.submit()
        return req

    send_and_evaluate_acquire = evaluate(send_acquire)

    def send_release(self, dst, target, force=False):
        #req_flags = XF_NOSYNC
        #if force:
            #req_flags |= XF_FORCE
        #req = self.get_req(X_RELEASE, dst, target, size=0, flags=req_flags)
        req = Request.get_release_request(self.xseg, dst, target, force)
        req.submit()
        return req

    send_and_evaluate_release = evaluate(send_release)

    def send_delete(self, dst, target):
        #req = self.get_req(X_DELETE, dst, target)
        req = Request.get_delete_request(self.xseg, dst, target)
        req.submit()
        return req

    send_and_evaluate_delete = evaluate(send_delete)

    def send_clone(self, dst, src_target, clone=None, clone_size=0):
        #xclone = xseg_request_clone()
        #xclone.target = src_target
        #xclone.targetlen = len(src_target)
        #xclone.size = clone_size

        #req = self.get_req(X_CLONE, dst, clone, data=xclone,
                #datalen=ctypes.sizeof(xclone))
        req = Request.get_clone_request(self.xseg, dst, src_target,
                clone=clone, clone_size=clone_size)
        req.submit()
        return req

    send_and_evaluate_clone = evaluate(send_clone)

    def send_snapshot(self, dst, src_target, snap=None):
        #xsnapshot = xseg_request_snapshot()
        #xsnapshot.target = snap
        #xsnapshot.targetlen = len(snap)

        #req = self.get_req(X_SNAPSHOT, dst, src_target, data=xsnapshot,
                #datalen=ctypes.sizeof(xsnapshot))
        req = Request.get_snapshot_request(self.xseg, dst, src_target, snap=snap)
        req.submit()
        return req

    send_and_evaluate_snapshot = evaluate(send_snapshot)

    def send_open(self, dst, target):
        #req = self.get_req(X_OPEN, dst, target)
        req = Request.get_open_request(self.xseg, dst, target)
        req.submit()
        return req

    send_and_evaluate_open = evaluate(send_open)

    def send_close(self, dst, target):
        #req = self.get_req(X_CLOSE, dst, target)
        req = Request.get_close_request(self.xseg, dst, target)
        req.submit()
        return req

    send_and_evaluate_close = evaluate(send_close)

    def send_map_read(self, dst, target, offset=0, size=0):
        #req = self.get_req(X_MAPR, dst, target, size=size, offset=offset,
                #datalen=0)
        req = Request.get_mapr_request(self.xseg, dst, target, offset=offset,
                size=size)
        req.submit()
        return req

    send_and_evaluate_map_read = evaluate(send_map_read)

    def send_map_write(self, dst, target, offset=0, size=0):
        #req = self.get_req(X_MAPW, dst, target, size=size, offset=offset,
                #datalen=0)
        req = Request.get_mapw_request(self.xseg, dst, target, offset=offset,
                size=size)
        req.submit()
        return req

    send_and_evaluate_map_write = evaluate(send_map_write)

    def send_hash(self, dst, target, size=0):
        #req = self.get_req(X_hash, dst, target, data=None, size=0)
        req = Request.get_hash_request(self.xseg, dst, target, size=size)
        req.submit()
        return req

    send_and_evaluate_hash = evaluate(send_hash)

    def send_create(self, dst, target, mapflags=0, size=0, objects=None,
            blocksize=None):
        req = Request.get_create_request(self.xseg, dst, target, size=size,
                mapflags=mapflags, blocksize=blocksize, objects=objects)
        req.submit()
        return req

    send_and_evaluate_create = evaluate(send_create)

    def send_rename(self, dst, target, newname=None):
        req = Request.get_rename_request(self.xseg, dst, target,
                newname=newname)
        req.submit()
        return req

    send_and_evaluate_rename = evaluate(send_rename)

    def get_filed(self, args, clean=False):
        path = args['archip_dir']
        if not os.path.exists(path):
            os.makedirs(path)

        if clean:
            recursive_remove(path)

        return Filed(**args)

    def get_radosd(self, args, clean=False):
        pool = args['pool']
        import rados
        cluster = rados.Rados(conffile='/etc/ceph/ceph.conf')
        cluster.connect()
        if cluster.pool_exists(pool):
            cluster.delete_pool(pool)
        cluster.create_pool(pool)

        cluster.shutdown()
        return Radosd(**args)

    def get_mapperd(self, args):
        return Mapperd(**args)

    def get_vlmcd(self, args):
        return Vlmcd(**args)

class VlmcdTest(XsegTest):
    bfiled_args = {
            'role': 'vlmctest-blockerb',
            'spec': XsegTest.spec,
            'nr_ops': 16,
            'archip_dir': '/tmp/bfiledtest/',
            'prefix': 'archip_',
            'portno_start': 0,
            'portno_end': 0,
            'daemon': True,
            'log_level': 3,
            'direct': False,
            }
    mfiled_args = {
            'role': 'vlmctest-blockerm',
            'spec': XsegTest.spec,
            'nr_ops': 16,
            'archip_dir': '/tmp/mfiledtest/',
            'prefix': 'archip_',
            'portno_start': 1,
            'portno_end': 1,
            'daemon': True,
            'log_level': 3,
            'direct': False,
            }
    mapperd_args = {
            'role': 'vlmctest-mapper',
            'spec': XsegTest.spec,
            'nr_ops': 16,
            'portno_start': 2,
            'portno_end': 2,
            'daemon': True,
            'log_level': 3,
            'blockerb_port': 0,
            'blockerm_port': 1,
            }
    vlmcd_args = {
            'role': 'vlmctest-vlmc',
            'spec': XsegTest.spec,
            'nr_ops': 16,
            'portno_start': 3,
            'portno_end': 3,
            'daemon': True,
            'log_level': 3,
            'blocker_port': 0,
            'mapper_port': 2
            }

    def setUp(self):
        super(VlmcdTest, self).setUp()
        try:
            self.blockerm = self.get_filed(self.mfiled_args, clean=True)
            self.blockerb = self.get_filed(self.bfiled_args, clean=True)
            self.mapperd = self.get_mapperd(self.mapperd_args)
            self.vlmcd = self.get_vlmcd(self.vlmcd_args)
            self.vlmcdport = self.vlmcd.portno_start
            self.mapperdport = self.mapperd.portno_start
            self.blockerbport = self.blockerb.portno_start
            start_peer(self.blockerm)
            start_peer(self.blockerb)
            start_peer(self.mapperd)
            start_peer(self.vlmcd)
        except Exception as e:
            print e
            stop_peer(self.vlmcd)
            stop_peer(self.mapperd)
            stop_peer(self.blockerb)
            stop_peer(self.blockerm)
            super(VlmcdTest, self).tearDown()
            raise e

    def tearDown(self):
        stop_peer(self.vlmcd)
        stop_peer(self.mapperd)
        stop_peer(self.blockerb)
        stop_peer(self.blockerm)
        super(VlmcdTest, self).tearDown()

    def test_open(self):
        volume = "myvolume"
        volsize = 10*1024*1024
        self.send_and_evaluate_open(self.vlmcdport, volume, expected=False)
        self.send_and_evaluate_clone(self.mapperdport, "", clone=volume,
                clone_size=volsize)
        self.send_and_evaluate_open(self.vlmcdport, volume)
        self.send_and_evaluate_open(self.vlmcdport, volume)

    def test_close(self):
        volume = "myvolume"
        volsize = 10*1024*1024
        self.send_and_evaluate_close(self.vlmcdport, volume, expected=False)
        self.send_and_evaluate_clone(self.mapperdport, "", clone=volume,
                clone_size=volsize)
        self.send_and_evaluate_close(self.vlmcdport, volume, expected=False)
        self.send_and_evaluate_open(self.vlmcdport, volume)
        self.send_and_evaluate_close(self.vlmcdport, volume)
        self.send_and_evaluate_close(self.vlmcdport, volume, expected=False)

    def test_info(self):
        volume = "myvolume"
        volsize = 10*1024*1024
        self.send_and_evaluate_clone(self.mapperdport, "", clone=volume,
                clone_size=volsize)
        xinfo = self.get_reply_info(volsize)
        self.send_and_evaluate_info(self.vlmcdport, volume, expected_data=xinfo)

    def test_write_read(self):
        datalen = 1024
        data = get_random_string(datalen, 16)
        volume = "myvolume"
        volsize = 10*1024*1024

        self.send_and_evaluate_write(self.vlmcdport, volume, data=data,
                expected=False)
        self.send_and_evaluate_read(self.vlmcdport, volume, size=datalen,
                expected=False)
        self.send_and_evaluate_clone(self.mapperdport, "", clone=volume,
                clone_size=volsize)
        self.send_and_evaluate_write(self.vlmcdport, volume, data=data,
                serviced=datalen)
        self.send_and_evaluate_read(self.vlmcdport, volume, size=datalen,
                expected_data=data)

    def test_clone_snapshot(self):
        volume = "myvolume"
        snap = "mysnapshot"
        snap2 = "mysnapshot2"
        snap2 = "mysnapshot3"
        clone1 = "myclone1"
        clone2 = "myclone2"

        volsize = 100*1024*1024*1024
        clone2size = 200*1024*1024*1024
        offset = 90*1024*1024*1024
        size = 10*1024*1024

        zeros = '\x00' * size
        data = get_random_string(size, 16)
        data2 = get_random_string(size, 16)

        self.send_and_evaluate_clone(self.mapperdport, "", clone=volume,
                clone_size=volsize)
        self.send_and_evaluate_read(self.vlmcdport, volume, size=size,
                offset=offset, expected_data=zeros)

        self.send_and_evaluate_snapshot(self.vlmcdport, volume, snap=snap)
        self.send_and_evaluate_read(self.vlmcdport, snap, size=size,
                offset=offset, expected_data=zeros)
        self.send_and_evaluate_write(self.vlmcdport, volume, data=data, offset=offset,
                serviced=size)
        self.send_and_evaluate_read(self.vlmcdport, snap, size=size,
                offset=offset, expected_data=zeros)
        self.send_and_evaluate_read(self.vlmcdport, volume, size=size,
                offset=offset, expected_data=data)

        self.send_and_evaluate_snapshot(self.vlmcdport, volume, snap=snap2)
        self.send_and_evaluate_read(self.vlmcdport, snap2, size=size,
                offset=offset, expected_data=data)
        self.send_and_evaluate_clone(self.mapperdport, snap2, clone=clone1,
                clone_size=clone2size)
        self.send_and_evaluate_read(self.vlmcdport, clone1, size=size,
                offset=offset, expected_data=data)
        self.send_and_evaluate_read(self.vlmcdport, clone1, size=size,
                offset=volsize+offset, expected_data=zeros)

        self.send_and_evaluate_write(self.vlmcdport, clone1, data=data2,
				offset=offset, serviced=size)
        self.send_and_evaluate_read(self.vlmcdport, clone1, size=size,
                offset=offset, expected_data=data2)
        self.send_and_evaluate_read(self.vlmcdport, snap2, size=size,
                offset=offset, expected_data=data)
        self.send_and_evaluate_read(self.vlmcdport, volume, size=size,
                offset=offset, expected_data=data)
        self.send_and_evaluate_read(self.vlmcdport, snap, size=size,
                offset=offset, expected_data=zeros)

    def test_info2(self):
        volume = "myvolume"
        volsize = 10*1024*1024
        self.send_and_evaluate_clone(self.mapperdport, "", clone=volume,
                clone_size=volsize)
        xinfo = self.get_reply_info(volsize)
        reqs = Set([])
        reqs.add(self.send_info(self.vlmcdport, volume))
        reqs.add(self.send_info(self.vlmcdport, volume))
        while len(reqs) > 0:
            req = self.xseg.wait_requests(reqs)
            self.evaluate_req(req, data=xinfo)
            reqs.remove(req)
            self.assertTrue(req.put())

    def test_flush(self):
        datalen = 1024
        data = get_random_string(datalen, 16)
        volume = "myvolume"
        volsize = 10*1024*1024

        #This may seems weird, but actually vlmcd flush, only guarantees that
        #there are no pending operation the volume. On a volume that does not
        #exists, this is always true, so this should succeed.
        self.send_and_evaluate_write(self.vlmcdport, volume, data="",
                flags=XF_FLUSH, expected=True)
        self.send_and_evaluate_clone(self.mapperdport, "", clone=volume,
                clone_size=volsize)
        self.send_and_evaluate_write(self.vlmcdport, volume, data="",
                flags=XF_FLUSH)
        self.send_and_evaluate_write(self.vlmcdport, volume, data=data,
                serviced=datalen)
        self.send_and_evaluate_write(self.vlmcdport, volume, data="",
                flags=XF_FLUSH)

    def test_flush2(self):
        volume = "myvolume"
        volsize = 10*1024*1024
        datalen = 1024
        data = get_random_string(datalen, 16)

        self.send_and_evaluate_clone(self.mapperdport, "", clone=volume,
                clone_size=volsize)
        xinfo = self.get_reply_info(volsize)
        reqs = Set([])
        reqs.add(self.send_write(self.vlmcdport, volume, data=data))
        reqs.add(self.send_write(self.vlmcdport, volume, data=data))
        reqs.add(self.send_write(self.vlmcdport, volume, data=data))
        reqs.add(self.send_write(self.vlmcdport, volume, data=data))
        reqs.add(self.send_write(self.vlmcdport, volume, data=data))
        reqs.add(self.send_write(self.vlmcdport, volume, data=data))
        reqs.add(self.send_write(self.vlmcdport, volume, data=data))
        reqs.add(self.send_write(self.vlmcdport, volume, data=data))
        reqs.add(self.send_write(self.vlmcdport, volume, data=data))
        reqs.add(self.send_write(self.vlmcdport, volume, data=data))
        reqs.add(self.send_write(self.vlmcdport, volume, data=data))
        reqs.add(self.send_write(self.vlmcdport, volume, data=data))
        reqs.add(self.send_write(self.vlmcdport, volume, data=data))
        reqs.add(self.send_write(self.vlmcdport, volume, data="", flags=XF_FLUSH))
        reqs.add(self.send_write(self.vlmcdport, volume, data=data))
        reqs.add(self.send_write(self.vlmcdport, volume, data=data))
        reqs.add(self.send_write(self.vlmcdport, volume, data=data))
        reqs.add(self.send_write(self.vlmcdport, volume, data=data))
        reqs.add(self.send_write(self.vlmcdport, volume, data=data))
        reqs.add(self.send_write(self.vlmcdport, volume, data=data))
        while len(reqs) > 0:
            req = self.xseg.wait_requests(reqs)
            self.evaluate_req(req)
            reqs.remove(req)
            self.assertTrue(req.put())

    def test_hash(self):
        blocksize = self.blocksize
        volume = "myvolume"
        volume2 = "myvolume2"
        snap = "snapshot"
        clone = "clone"
        volsize = 10*1024*1024
        size = 512*1024
        epoch = 1
        offset = 0
        data = get_random_string(size, 16)

        self.send_and_evaluate_clone(self.mapperdport, "", clone=volume,
                clone_size=volsize)
        self.send_and_evaluate_write(self.vlmcdport, volume, data=data,
				offset=offset, serviced=size)

        self.send_and_evaluate_snapshot(self.vlmcdport, volume, snap=snap)

        self.send_and_evaluate_hash(self.mapperdport, volume, size=volsize,
                expected=False)
        req = self.send_hash(self.mapperdport, snap, size=volsize)
        req.wait()
        self.assertTrue(req.success())
        xreply = req.get_data(xseg_reply_hash).contents
        hash_map = ctypes.string_at(xreply.target, xreply.targetlen)
        req.put()

        req = self.send_map_read(self.mapperdport, snap, offset=0,
                size=volsize)
        req.wait()
        self.assertTrue(req.success())
        xreply = req.get_data(xseg_reply_map).contents
        blocks = self.get_list_of_hashes(xreply, from_segment=True)
        req.put()
        h = []
        for b in blocks:
            if (b == sha256('').hexdigest()):
                h.append(unhexlify(b))
                continue
            req = self.send_hash(self.blockerbport, b, size=blocksize)
            req.wait()
            self.assertTrue(req.success())
            xreply = req.get_data(xseg_reply_hash).contents
            h.append(unhexlify(ctypes.string_at(xreply.target, xreply.targetlen)))
            req.put()

        mh = hexlify(merkle_hash(h))
        self.assertEqual(hash_map, mh)

#        self.send_and_evaluate_clone(self.mapperdport, hash_map, clone=volume2,
#                clone_size=volsize * 2, expected=False)
        self.send_and_evaluate_clone(self.mapperdport, hash_map, clone=volume2,
                clone_size=volsize * 2)
        self.send_and_evaluate_read(self.vlmcdport, volume2, size=size,
                offset=offset, expected_data=data)
        self.send_and_evaluate_read(self.vlmcdport, volume2, size=volsize - size,
                offset=offset + size, expected_data='\x00' * (volsize - size))


class MapperdTest(XsegTest):
    bfiled_args = {
            'role': 'mappertest-blockerb',
            'spec': XsegTest.spec,
            'nr_ops': 16,
            'archip_dir': '/tmp/bfiledtest/',
            'prefix': 'archip_',
            'portno_start': 0,
            'portno_end': 0,
            'daemon': True,
            'log_level': 3,
            'direct': False,
            }
    mfiled_args = {
            'role': 'mappertest-blockerm',
            'spec': XsegTest.spec,
            'nr_ops': 16,
            'archip_dir': '/tmp/mfiledtest/',
            'prefix': 'archip_',
            'portno_start': 1,
            'portno_end': 1,
            'daemon': True,
            'log_level': 3,
            'direct': False,
            }
    mapperd_args = {
            'role': 'mappertest-mapper',
            'spec': XsegTest.spec,
            'nr_ops': 16,
            'portno_start': 2,
            'portno_end': 2,
            'daemon': True,
            'log_level': 3,
            'blockerb_port': 0,
            'blockerm_port': 1,
            }
    blocksize = 4*1024*1024

    def setUp(self):
        super(MapperdTest, self).setUp()
        try:
            self.blockerm = self.get_filed(self.mfiled_args, clean=True)
            self.blockerb = self.get_filed(self.bfiled_args, clean=True)
            self.mapperd = self.get_mapperd(self.mapperd_args)
            self.mapperdport = self.mapperd.portno_start
            start_peer(self.blockerm)
            start_peer(self.blockerb)
            start_peer(self.mapperd)
        except Exception as e:
            print e
            stop_peer(self.mapperd)
            stop_peer(self.blockerb)
            stop_peer(self.blockerm)
            super(MapperdTest, self).tearDown()
            raise e

    def tearDown(self):
        stop_peer(self.mapperd)
        stop_peer(self.blockerb)
        stop_peer(self.blockerm)
        super(MapperdTest, self).tearDown()

    def test_create(self):
        volume = "myvolume"
        volsize = 10*1024*1024
        self.send_and_evaluate_clone(self.mapperdport, "", clone=volume,
                clone_size=0, expected=False)
        self.send_and_evaluate_clone(self.mapperdport, "", clone=volume,
                clone_size=volsize)
        self.send_and_evaluate_clone(self.mapperdport, "", clone=volume,
                clone_size=volsize, expected=False)

    def test_delete(self):
        volume = "myvolume"
        volsize = 10*1024*1024
        offset = 0
        size = 10
        epoch = 2

        self.send_and_evaluate_clone(self.mapperdport, "", clone=volume,
                clone_size=0, expected=False)
        self.send_and_evaluate_clone(self.mapperdport, "", clone=volume,
                clone_size=volsize)
        self.send_and_evaluate_clone(self.mapperdport, "", clone=volume,
                clone_size=volsize, expected=False)
        self.send_and_evaluate_delete(self.mapperdport, volume)
        self.send_and_evaluate_delete(self.mapperdport, volume, expected=False)
        self.send_and_evaluate_map_write(self.mapperdport, volume,
                offset=offset, size=size, expected=False)
        self.send_and_evaluate_clone(self.mapperdport, "", clone=volume,
                clone_size=volsize)

        ret = self.get_copy_map_reply(volume, offset, size, epoch)

        self.send_and_evaluate_map_write(self.mapperdport, volume,
                expected_data=ret, offset=offset, size=size)

    def test_clone_snapshot(self):
        volume = "myvolume"
        snap = "mysnapshot"
        snap2 = "mysnapshot2"
        snap2 = "mysnapshot3"
        clone1 = "myclone1"
        clone2 = "myclone2"
        volsize = 100*1024*1024*1024
        clone2size = 200*1024*1024*1024
        offset = 90*1024*1024*1024
        size = 10*1024*1024
        offset = 0
        size = volsize
        epoch = 2

        self.send_and_evaluate_clone(self.mapperdport, "", clone=volume,
                clone_size=volsize)
        self.send_and_evaluate_snapshot(self.mapperdport, volume, snap=snap)
        self.send_and_evaluate_snapshot(self.mapperdport, volume, snap=snap,
                expected=False)
        xinfo = self.get_reply_info(volsize)
        self.send_and_evaluate_info(self.mapperdport, snap, expected_data=xinfo)
        ret = self.get_zero_map_reply(offset, size)
        self.send_and_evaluate_map_read(self.mapperdport, volume,
                expected_data=ret, offset=offset, size=size)
        self.send_and_evaluate_map_read(self.mapperdport, snap,
                expected_data=ret, offset=offset, size=size)

        ret = self.get_copy_map_reply(volume, offset, size, epoch)
        self.send_and_evaluate_map_write(self.mapperdport, volume,
                expected_data=ret, offset=offset, size=size)

        stop_peer(self.mapperd)
        start_peer(self.mapperd)
        self.send_and_evaluate_map_read(self.mapperdport, volume,
                expected_data=ret, offset=offset, size=size)

        self.send_and_evaluate_clone(self.mapperdport, snap, clone=clone1)
        xinfo = self.get_reply_info(volsize)
        self.send_and_evaluate_info(self.mapperdport, clone1, expected_data=xinfo)
        self.send_and_evaluate_clone(self.mapperdport, snap, clone=clone2,
                clone_size=2, expected=False)
        self.send_and_evaluate_clone(self.mapperdport, snap, clone=clone2,
                clone_size=clone2size)
        xinfo = self.get_reply_info(clone2size)
        self.send_and_evaluate_info(self.mapperdport, clone2, expected_data=xinfo)

    def test_info(self):
        volume = "myvolume"
        volsize = 10*1024*1024
        self.send_and_evaluate_clone(self.mapperdport, "", clone=volume,
                clone_size=volsize)
        xinfo = self.get_reply_info(volsize)
        self.send_and_evaluate_info(self.mapperdport, volume, expected_data=xinfo)

    def test_info2(self):
        volume = "myvolume"
        volsize = 10*1024*1024
        self.send_and_evaluate_clone(self.mapperdport, "", clone=volume,
                clone_size=volsize)
        xinfo = self.get_reply_info(volsize)
        reqs = Set([])
        reqs.add(self.send_info(self.mapperdport, volume))
        reqs.add(self.send_info(self.mapperdport, volume))
        while len(reqs) > 0:
            req = self.xseg.wait_requests(reqs)
            self.evaluate_req(req, data=xinfo)
            reqs.remove(req)
            self.assertTrue(req.put())

    def test_open(self):
        volume = "myvolume"
        volsize = 10*1024*1024
        self.send_and_evaluate_open(self.mapperdport, volume, expected=False)
        self.send_and_evaluate_clone(self.mapperdport, "", clone=volume,
                clone_size=volsize)
        self.send_and_evaluate_open(self.mapperdport, volume)
        self.send_and_evaluate_open(self.mapperdport, volume)

    def test_open2(self):
        volume = "myvolume"
        volsize = 10*1024*1024
        self.send_and_evaluate_clone(self.mapperdport, "", clone=volume,
                clone_size=volsize)
        reqs = Set([])
        reqs.add(self.send_open(self.mapperdport, volume))
        reqs.add(self.send_open(self.mapperdport, volume))
        while len(reqs) > 0:
            req = self.xseg.wait_requests(reqs)
            self.evaluate_req(req)
            reqs.remove(req)
            self.assertTrue(req.put())

    def test_close(self):
        volume = "myvolume"
        volsize = 10*1024*1024
        self.send_and_evaluate_close(self.mapperdport, volume, expected=False)
        self.send_and_evaluate_clone(self.mapperdport, "", clone=volume,
                clone_size=volsize)
        self.send_and_evaluate_close(self.mapperdport, volume, expected=False)
        self.send_and_evaluate_open(self.mapperdport, volume)
        self.send_and_evaluate_close(self.mapperdport, volume)
        self.send_and_evaluate_close(self.mapperdport, volume, expected=False)

    def test_mapr(self):
        volume = "myvolume"
        volsize = 10*1024*1024
        offset = 0
        size = volsize
        ret = MapperdTest.get_zero_map_reply(offset, size)
        self.send_and_evaluate_map_read(self.mapperdport, volume,
                offset=offset, size=size, expected=False)
        self.send_and_evaluate_clone(self.mapperdport, "", clone=volume,
                clone_size=volsize)
        self.send_and_evaluate_map_read(self.mapperdport, volume,
                expected_data=ret, offset=offset, size=size)
        offset = volsize - 1
        self.send_and_evaluate_map_read(self.mapperdport, volume,
                offset=offset, size=size, expected=False)
        offset = volsize + 1
        self.send_and_evaluate_map_read(self.mapperdport, volume,
                offset=offset, size=size, expected=False)

    def test_mapr2(self):
        volume = "myvolume"
        volsize = 10*1024*1024
        offset = 0
        size = volsize

        self.send_and_evaluate_clone(self.mapperdport, "", clone=volume,
                clone_size=volsize)
        reqs = Set([])
        reqs.add(self.send_map_read(self.mapperdport, volume, offset=offset,
            size=size))
        reqs.add(self.send_map_read(self.mapperdport, volume, offset=offset,
            size=size))
        ret = MapperdTest.get_zero_map_reply(offset, size)
        while len(reqs) > 0:
            req = self.xseg.wait_requests(reqs)
            self.evaluate_req(req, data=ret)
            reqs.remove(req)
            self.assertTrue(req.put())

    def test_mapr3(self):
        volume = "myvolume"
        volsize = 10*1024*1024
        offset = 0
        size = volsize


        self.send_and_evaluate_clone(self.mapperdport, "", clone=volume,
                clone_size=volsize)
        stop_peer(self.mapperd)
        start_peer(self.mapperd)

        self.send_and_evaluate_acquire(self.blockerm.portno_start, volume, expected=True)
        stop_peer(self.blockerm)
        new_filed_args = copy(self.mfiled_args)
        new_filed_args['unique_str'] = 'ThisisSparta'
        self.blockerm = Filed(**new_filed_args)
        start_peer(self.blockerm)

        reqs = Set([])
        reqs.add(self.send_map_read(self.mapperdport, volume, offset=offset,
            size=size))
        reqs.add(self.send_map_read(self.mapperdport, volume, offset=offset,
            size=size))
        ret = MapperdTest.get_zero_map_reply(offset, size)
        while len(reqs) > 0:
            req = self.xseg.wait_requests(reqs)
            self.evaluate_req(req, data=ret)
            reqs.remove(req)
            self.assertTrue(req.put())

    def test_mapw(self):
        blocksize = self.blocksize
        volume = "myvolume"
        volsize = 100*1024*1024*1024
        offset = 90*1024*1024*1024 - 2
        size = 512*1024
        epoch = 1

        ret = self.get_copy_map_reply(volume, offset, size, epoch)

        self.send_and_evaluate_map_write(self.mapperdport, volume,
                offset=offset, size=size, expected=False)
        self.send_and_evaluate_clone(self.mapperdport, "", clone=volume,
                clone_size=volsize)
        self.send_and_evaluate_map_write(self.mapperdport, volume,
                expected_data=ret, offset=offset, size=size)
        self.send_and_evaluate_map_read(self.mapperdport, volume,
                expected_data = ret, offset=offset, size=size)
        stop_peer(self.mapperd)
        start_peer(self.mapperd)
        self.send_and_evaluate_map_read(self.mapperdport, volume,
                expected_data=ret, offset=offset, size=size)
        self.send_and_evaluate_open(self.mapperdport, volume)
        offset = 101*1024*1024*1024
        self.send_and_evaluate_map_write(self.mapperdport, volume,
                offset=offset, size=size, expected=False)
        offset = 100*1024*1024*1024 - 1
        self.send_and_evaluate_map_write(self.mapperdport, volume,
                offset=offset, size=size, expected=False)

    def test_rename(self):
        blocksize = self.blocksize
        volume = "myvolume"
        newvolume = "newvolume"
        volsize = 100*1024*1024*1024
        offset = 90*1024*1024*1024 - 2
        size = 512*1024
        epoch = 1
        snap = "snapshot"

        ret = self.get_copy_map_reply(volume, offset, size, epoch)
        self.send_and_evaluate_rename(self.mapperdport, volume,
                newname=newvolume, expected=False)
        self.send_and_evaluate_clone(self.mapperdport, "", clone=volume,
                clone_size=volsize)
        self.send_and_evaluate_map_write(self.mapperdport, volume,
                expected_data=ret, offset=offset, size=size)
        self.send_and_evaluate_map_read(self.mapperdport, volume,
                expected_data = ret, offset=offset, size=size)
        self.send_and_evaluate_rename(self.mapperdport, volume,
                newname=newvolume)

        self.send_and_evaluate_map_write(self.mapperdport, volume,
                offset=offset, size=size, expected=False)
        self.send_and_evaluate_map_read(self.mapperdport, volume,
                offset=offset, size=size, expected=False)

        self.send_and_evaluate_map_read(self.mapperdport, newvolume,
                expected_data = ret, offset=offset, size=size)
        self.send_and_evaluate_map_write(self.mapperdport, newvolume,
                expected_data=ret, offset=offset, size=size)

        self.send_and_evaluate_clone(self.mapperdport, "", clone=newvolume,
                clone_size=volsize, expected=False)

        self.send_and_evaluate_snapshot(self.mapperdport, newvolume, snap=snap)

        stop_peer(self.mapperd)
        start_peer(self.mapperd)

        self.send_and_evaluate_map_read(self.mapperdport, newvolume,
                expected_data = ret, offset=offset, size=size)
        self.send_and_evaluate_map_read(self.mapperdport, snap,
                expected_data = ret, offset=offset, size=size)

        ret = self.get_copy_map_reply(newvolume, offset, size, epoch+1)
        self.send_and_evaluate_map_write(self.mapperdport, newvolume,
                expected_data=ret, offset=offset, size=size)



    def test_mapw2(self):
        blocksize = self.blocksize
        volume = "myvolume"
        volsize = 100*1024*1024*1024
        offset = 90*1024*1024*1024 - 2
        size = 512*1024
        epoch = 1

        ret = self.get_copy_map_reply(volume, offset, size, epoch)

        self.send_and_evaluate_clone(self.mapperdport, "", clone=volume,
                clone_size=volsize)

        reqs = Set([])
        reqs.add(self.send_map_write(self.mapperdport, volume, offset=offset,
            size=size))
        reqs.add(self.send_map_write(self.mapperdport, volume, offset=offset,
            size=size))
        reqs.add(self.send_map_write(self.mapperdport, volume, offset=offset,
            size=size))
        reqs.add(self.send_map_write(self.mapperdport, volume, offset=offset,
            size=size))
        reqs.add(self.send_map_write(self.mapperdport, volume, offset=offset,
            size=size))
        reqs.add(self.send_map_write(self.mapperdport, volume, offset=offset,
            size=size))
        reqs.add(self.send_map_write(self.mapperdport, volume, offset=offset,
            size=size))
        while len(reqs) > 0:
            req = self.xseg.wait_requests(reqs)
            self.evaluate_req(req, data=ret)
            reqs.remove(req)
            self.assertTrue(req.put())

    def test_create(self):
        blocksize = self.blocksize
        volume = "myvolume"
        volume2 = "myvolume2"
        volume3 = "myvolume3"
        volume4 = "myvolume4"
        volsize = 100*1024*1024
        offset = 0
        epoch = 1

        ret = self.get_copy_map_reply(volume, offset, volsize, epoch)

        #create a new volume
        self.send_and_evaluate_clone(self.mapperdport, "", clone=volume,
                clone_size=volsize)
        #write it and get objects
        self.send_and_evaluate_map_write(self.mapperdport, volume,
                expected_data=ret, offset=offset, size=volsize)


        object_flags = XF_MAPFLAG_READONLY
        objects = []
        for i in range(0, ret.cnt):
            objects.append({'name': ret.segs[i].target, 'flags': object_flags})

        #try to create a new volume with the same name from these objects
        self.send_and_evaluate_create(self.mapperdport, volume, size=volsize,
                objects=objects, mapflags=0, blocksize=blocksize, expected=False)
        #try to create a volume with less objects
        self.send_and_evaluate_create(self.mapperdport, volume, size=2*volsize,
                objects=objects, mapflags=0, blocksize=blocksize, expected=False)

        #try to create a new volume with another name from these objects
        self.send_and_evaluate_create(self.mapperdport, volume2, size=volsize,
                objects=objects, mapflags=0, blocksize=blocksize)
        #read it. Assert same objects.
        self.send_and_evaluate_map_read(self.mapperdport, volume,
                expected_data=ret, offset=offset, size=volsize)

        ret2 = self.get_copy_map_reply(volume2, offset, volsize, epoch)
        #write it and assert new objects.
        self.send_and_evaluate_map_write(self.mapperdport, volume2,
                expected_data=ret2, offset=offset, size=volsize)

        #create a new map from the same objects but without the readonly flag
        #on the objects
        for i in range(0, len(objects)):
            objects[i]['flags'] = 0
        self.send_and_evaluate_create(self.mapperdport, volume3, size=volsize,
                objects=objects, mapflags=0, blocksize=blocksize)
        #write it and assert same objects.
        self.send_and_evaluate_map_write(self.mapperdport, volume3,
                expected_data=ret, offset=offset, size=volsize)

        for i in range(0, len(objects)):
            objects[i]['flags'] = XF_MAPFLAG_READONLY
        #create a new volume with read only flag
        self.send_and_evaluate_create(self.mapperdport, volume4, size=volsize,
                objects=objects, mapflags=XF_MAPFLAG_READONLY, blocksize=blocksize)
        #write it. Assert failed
        self.send_and_evaluate_map_write(self.mapperdport, volume4,
                offset=offset, size=volsize, expected=False)

class BlockerTest(object):
    def test_write_read(self):
        datalen = 1024
        data = get_random_string(datalen, 16)
        target = "mytarget"
        xinfo = self.get_reply_info(datalen)

        self.send_and_evaluate_write(self.blockerport, target, data=data,
                serviced=datalen)
        self.send_and_evaluate_read(self.blockerport, target, size=datalen,
                expected_data=data)
        self.send_and_evaluate_info(self.blockerport, target, expected_data=xinfo)
        stop_peer(self.blocker)
        start_peer(self.blocker)
        self.send_and_evaluate_read(self.blockerport, target, size=datalen,
                expected_data=data)
        self.send_and_evaluate_info(self.blockerport, target, expected_data=xinfo)

    def test_info(self):
        datalen = 1024
        data = get_random_string(datalen, 16)
        target = "mytarget"
        self.send_and_evaluate_write(self.blockerport, target, data=data,
                serviced=datalen)
        xinfo = self.get_reply_info(datalen)
        self.send_and_evaluate_info(self.blockerport, target, expected_data=xinfo)

    def test_copy(self):
        datalen = 1024
        data = get_random_string(datalen, 16)
        target = "mytarget"
        copy_target = "copy_target"

        self.send_and_evaluate_write(self.blockerport, target, data=data,
                serviced=datalen)
        self.send_and_evaluate_read(self.blockerport, target, size=datalen,
                expected_data=data, serviced=datalen)
        self.send_and_evaluate_copy(self.blockerport, target, dst_target=copy_target,
                size=datalen, serviced=datalen)
        self.send_and_evaluate_copy(self.blockerport, target, dst_target=copy_target,
                size=datalen+1, serviced=datalen+1)
        self.send_and_evaluate_read(self.blockerport, copy_target, size=datalen,
                expected_data=data)


    def test_delete(self):
        datalen = 1024
        data = get_random_string(datalen, 16)
        target = "mytarget"
        self.send_and_evaluate_delete(self.blockerport, target, False)
        self.send_and_evaluate_write(self.blockerport, target, data=data)
        self.send_and_evaluate_read(self.blockerport, target, size=datalen,
                expected_data=data)
        self.send_and_evaluate_delete(self.blockerport, target, True)
        data = '\x00' * datalen
        self.send_and_evaluate_read(self.blockerport, target, size=datalen,
                expected=False)

    def test_hash(self):
        datalen = 1024
        data = '\x00'*datalen
        target = "target_zeros"


        self.send_and_evaluate_write(self.blockerport, target, data=data,
                serviced=datalen)
        ret = self.get_hash_reply(sha256(data.rstrip('\x00')).hexdigest())
        self.send_and_evaluate_hash(self.blockerport, target, size=datalen,
                expected_data=ret, serviced=datalen)

        target = "mytarget"
        data = get_random_string(datalen, 16)
        self.send_and_evaluate_write(self.blockerport, target, data=data,
                serviced=datalen)
        ret = self.get_hash_reply(sha256(data.rstrip('\x00')).hexdigest())
        self.send_and_evaluate_hash(self.blockerport, target, size=datalen,
                expected_data=ret, serviced=datalen)
        self.send_and_evaluate_hash(self.blockerport, target, size=datalen,
                expected_data=ret, serviced=datalen)
        self.send_and_evaluate_hash(self.blockerport, target, size=datalen,
                expected_data=ret, serviced=datalen)

    def test_locking(self):
        target = "mytarget"
        self.send_and_evaluate_acquire(self.blockerport, target, expected=True)
        self.send_and_evaluate_acquire(self.blockerport, target, expected=True)
        self.send_and_evaluate_release(self.blockerport, target, expected=True)
        self.send_and_evaluate_release(self.blockerport, target, expected=False)
        self.send_and_evaluate_acquire(self.blockerport, target, expected=True)
        stop_peer(self.blocker)
        start_peer(self.blocker)
        self.send_and_evaluate_acquire(self.blockerport, target, expected=False)
        self.send_and_evaluate_release(self.blockerport, target, expected=False)
        self.send_and_evaluate_release(self.blockerport, target, force=True,
                expected=True)


class FiledTest(BlockerTest, XsegTest):
    filed_args = {
            'role': 'testfiled',
            'spec': XsegTest.spec,
            'nr_ops': 16,
            'archip_dir': '/tmp/filedtest/',
            'prefix': 'archip_',
            'portno_start': 0,
            'portno_end': 0,
            'daemon': True,
            'log_level': 3,
            'direct': False,
            }

    def setUp(self):
        super(FiledTest, self).setUp()
        try:
            self.blocker = self.get_filed(self.filed_args, clean=True)
            self.blockerport = self.blocker.portno_start
            start_peer(self.blocker)
        except Exception as e:
            super(FiledTest, self).tearDown()
            raise e

    def tearDown(self):
        stop_peer(self.blocker)
        super(FiledTest, self).tearDown()

    def test_locking(self):
        target = "mytarget"
        self.send_and_evaluate_acquire(self.blockerport, target, expected=True)
        self.send_and_evaluate_acquire(self.blockerport, target, expected=True)
        self.send_and_evaluate_release(self.blockerport, target, expected=True)
        self.send_and_evaluate_release(self.blockerport, target, expected=False)
        self.send_and_evaluate_acquire(self.blockerport, target, expected=True)
        stop_peer(self.blocker)
        new_filed_args = copy(self.filed_args)
        new_filed_args['unique_str'] = 'ThisisSparta'
        self.blocker = Filed(**new_filed_args)
        start_peer(self.blocker)
        self.send_and_evaluate_acquire(self.blockerport, target, expected=False)
        self.send_and_evaluate_release(self.blockerport, target, expected=False)
        self.send_and_evaluate_release(self.blockerport, target, force=True,
                expected=True)

class RadosdTest(BlockerTest, XsegTest):
    filed_args = {
            'role': 'testradosd',
            'spec': XsegTest.spec,
            'nr_ops': 16,
            'portno_start': 0,
            'portno_end': 0,
            'daemon': True,
            'log_level': 3,
            'pool': 'test_radosd',
            'nr_threads': 3,
            }

    def setUp(self):
        super(RadosdTest, self).setUp()
        try:
            self.blocker = self.get_radosd(self.filed_args, clean=True)
            self.blockerport = self.blocker.portno_start
            start_peer(self.blocker)
        except Exception as e:
            super(RadosdTest, self).tearDown()
            raise e

    def tearDown(self):
        stop_peer(self.blocker)
        super(RadosdTest, self).tearDown()

if __name__=='__main__':
    init()
    unittest.main()
