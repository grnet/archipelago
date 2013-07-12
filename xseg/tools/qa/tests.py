import archipelago
from archipelago.common import Xseg_ctx, Request, Filed, Mapperd, Vlmcd, create_segment, destroy_segment
from archipelago.archipelago import start_peer, stop_peer
import random as rnd
import unittest
from xseg.xprotocol import *
from xseg.xseg_api import *
import ctypes
import os
from copy import copy

rnd.seed()
archipelago.common.BIN_DIR='/home/philipgian/code/archipelago/xseg/peers/user/'
archipelago.common.LOGS_PATH=os.path.join(os.getcwd(), 'logs')
archipelago.common.PIDFILE_PATH=os.path.join(os.getcwd(), 'pids')
if not os.path.isdir(archipelago.common.LOGS_PATH):
    os.makedirs(archipelago.common.LOGS_PATH)
if not os.path.isdir(archipelago.common.PIDFILE_PATH):
    os.makedirs(archipelago.common.PIDFILE_PATH)

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



class XsegTest(unittest.TestCase):
    xseg = None
    myport = 15
    spec = "posix:testsegment:16:256:12".encode()

    def setUp(self):
        try:
            create_segment(self.spec)
        except:
            destroy_segment(self.spec)
            create_segment(self.spec)
        self.xseg = Xseg_ctx(self.spec, self.myport)

    def tearDown(self):
        if self.xseg:
            self.xseg.shutdown()
        destroy_segment(self.spec)

    @staticmethod
    def get_reply_info(size):
        xinfo = xseg_reply_info()
        xinfo.size = size
        return xinfo

    def get_req(self, op, dst, target, data=None, size=None, offset=0, datalen=0,
            flags=0):
        targetlen = len(target)
        if not datalen and data:
            datalen = len(data)
        req = Request(self.xseg, dst, targetlen, datalen)
        req.set_op(op)
        if size is not None:
            req.set_size(size)
        else:
            req.set_size(datalen)
        req.set_offset(offset)
        req.set_flags(flags)
        self.assertTrue(req.set_target(target))
        if data:
            self.assertTrue(req.set_data(data))
        return req

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
            #expected_array = SegsArray.from_address(ctypes.addressof(expected_data.segs))
            expected_array = expected_data.segs
            for i in range(0, cnt):
                t = ctypes.string_at(array[i].target, array[i].targetlen)
                self.assertEqual(array[i].targetlen, expected_array[i].targetlen)
                self.assertEqual(t, expected_array[i].target)
                self.assertEqual(array[i].offset, expected_array[i].offset)
                self.assertEqual(array[i].size, expected_array[i].size)
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

    def send_write(self, dst, target, data=None, offset=0, datalen=0):
        req = self.get_req(X_WRITE, dst, target, data, offset=offset, datalen=datalen)
        req.submit()
        return req

    send_and_evaluate_write = evaluate(send_write)

    def send_read(self, dst, target, size=0, datalen=0, offset=0):
        if not datalen:
            datalen=size
        req = self.get_req(X_READ, dst, target, data=None, size=size, offset=offset, datalen=datalen)
        req.submit()
        return req

    send_and_evaluate_read = evaluate(send_read)

    def send_info(self, dst, target):
        req = self.get_req(X_INFO, dst, target, data=None, size=0)
        req.submit()
        return req

    send_and_evaluate_info = evaluate(send_info)

    def send_copy(self, dst, src_target, dst_target=None, size=0, offset=0):
        datalen = ctypes.sizeof(xseg_request_copy)
        xcopy = xseg_request_copy()
        xcopy.target = src_target
        xcopy.targetlen = len(src_target)
        req = self.get_req(X_COPY, dst, dst_target, xcopy, datalen=datalen,
                offset=offset)
        req.submit()
        return req

    send_and_evaluate_copy = evaluate(send_copy)

    def send_acquire(self, dst, target):
        req = self.get_req(X_ACQUIRE, dst, target, flags=XF_NOSYNC)
        req.submit()
        return req

    send_and_evaluate_acquire = evaluate(send_acquire)

    def send_release(self, dst, target, force=False):
        req_flags = XF_NOSYNC
        if force:
            req_flags |= XF_FORCE
        req = self.get_req(X_RELEASE, dst, target, size=0, flags=req_flags)
        req.submit()
        return req

    send_and_evaluate_release = evaluate(send_release)

    def send_delete(self, dst, target):
        req = self.get_req(X_DELETE, dst, target)
        req.submit()
        return req

    send_and_evaluate_delete = evaluate(send_delete)

    def send_clone(self, dst, src_target, clone=None, clone_size=0):
        xclone = xseg_request_clone()
        xclone.target = src_target
        xclone.targetlen = len(src_target)
        xclone.size = clone_size

        req = self.get_req(X_CLONE, dst, clone, data=xclone,
                datalen=ctypes.sizeof(xclone))
        req.submit()
        return req

    send_and_evaluate_clone = evaluate(send_clone)

    def send_snapshot(self, dst, src_target, snap=None):
        xsnapshot = xseg_request_snapshot()
        xsnapshot.target = snap
        xsnapshot.targetlen = len(snap)

        req = self.get_req(X_SNAPSHOT, dst, src_target, data=xsnapshot,
                datalen=ctypes.sizeof(xsnapshot))
        req.submit()
        return req

    send_and_evaluate_snapshot = evaluate(send_snapshot)

    def send_open(self, dst, target):
        req = self.get_req(X_OPEN, dst, target)
        req.submit()
        return req

    send_and_evaluate_open = evaluate(send_open)

    def send_close(self, dst, target):
        req = self.get_req(X_CLOSE, dst, target)
        req.submit()
        return req

    send_and_evaluate_close = evaluate(send_close)

    def send_map_read(self, dst, target, offset=0, size=0):
        req = self.get_req(X_MAPR, dst, target, size=size, offset=offset,
                datalen=0)
        req.submit()
        return req

    send_and_evaluate_map_read = evaluate(send_map_read)

    def send_map_write(self, dst, target, offset=0, size=0):
        req = self.get_req(X_MAPW, dst, target, size=size, offset=offset,
                datalen=0)
        req.submit()
        return req

    send_and_evaluate_map_write = evaluate(send_map_write)

    def get_filed(self, args, clean=False):
        path = args['archip_dir']
        if not os.path.exists(path):
            os.makedirs(path)

        if clean:
            for root, dirs, files in os.walk(path, topdown=False):
                for name in files:
                    os.remove(os.path.join(root, name))
                for name in dirs:
                    os.rmdir(os.path.join(root, name))

        return Filed(**args)

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
            }
    mfiled_args = {
            'role': 'vlmctest-blockerm',
            'spec': XsegTest.spec,
            'nr_ops': 16,
            'archip_dir': '/tmp/bfiledtest/',
            'prefix': 'archip_',
            'portno_start': 1,
            'portno_end': 1,
            'daemon': True,
            'log_level': 3,
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
    blocksize = 4*1024*1024

    def setUp(self):
        super(VlmcdTest, self).setUp()
        try:
            self.blockerm = self.get_filed(self.mfiled_args, clean=True)
            self.blockerb = self.get_filed(self.bfiled_args, clean=True)
            self.mapperd = self.get_mapperd(self.mapperd_args)
            self.vlmcd = self.get_vlmcd(self.vlmcd_args)
            self.vlmcdport = self.vlmcd.portno_start
            self.mapperdport = self.mapperd.portno_start
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
        self.send_and_evaluate_write(self.vlmcdport, volume, data=data)
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
        clone2size = 200*1024*1024*104
        offset = 90*1024*1024*1024
        size = 10*1024*1024

        zeros = '\x00' * size
        data = get_random_string(size, 16)

        self.send_and_evaluate_clone(self.mapperdport, "", clone=volume,
                clone_size=volsize)
        self.send_and_evaluate_read(self.vlmcdport, volume, size=size,
                offset=offset, expected_data=zeros)

        self.send_and_evaluate_snapshot(self.mapperdport, volume, snap=snap)
        self.send_and_evaluate_read(self.vlmcdport, snap, size=size,
                offset=offset, expected_data=zeros)
        self.send_and_evaluate_write(self.vlmcdport, volume, data=data, offset=offset)
        self.send_and_evaluate_read(self.vlmcdport, snap, size=size,
                offset=offset, expected_data=zeros)
        self.send_and_evaluate_read(self.vlmcdport, volume, size=size,
                offset=offset, expected_data=data)



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
            }
    mfiled_args = {
            'role': 'mappertest-blockerm',
            'spec': XsegTest.spec,
            'nr_ops': 16,
            'archip_dir': '/tmp/bfiledtest/',
            'prefix': 'archip_',
            'portno_start': 1,
            'portno_end': 1,
            'daemon': True,
            'log_level': 3,
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

    @staticmethod
    def get_object_name(volume, epoch, index):
        from binascii import hexlify
        epoch_64 = ctypes.c_uint64(epoch)
        index_64 = ctypes.c_uint64(index)
        epoch_64_char = ctypes.cast(ctypes.addressof(epoch_64), ctypes.c_char_p)
        index_64_char = ctypes.cast(ctypes.addressof(index_64), ctypes.c_char_p)
        epoch_64_str = ctypes.string_at(epoch_64_char, ctypes.sizeof(ctypes.c_uint64))
        index_64_str = ctypes.string_at(index_64_char, ctypes.sizeof(ctypes.c_uint64))
        epoch_hex = hexlify(epoch_64_str)
        index_hex = hexlify(index_64_str)
        return "archip_" + volume + "_" + epoch_hex + "_" + index_hex

    @staticmethod
    def get_map_reply(offset, size):
        blocksize = MapperdTest.blocksize
        ret = xseg_reply_map()
        cnt = (offset+size)//blocksize - offset//blocksize
        if (offset+size) % blocksize > 0 :
            cnt += 1
        xseg_reply_map.cnt = cnt
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
    def get_zero_map_reply(offset, size):
        ret = MapperdTest.get_map_reply(offset, size);
        cnt = ret.cnt
        for i in range(0, cnt):
            ret.segs[i].target = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            ret.segs[i].targetlen = len(ret.segs[i].target)
        return ret

    @staticmethod
    def get_copy_map_reply(volume, offset, size, epoch):
        blocksize = MapperdTest.blocksize
        objidx_start = offset//blocksize
        ret = MapperdTest.get_map_reply(offset, size);
        cnt = ret.cnt
        for i in range(0, cnt):
            ret.segs[i].target = MapperdTest.get_object_name(volume, epoch,
                    objidx_start+i)
            ret.segs[i].targetlen = len(ret.segs[i].target)
        return ret

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
        clone2size = 200*1024*1024*104
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

#        self.send_and_evaluate_clone(self.mapperdport, snap, clone1)
#        self.send_and_evaluate_info(self.mapperdport, clone1, volsize)
#        self.send_and_evaluate_clone(self.mapperdport, snap, clone2,
#                dst_size=clone2size)
#        self.send_and_evaluate_info(self.mapperdport, clone2, clone2size)

    def test_info(self):
        volume = "myvolume"
        volsize = 10*1024*1024
        self.send_and_evaluate_clone(self.mapperdport, "", clone=volume,
                clone_size=volsize)
        xinfo = self.get_reply_info(volsize)
        self.send_and_evaluate_info(self.mapperdport, volume, expected=xinfo)

    def test_open(self):
        volume = "myvolume"
        volsize = 10*1024*1024
        self.send_and_evaluate_open(self.mapperdport, volume, expected=False)
        self.send_and_evaluate_clone(self.mapperdport, "", clone=volume,
                clone_size=volsize)
        self.send_and_evaluate_open(self.mapperdport, volume)
        self.send_and_evaluate_open(self.mapperdport, volume)

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
        offset = 101*1024*1024*1024
        self.send_and_evaluate_map_write(self.mapperdport, volume,
                offset=offset, size=size, expected=False)
        offset = 100*1024*1024*1024 - 1
        self.send_and_evaluate_map_write(self.mapperdport, volume,
                offset=offset, size=size, expected=False)

class FiledTest(XsegTest):
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
            }

    def setUp(self):
        super(FiledTest, self).setUp()
        try:
            self.filed = self.get_filed(self.filed_args, clean=True)
            self.filedport = self.filed.portno_start
            start_peer(self.filed)
        except Exception as e:
            super(FiledTest, self).tearDown()
            raise e

    def tearDown(self):
        stop_peer(self.filed)
        super(FiledTest, self).tearDown()

    def test_write_read(self):
        datalen = 1024
        data = get_random_string(datalen, 16)
        target = "mytarget"

        self.send_and_evaluate_write(self.filedport, target, data=data)
        self.send_and_evaluate_read(self.filedport, target, size=datalen,
                expected_data=data)
        stop_peer(self.filed)
        start_peer(self.filed)
        self.send_and_evaluate_read(self.filedport, target, size=datalen,
                expected_data=data)
        xinfo = self.get_reply_info(datalen)
        self.send_and_evaluate_info(self.filedport, target, expected_data=xinfo)

    def test_info(self):
        datalen = 1024
        data = get_random_string(datalen, 16)
        target = "mytarget"
        self.send_and_evaluate_write(self.filedport, target, data=data)
        xinfo = self.get_reply_info(datalen)
        self.send_and_evaluate_info(self.filedport, target, expected_data=xinfo)

    def test_copy(self):
        datalen = 1024
        data = get_random_string(datalen, 16)
        target = "mytarget"
        copy_target = "copy_target"

        self.send_and_evaluate_write(self.filedport, target, data=data)
        self.send_and_evaluate_read(self.filedport, target, size=datalen,
                expected_data=data)
        self.send_and_evaluate_copy(self.filedport, target, dst_target=copy_target,
                size=datalen, serviced=datalen)
        self.send_and_evaluate_read(self.filedport, copy_target, size=datalen,
                expected_data=data)

    def test_locking(self):
        target = "mytarget"
        self.send_and_evaluate_acquire(self.filedport, target, expected=True)
        self.send_and_evaluate_acquire(self.filedport, target, expected=True)
        self.send_and_evaluate_release(self.filedport, target, expected=True)
        self.send_and_evaluate_release(self.filedport, target, expected=False)
        self.send_and_evaluate_acquire(self.filedport, target, expected=True)
        stop_peer(self.filed)
        new_filed_args = copy(self.filed_args)
        new_filed_args['unique_str'] = 'ThisisSparta'
        self.filed = Filed(**new_filed_args)
        start_peer(self.filed)
        self.send_and_evaluate_acquire(self.filedport, target, expected=False)
        self.send_and_evaluate_release(self.filedport, target, expected=False)
        self.send_and_evaluate_release(self.filedport, target, force=True,
                expected=True)

    def test_delete(self):
        datalen = 1024
        data = get_random_string(datalen, 16)
        target = "mytarget"
        self.send_and_evaluate_delete(self.filedport, target, False)
        self.send_and_evaluate_write(self.filedport, target, data=data)
        self.send_and_evaluate_read(self.filedport, target, size=datalen,
                expected_data=data)
        self.send_and_evaluate_delete(self.filedport, target, True)
        data = '\x00' * datalen
        self.send_and_evaluate_read(self.filedport, target, size=datalen, expected_data=data)

if __name__=='__main__':
    unittest.main()
