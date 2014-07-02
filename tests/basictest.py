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

from archipelago.common import loadrc, DEVICE_PREFIX, Error, construct_peers
import archipelago.vlmc as vlmc
import archipelago.archipelago as archipelago

import os, errno
import tempfile
from subprocess import check_call

def gettempname(prefix='myvolume-'):
    t = tempfile.mktemp(prefix=prefix)
    return os.path.basename(t)

def getrandomdata(size):
    return os.urandom(size)

def getrandomfile(size):
    randomfile = gettempname(prefix='random-') 
    randomdata = getrandomdata(size)
    return (randomfile, randomdata)

def is_mounted(device):
    lines = open("/proc/mounts").read().split("\n")
    mounts = [l.split(" ")[0] for l in lines]
    for m in mounts:
        if m == device:
            return True
    return False

def mount(device, directory):
    cmd = ['mount', device, directory]
    try:
        check_call(cmd, shell=False)
    except:
        raise Error("Cannot mount %s to %s" % (device, directory))

def umount(device):
    if not is_mounted(device):
        return
    cmd = ['umount', device]
    try:
        check_call(cmd, shell=False)
    except:
        raise Error("Cannot umount %s" % device)


def test_create(volume, volumesize=None, snap=None):
    vlmc.create(name=volume, size=volumesize, snap=snap)
    #should we catch Error here and do a vlmc.remove(name=volume)
#    d_id = vlmc.map_volume(name=volume)
#    device = DEVICE_PREFIX + str(d_id)
#    vlmc.unmap_volume(name=device)


def write(volume, volumesize):
    d_id=vlmc.map_volume(name=volume)
    device = DEVICE_PREFIX + str(d_id)
    try:
        fd = os.open(device, os.O_WRONLY)
        os.lseek(fd, (volumesize*1024*1024)+1, os.SEEK_SET)
        os.write(fd, "This should not succeed")
        print ("wtf")
    except OSError, (err, reason):
        if err != errno.EINVAL:
            raise Error("Cannot write to device %s : %s" % (device,reason))
    finally:
        if fd:
            os.close(fd)
        vlmc.unmap_volume(name=device)


def mkfs_and_mount(volume, mountdir):
    d_id=vlmc.map_volume(name=volume)
    device = DEVICE_PREFIX + str(d_id)

    cmd = ['mkfs.ext3', device]
    check_call(cmd, shell=False)
    try:
        mount(device, mountdir)
        umount(device)
    finally:
        vlmc.unmap_volume(name=device)


def write_data(volume, mountdir, randomfiles):
    d_id=vlmc.map_volume(name=volume)
    device = DEVICE_PREFIX + str(d_id)
    try:
        mount(device, mountdir)
        for rf in randomfiles:
            print "writing " + rf[0]
            f = open(os.path.join(mountdir, rf[0]), 'w')
            f.write(rf[1])
            f.close()
    finally:
        umount(device)
        vlmc.unmap_volume(name=device)

def read_data(volume, mountdir, randomfiles):
    d_id=vlmc.map_volume(name=volume)
    device = DEVICE_PREFIX + str(d_id)
    try:
        mount(device, mountdir)
        for rf in randomfiles:
            print "reading " + rf[0]
            f = open(os.path.join(mountdir, rf[0]), 'r')
            data = f.read()
            f.close()
            if data != rf[1]:
                raise Error("Data mismatch %s" % rf[0])
    finally:
        umount(device)
        vlmc.unmap_volume(name=device)

def snapshot(volume):
    vlmc.snapshot(name=volume)

if __name__ == '__main__':
    loadrc(None)
    peers = construct_peers()
    tmpvolume=gettempname()
    mntdir = '/mnt/mountpoint'
    RANDOMSIZE=20*1024*1024

    test_create(tmpvolume, volumesize=10240)
    try:
        write(tmpvolume, 10240)
        mkfs_and_mount(tmpvolume, mntdir)

        rf = [getrandomfile(RANDOMSIZE)]
        write_data(tmpvolume, mntdir, rf)
        archipelago.restart(user=True)
        read_data(tmpvolume, mntdir, rf)

        #snapshot
        snapname=gettempname(prefix="snapshot")
        print "Snapshot ", tmpvolume, "to", snapname
        snap = vlmc.snapshot(name=tmpvolume, snap_name=snapname)
        clonedvolume=gettempname()
        print "Cloning ", snapname, "to", clonedvolume
        test_create(clonedvolume, snap=snapname)
    except Exception as e:
        print e
        vlmc.remove(name=tmpvolume)
        raise e

    #create clone volume from snapshot
    try:
        rf1 = [getrandomfile(RANDOMSIZE)]
        #write new data to old volume
        write_data(tmpvolume, mntdir, rf1)
        #read new data from old volume
        read_data(tmpvolume, mntdir, rf1)
        #read old data from new volume
        read_data(clonedvolume, mntdir, rf)

        rf2 = [getrandomfile(RANDOMSIZE)]
        #write new data2 to snapshot
        write_data(clonedvolume, mntdir, rf2)
        #read new data2 from clonedvolume
        read_data(clonedvolume, mntdir, rf2)
        #read new data from old volume
        read_data(tmpvolume, mntdir, rf1)
    except Exception as e:
        print e
    finally:
        vlmc.remove(name=tmpvolume)
        vlmc.remove(name=clonedvolume)



