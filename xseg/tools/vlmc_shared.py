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

# shared funcs for both blockd and filed

import os, sys, shutil, glob, argparse

XSEG_HOME="/root/archip/xseg/"
IMAGES="/srv/archip/"
XSEGBD_SYSFS="/sys/bus/xsegbd/"
DEVICE_PREFIX="/dev/xsegbd"
BLOCKD_LOGS="/root/archip_logs/"
FILED_PORT=0
NR_OPS=16
REQS=512

def vlmc_list(args):
    print "name\t\t\t\tsize"
    try:
        for f in glob.glob(IMAGES + '*'):
            print "%s\t\t\t\t%dM" % (os.path.basename(f), os.stat(f).st_size / 1024 / 1024)

        sys.exit(0)
    except Exception, reason:
        print >> sys.stderr, reason
        sys.exit(-1)

def vlmc_create(args):
    name = args.name[0]
    size = args.size
    snap = args.snap

    if size == None and snap == None:
        print >> sys.stderr, "At least one of the size/snap args must be provided"
        sys.exit(-1)

    try:
        old_dir = os.getcwd()
        os.chdir(IMAGES)

        try:
            os.stat(name)
            print "file exists"
            os.chdir(old_dir)
            sys.exit(-1)
        except:
            pass

        if size != None:
            size *= 1024*1024

            if snap != None and size < os.stat(snap).st_size:
                print >> sys.stderr, "Given size smaller than snapshot volume size"
                sys.exit(-1)

        if snap != None:
            shutil.copy(snap, name)
            if size != None:
                f = os.open(name, os.O_WRONLY)
        else:
            f = os.open(name, os.O_CREAT | os.O_WRONLY, 0755)

        if size != None:
            os.lseek(f, size - 1, os.SEEK_SET)
            os.write(f, "1")
            os.close(f)

        os.chdir(old_dir)
        sys.exit(0)
    except Exception, reason:
        print >> sys.stderr, reason
        sys.exit(-1)

def vlmc_remove(args):
    name = args.name[0]

    try:
        old_dir = os.getcwd()
        os.chdir(IMAGES)

        try:
            os.stat(name)
        except:
            print "file doesn't exist"
            os.chdir(old_dir)
            sys.exit(-1)

        os.unlink(IMAGES + '/' + name)

        os.chdir(old_dir)
        sys.exit(0)
    except Exception, reason:
        print >> sys.stderr, reason
        sys.exit(-1)

def xsegbd_loaded():
    try:
        os.stat("/sys/bus/xsegbd")
    except Exception, reason:
        print >> sys.stderr, reason
        sys.exit(-1)

def vlmc_resize(args):
    name = args.name[0]
    size = args.size[0]

    try:
        old_dir = os.getcwd()
        os.chdir(IMAGES)

        size *= 1024*1024

        f = os.open(name, os.O_WRONLY, 0755)
        if size >= os.stat(name).st_size:
            os.lseek(f, size - 1, os.SEEK_SET)
            os.write(f, "1")
        else:
            os.ftruncate(f, size)

        os.close(f)
        os.chdir(old_dir)

        for f in os.listdir(XSEGBD_SYSFS + "devices/"):
            d_id = open(XSEGBD_SYSFS + "devices/" + f + "/id").read().strip()
            d_name = open(XSEGBD_SYSFS + "devices/"+ f + "/name").read().strip()
            if name == d_name:
                fd = os.open(XSEGBD_SYSFS + "devices/" +  d_id +"/refresh", os.O_WRONLY)
                os.write(fd, "1")
                os.close(fd)

        sys.exit(0)
    except Exception, reason:
        print >> sys.stderr, reason
        sys.exit(-1)

def loadrc(rc):
    #FIXME
    try:
        if rc == None:
            execfile(os.path.expanduser("~/.xsegrc"), globals())
        else:
            execfile(rc, globals())
    except:
        pass
