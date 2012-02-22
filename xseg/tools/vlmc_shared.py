# shared funcs for both blockd and filed

import os, sys, shutil, glob, argparse

XSEG_HOME="/root/archip/xseg/"
IMAGES="/srv/pithos/archip-data/images/"
XSEGBD_SYSFS="/sys/bus/xsegbd/"
DEVICE_PREFIX="/dev/xsegbd"
BLOCKD_LOGS="/root/logs/"
FILED_PORT=0
NR_OPS=16

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
