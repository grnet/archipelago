#!/usr/bin/env python2.7
#
# vlmc tool
# (blockd-only atm)

import os, sys, subprocess, shutil, re, argparse

#FIXME 
XSEG_HOME="/root/archip/xseg/"
IMAGES="/srv/pithos/archip-data/images/"
XSEGBD_SYSFS="/sys/bus/xsegbd/"
DEVICE_PREFIX="/dev/xsegbd"
BLOCKD_LOGS="/root/logs/"

def vlmc_list(args):
    print "name\t\t\t\tsize"
    try:
        for f in os.listdir(IMAGES):
            print "%s\t\t\t\t%dM" % (f, os.stat(IMAGES + f).st_size / 1024 / 1024)

        sys.exit(0)
    except Exception, reason:
        print >> sys.stderr, reason
        sys.exit(-1)
        
def vlmc_create(args):
    name = args.name[0]
    size = args.size
    snap = args.snap

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
        
        if snap:
            shutil.copyfile(snap, name)
        else:
            f = os.open(name, os.O_CREAT | os.O_WRONLY, 0755)
            size *= 1024*1024
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

def vlmc_map(args):
    name = args.name[0]
    try:
        try:
            r = subprocess.check_output(["ps", "-o", "command", "-C",
            "blockd"]).splitlines()[1:]
            result = [int(re.search('-p (\d+)', x).group(1)) for x in r]
            result.sort()

            prev = -1
            for i in result:
                if i - prev > 1:
                    port = prev + 1
                    break
                else:
                    prev = i

            port = prev + 1
        except:
            port = 0
            
        old_dir = os.getcwd()
        os.chdir(IMAGES)
        f = os.open(BLOCKD_LOGS +  name, os.O_CREAT | os.O_WRONLY)
        r = subprocess.Popen([XSEG_HOME + "peers/blockd", name, "-p", str(port),
        "-g", "segdev:xsegbd:128:4096:64:1024:12"], stdout=f, stderr=f)

        os.chdir(IMAGES)
        fd = os.open(XSEGBD_SYSFS + "add", os.O_WRONLY)
        os.write(fd, "%s %d:%d:%d" % (name, port + 64, port, REQS))
        os.close(fd)
    except Exception, reason:
        print >> sys.stderr, reason
        sys.exit(-1)

def vlmc_unmap(args):
    device = args.name[0]
    try:
        for f in os.listdir(XSEGBD_SYSFS + "devices/"):
            d_id = open(XSEGBD_SYSFS + "devices/" + f + "/id").read().strip()
            name = open(XSEGBD_SYSFS + "devices/"+ f + "/name").read().strip()
            if device == DEVICE_PREFIX + d_id:
                fd = os.open(XSEGBD_SYSFS + "remove", os.O_WRONLY)
                os.write(fd, d_id)
                os.close(fd)

                break
        
        subprocess.check_output(["pkill", "-f", "blockd " + name + " "])
    except Exception, reason:
        print >> sys.stderr, reason
        sys.exit(-1)

def vlmc_showmapped(args):
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
    group = create_parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-s', '--size', type=int, nargs='?', help='requested size in MB for create')
    group.add_argument('--snap', type=str, nargs='?', help='create from snapshot')
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

    #FIXME
    try:
        if args.config == None:
            execfile(os.path.expanduser("~/.xsegrc"))
        else:
            execfile(args.config)
    except:
        pass

    args.func(args)
