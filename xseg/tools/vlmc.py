#!/usr/bin/env python
#
# vlmc tool
# (blockd-only atm)

import os, sys, subprocess, shutil, re, argparse

#FIXME 
xseg_home = "/root/archip/xseg/"
images = "/root/images/"
xsegbd_sysfs = "/sys/bus/xsegbd/"
device_prefix = "/dev/xsegbd"
blockd_logs = "/root/logs/"


def vlmc_list():
    print "name\t\t\t\tsize"
    try:
        for f in os.listdir(images):
            print "%s\t\t\t\t%dK" % (f, os.stat(images + f).st_size / 1024)

        sys.exit(0)
    except Exception, reason:
        print >> sys.stderr, reason
        sys.exit(-1)


def vlmc_create(name, size, snap=""):
    try:
        size *= 1024*1024
        
        old_dir = os.getcwd()
        os.chdir(images)

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
            os.lseek(f, size - 1, os.SEEK_SET)
            os.write(f, "1")
            os.close(f)

        os.chdir(old_dir)
        sys.exit(0)
    except Exception, reason:
        print >> sys.stderr, reason
        sys.exit(-1)


def vlmc_remove(name):
    try:
        old_dir = os.getcwd()
        os.chdir(images) 

        try:
            os.stat(name)
        except:
            print >> sys.stderr, "file does not exist"
            os.chdir(old_dir)
            sys.exit(-1)
        
        os.unlink(images + "/" + name)

        os.chdir(old_dir)
        sys.exit(0)
    except Exception, reason:
        print >> sys.stderr, reason
        sys.exit(-1)


def vlmc_map(name):
    try:
        try:
            r = subprocess.check_output(["ps", "-o", "command", "-C",
            "blockd"]).splitlines()[1:]
            result = [int(re.search("-p (\d+)", x).group(1)) for x in r]
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
        os.chdir(images)
        f = open(blockd_logs + "/"  + name)
        r = subprocess.Popen([xseg_home + "peers/blockd", name, "-p", str(port),
        "-g", "xsegdev:xsegbd:128:4096:64:1024:12"], stdout=f, stderr=f)

        os.chdir(images)
        fd = os.open(xsegbd_sysfs + "add", os.O_WRONLY)
        os.write(fd, "%s %d:%d:128" % (name, port + 64, port))
        os.close(fd)
    except Exception, reason:
        print >> sys.stderr, reason
        sys.exit(-1)


def vlmc_unmap(device):
    try:
        for f in os.listdir(xsegbd_sysfs + "devices/"):
            d_id = open(xsegbd_sysfs + "devices/" + f + "/id").read().strip()
            name = open(xsegbd_sysfs + "devices/"+ f + "/name").read().strip()
            if device == device_prefix + d_id:
                fd = os.open(xsegbd_sysfs + "remove", os.O_WRONLY) 
                os.write(fd, d_id)
                os.close(fd)

                break
        
        subprocess.check_output(["pkill", "-f", "blockd " + name + " "])
    except Exception, reason:
        print >> sys.stderr, reason
        sys.exit(-1)


def vlmc_showmapped():
    print "id\tpool\timage\tsnap\tdevice"
    try:
        for f in os.listdir(xsegbd_sysfs + "devices/"):
            d_id = open(xsegbd_sysfs + "devices/" + f + "/id").read().strip()
            name = open(xsegbd_sysfs + "devices/"+ f + "/name").read().strip()

            print "%s\t%s\t%s\t%s\t%s" % (d_id, "-", name, "-", device_prefix +
            d_id)
    except Exception, reason:
        print >> sys.stderr, reason
        sys.exit(-1)

    sys.exit(0)


def check_no_opts(args, parser):
    if args.name == None or args.size != None or args.snap != None:
        parser.print_usage(file=sys.stderr)
        sys.exit(-1)


if __name__ == "__main__":
    # parse arguments and discpatch to the correct func
    parser = argparse.ArgumentParser(description="vlmc tool")
    parser.add_argument("op", type=str, nargs="?",
		        help=("operation requested (create, remove, map,"
		              " unmap, showmapped)"))
    parser.add_argument("name", type=str, nargs="?",
                        help="volume/device name")
    parser.add_argument("-s", "--size", type=int, nargs="?",
                        help="requested size in MB for create")
    parser.add_argument("--snap", type=str, help="create from snapshot")
    parser.add_argument("-p", "--pool", type=str,
                        help="for backwards compatiblity with rbd")
    args = parser.parse_args()    

    if args.op == "create":
        if args.name == None or (args.snap == None and (args.size == None or args.size <= 0)) or (args.snap != None and args.size != None):
            parser.print_usage(file=sys.stderr)
            sys.exit(-1)
        vlmc_create(args.name, args.size, args.snap)
    elif args.op == "remove":
        check_no_opts(args, parser)
        vlmc_remove(args.name)
    elif args.op == "map":
        check_no_opts(args, parser)
        vlmc_map(args.name)
    elif args.op == "unmap":
        check_no_opts(args, parser)
        vlmc_unmap(args.name)
    elif args.op == "showmapped":
        if args.name != None or args.size != None or args.snap != None:
            parser.print_usage(file=sys.stderr)
            sys.exit(-1)
        vlmc_showmapped()
    elif args.op == "list" or args.op == "ls":
        if args.name != None or args.size != None or args.snap != None:
            parser.print_usage(file=sys.stderr)
            sys.exit(-1)
        vlmc_list()
    else:
        parser.print_usage(file=sys.stderr)
        sys.exit(-1)
