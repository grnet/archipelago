#!/usr/bin/env python2.7
#
# vlmc tool
# (blockd-only atm)

import os, sys, subprocess, shutil, re, argparse

#FIXME 
xseg_home="/root/archip/xseg/"
images="/srv/pithos/archip-data/images/"
xsegbd_sysfs="/sys/bus/xsegbd/"
device_prefix="/dev/xsegbd"
blockd_logs="/srv/pithos/archip-data/logs/"

def vlmc_list(args):
	print "name\t\t\t\tsize"
	try:
		for f in os.listdir(images):
			print "%s\t\t\t\t%dK" % (f, os.stat(images + f).st_size / 1024)

		sys.exit(0)
	except Exception, reason:
		print >> sys.stderr, reason
		sys.exit(-1)
		
def vlmc_create(args):
	name = args.name[0]
	if args.size == None and args.snap == None:
		print >> sys.stderr, "Specify at least one of the two"
		sys.exit(-1)

	size = args.size
	snap = args.snap

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

def vlmc_remove(args):
	name = args.name[0]

	try:
		old_dir = os.getcwd()
		os.chdir(images)

		try:
			os.stat(name)
		except:
			print "file doesn't exist"
			os.chdir(old_dir)
			sys.exit(-1)
		
		os.unlink(images + '/' + name)

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
		os.chdir(images)
		f = os.open(blockd_logs +  name, os.O_CREAT | os.O_WRONLY)
		r = subprocess.Popen([xseg_home + "peers/blockd", name, "-p", str(port),
		"-g", "xsegdev:xsegbd:128:4096:64:1024:12"], stdout=f, stderr=f)

		os.chdir(images)
		fd = os.open(xsegbd_sysfs + "add", os.O_WRONLY)
		os.write(fd, "%s %d:%d:128" % (name, port + 64, port))
		os.close(fd)
	except Exception, reason:
		print >> sys.stderr, reason
		sys.exit(-1)

def vlmc_unmap(args):
	device = args.name[0]
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

def vlmc_showmapped(args):
	print "id\tpool\timage\tsnap\tdevice"
	try:
		for f in os.listdir(xsegbd_sysfs + "devices/"):
			d_id = open(xsegbd_sysfs + "devices/" + f + "/id").read().strip()
			name = open(xsegbd_sysfs + "devices/"+ f + "/name").read().strip()

			print "%s\t%s\t%s\t%s\t%s" % (d_id, '-', name, '-', device_prefix +
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
	parser = argparse.ArgumentParser(description='vlmc tool')
	subparsers = parser.add_subparsers()

	create_parser = subparsers.add_parser('create', help='Create volume')
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
	showmapped_parser.set_defaults(func=vlmc_showmapped)
	showmapped_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')

	list_parser = subparsers.add_parser('list', help='List volumes')
	list_parser.set_defaults(func=vlmc_list)
	list_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')

	ls_parser = subparsers.add_parser('ls', help='List volumes')
	ls_parser.set_defaults(func=vlmc_list)
	ls_parser.add_argument('-p', '--pool', type=str, nargs='?', help='for backwards compatiblity with rbd')

	args = parser.parse_args()	
	args.func(args)
