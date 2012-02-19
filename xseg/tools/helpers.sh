#!/bin/bash
#
# Helper functions for xseg testing and setup

function usage {
	echo "`basename $0` $1"
	exit 1
}

function pretty_print {
	echo "======================="
	echo "$1"
	echo "======================="
}

function parse_config {
	[ -e .xsegrc ] && source .xsegrc

	[ -n "${XSEG_HOME}" ] || XSEG_HOME="/root/archip/xseg/"
	[ -n "${MODULES_DIR}" ] || MODULES_DIR="${XSEG_HOME}/sys/"
	[ -n "${SPEC}" ] || SPEC="xsegdev:xsegbd:128:8192:64:1024:12"
	[ -n "${REQS}" ] || REQS=128
	[ -n "${PORTS}" ] || PORTS=128

	[ -n "${CHRDEV_NAME}" ] || CHRDEV_NAME="/dev/xsegdev"
	[ -n "${CHRDEV_MAJOR}" ] || CHRDEV_MAJOR=60
}

function unload_module {
	rmmod "$1"
}

function unload_all {
	unload_module "xsegbd"
	unload_module "xsegdev"
	rm "${CHARDEV_NAME}"
	unload_module "xseg"
}

function load_module {
	(lsmod | grep "$1" > /dev/null) || insmod "${MODULES_DIR}$1.ko" "$2" || exit 1
}

function mk_chardev {
	ls "${CHRDEV_NAME}" &> /dev/null || \
	mknod "${CHRDEV_NAME}" c "${CHRDEV_MAJOR}" 0 || exit 1
}

function load_all {
	load_module "xseg"
	load_module "xsegdev"
	mk_chardev
	load_module "xsegbd" "spec=$SPEC"
}

# spawn_blcokd - Spawn a block instance
#
# @param $1		target/volume name
# @param $2		xseg port
function spawn_blockd {
	"${XSEG_HOME}/peers/blockd" "$1" -p "$2" -g "$SPEC"
}

# map_volume - Map a volume to an xsegbd device
#
# @param $1		target/volume name
# @param $2		(blockd) xseg port
function map_volume {
	echo "$1 $(($2 + PORTS/2)):$2:${REQS}" > /sys/bus/xsegbd/add
}

# unmap_device - Unmap an xsegbd device/volume
#
# @param $1		xsegbd device id
function unmap_device {
	echo "$1" > /sys/bus/xsegbd/remove
}
