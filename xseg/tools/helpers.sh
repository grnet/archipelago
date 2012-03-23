#!/bin/bash
#
# Helper functions for xseg testing and setup

function usage {
	echo Usage: "`basename $0` $1"
	exit 1
}

function pretty_print {
	echo "======================="
	echo "$1"
	echo "======================="
}

function fail {
	echo "${1}"
	exit 1
}

function parse_config {
	[ -e ~/.xsegrc ] && source ~/.xsegrc

	[ -n "${XSEG_HOME}" ] || XSEG_HOME="/root/archip/xseg/"
	[ -n "${MODULES_DIR}" ] || MODULES_DIR="${XSEG_HOME}/sys/"
	[ -n "${SPEC}" ] || SPEC="segdev:xsegbd:128:8192:64:1024:12"
	[ -n "${REQS}" ] || REQS=128
	[ -n "${PORTS}" ] || PORTS=128
	[ -n "${FILED_PORT}" ] || FILED_PORT=0
	[ -n "${IMAGES}" ] || IMAGES="/srv/archip/images/"
	[ -n "${BLOCKD_LOGS}" ] || BLOCKD_LOGS="/root/logs/"
	[ -n "${DEVICE_PREFIX}" ] || DEVICE_PREFIX="/dev/xsegbd"
	[ -n "${XSEGBD_SYSFS}" ] || XSEGBD_SYSFS="/sys/bus/xsegbd"
	[ -n "${CHRDEV_NAME}" ] || CHRDEV_NAME="/dev/segdev"
	[ -n "${CHRDEV_MAJOR}" ] || CHRDEV_MAJOR=60
	[ -n "${NR_OPS}" ] || NR_OPS=16
}

function unload_module {
	rmmod "$1"
}

function unload_all {
	unload_module "xsegbd"
	rm "${CHRDEV_NAME}"
	unload_module "xseg_segdev"
	unload_module "segdev"
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
	load_module "segdev"
	load_module "xseg_segdev"
	mk_chardev
	load_module "xsegbd" "spec=$SPEC"
}

# spawn_blcokd - Spawn a block instance
#
# @param $1		target/volume name
# @param $2		xseg port
function spawn_blockd {
	"${XSEG_HOME}peers/blockd" "$1" -p "$2" -g "$SPEC" -n ${NR_OPS} &> "${BLOCKD_LOGS}/$1" || fail "blockd"
}

function spawn_filed {
	"${XSEG_HOME}peers/filed" "$1" -p "$2" -g "${SPEC}" -n ${NR_OPS} &> "${BLOCKD_LOGS}/filed-${HOSTNAME}" &
}

# map_volume - Map a volume to an xsegbd device
#
# @param $1		target/volume name
# @param $2		src port
# @param $3		dst port
function map_volume {
	echo "$1 $2:$3:${REQS}" > "${XSEGBD_SYSFS}add" || exit 1
}

# unmap_device - Unmap an xsegbd device/volume
#
# @param $1		xsegbd device id
function unmap_device {
	echo "$1" > "${XSEGBD_SYSFS}remove" || exit 1
}
