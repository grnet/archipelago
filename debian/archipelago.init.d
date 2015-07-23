#!/bin/sh
### BEGIN INIT INFO
# Provides:          archipelago
# Required-Start:    $network $local_fs $remote_fs $all
# Required-Stop:     $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: <Enter a short description of the sortware>
# Description:       <Enter a long description of the software>
#                    <...>
#                    <...>
### END INIT INFO

# Author: philipgian<philipgian@grnet.gr>

# PATH should only include /usr/* if it runs after the mountnfs.sh script */
PATH=/sbin:/usr/sbin:/bin:/usr/bin
DESC=archipelago            # Introduce a short description here
NAME=archipelago            # Introduce the short server's name here
DAEMON=/usr/bin/archipelago # Introduce the server's location here
DAEMON_ARGS=""              # Arguments to run the daemon with
#PIDFILE=/var/run/$NAME.pid
SCRIPTNAME=/etc/init.d/$NAME
STOP_ARGS=""

# Exit if the package is not installed
[ -x $DAEMON ] || exit 0

# Read configuration variable file if it is present
[ -r /etc/default/$NAME ] && . /etc/default/$NAME

# Load the VERBOSE setting and other rcS variables
. /lib/init/vars.sh

# Define LSB log_* functions.
# Depend on lsb-base (>= 3.0-6) to ensure that this file is present.
. /lib/lsb/init-functions

#
# Function that starts the daemon/service
#
do_start()
{
	$DAEMON start > /dev/null && return 0
    return 2
}

#
# Function that stops the daemon/service
#
do_stop()
{
	$DAEMON stop $STOP_ARGS > /dev/null && return 0
    return 2
}

#
# Function that restarts the daemon/service
#
do_restart()
{
	$DAEMON restart > /dev/null && return 0
    return 2
}



case "$1" in
  start)
	log_daemon_msg "Starting $DESC " "$NAME"
	do_start
	case "$?" in
		0|1) log_end_msg 0 ;;
		2) log_end_msg 1 ;;
	esac
	;;
  stop)
	log_daemon_msg "Stopping $DESC" "$NAME"
	do_stop
	case "$?" in
		0|1) log_end_msg 0 ;;
		2) log_end_msg 1 ;;
	esac
	;;
  status)
       $DAEMON status
       ;;
  restart|force-reload)
	#
	# If the "reload" option is implemented then remove the
	# 'force-reload' alias
	#
	log_daemon_msg "Restarting $DESC" "$NAME"
	do_restart
	case "$?" in
		0|1) log_end_msg 0 ;;
		2) log_end_msg 1 ;;
	esac
    ;;
  *)
	echo "Usage: $SCRIPTNAME {start|stop|status|restart|force-reload}" >&2
	exit 3
	;;
esac

