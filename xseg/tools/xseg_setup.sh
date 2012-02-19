#!/bin/bash
#
# Setup/clean all the components needed to test xseg
# (behaviour determined by script name)

source "`dirname $0`/helpers.sh"

[ -n "${1}" ] && usage

parse_config

if [ `basename "$0"` == "xseg_setup.sh" ]
then
	load_all
elif [ `basename "$0"` == "xseg_cleanup.sh" ]
then
	unload_all
fi

exit 0
