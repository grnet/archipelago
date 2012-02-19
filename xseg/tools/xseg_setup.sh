#!/bin/bash
#
# Setup/clean all the components needed to test xseg
# (behaviour determined by script name)

source "`dirname $0`/helpers.sh"

[ -n "${1}" ] || usage "[blockd | filed]"

parse_config

if [ `basename "$0"` == "xseg_setup.sh" ]
then
	load_all

	if [ "${1}" == "filed" ]
	then
		spawn_filed ${IMAGES} ${FILED_PORT}
	fi
elif [ `basename "$0"` == "xseg_cleanup.sh" ]
then
	if [ "${1}" == "filed" ]
	then
		pkill filed
	fi

	unload_all
fi

exit 0
