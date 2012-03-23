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
		sleep 0.5
		pgrep filed &> /dev/null || fail "failed to spawn filed!"
		ln -sf "${XSEG_HOME}tools/vlmc-filed.py" "${XSEG_HOME}tools/vlmc"
	else
		ln -sf "${XSEG_HOME}tools/vlmc-blockd.py" "${XSEG_HOME}tools/vlmc"
	fi
elif [ `basename "$0"` == "xseg_cleanup.sh" ]
then
	if [ "${1}" == "filed" ]
	then
		pkill filed &> /dev/null
		sleep 0.5
	fi

	unload_all
	rm "${XSEG_HOME}tools/vlmc"
fi

exit 0
