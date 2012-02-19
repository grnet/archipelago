#!/bin/bash
#
# Setup a development environment for xseg.
# You need to *source* this.

# Get the directory containing the script
# into ${SCRIPTNAME}
pushd $(dirname -- "$0") >/dev/null
SCRIPTPATH=$(pwd)
popd >/dev/null

source "${SCRIPTPATH}"/helpers.sh

parse_config

# Setup a development environment
export LD_LIBRARY_PATH=${XSEG_HOME}/lib:${LD_LIBRARY_PATH}
export PATH=${XSEG_HOME}/tools:${XSEG_HOME}/peers:${PATH}
export XSEG_HOME

exec $SHELL
