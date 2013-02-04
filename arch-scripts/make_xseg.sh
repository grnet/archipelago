#! /bin/bash

###################
# Initializations #
###################

set -e  #exit on error

# Find script location
ARCH_SCRIPTS=$(dirname "$(readlink /proc/$$/fd/255)")

#Include basic functions
source $ARCH_SCRIPTS/init.sh

PIPE="1>/dev/null"
if [[ ! "$(logname)" = "root" ]]; then $SUDO=sudo; fi

#############
# Arguments #
#############

while [[ -n $1 ]]; do
	if [[ $1 = '-c' ]]; then CLEAN=0	#Will initially call `make clean`
	elif [[ $1 = '-d' ]]; then PIPE=""	#Will not pipe any output to /dev/null
	else red_echo "${1}: Unknown command."
	fi
	shift
done

#############
# Make XSEG #
#############

cd $XSEG

if [[ $CLEAN ]]; then
	eval make clean $PIPE
fi
eval make $PIPE
eval $SUDO make install $PIPE
