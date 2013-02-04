#! /bin/bash

###################
# Initializations #
###################

set -e	#exit on error

# Find script location
ARCH_SCRIPTS=$(dirname "$(readlink /proc/$$/fd/255)")

#Include basic functions
source $ARCH_SCRIPTS/init.sh

SED_XSEG=$(echo "${XSEG}/" | sed 's/\//\\\//g')
INCLUDE="--include=*.c --include=*.h"

#############
# Arguments #
#############

if [[ -z $1 ]]; then
	red_echo "No parameters given."
	exit 1
elif [[ $1 = "-m" ]]; then
	INCLUDE="--include=Makefile --include=*.mk --include=envsetup"
	shift
fi

#############
# Grep XSEG #
#############

grep -RIni --color=always ${INCLUDE} \
	--exclude-dir=python \
	-e $1 ${XSEG} | \
	sed 's/'$SED_XSEG'//'

