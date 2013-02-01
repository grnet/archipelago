#! /bin/bash

###################
# Initializations #
###################

#Include basic functions
source init.sh

set -e	#exit on error

XSEG=/home/$(logname)/archipelago/xseg
SED_XSEG=$(echo "${XSEG}/" | sed 's/\//\\\//g')

INCLUDE="--include=*.c --include=*.h"

#############
# Arguments #
#############

if [[ -z $1 ]]; then
	red_echo "No parameters given."
	exit 1
elif [[ $1 = "-m" ]]; then
	INCLUDE="--include=Makefile --include=*.mk"
	shift
fi

#############
# Grep XSEG #
#############

grep -RIni --exclude-dir=${XSEG}/sys/user/python --exclude=test.c \
	${INCLUDE} --color=always -e $1 ${XSEG} | \
	sed 's/'$SED_XSEG'//'
