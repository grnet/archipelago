#!/bin/bash
#
# Do some basic stress-testing on xseg

source ../tools/helpers.sh

parse_config

[ -e $1 ] && usage "[nr_times]"

PORTS_AVAIL=$(($PORTS / 2 - 1))

for i in `seq 1 $1`
do 
	# call some function to do work
done
