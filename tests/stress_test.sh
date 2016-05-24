#!/bin/bash

# Copyright (C) 2010-2014 GRNET S.A.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Do some basic stress-testing on xseg

source ../tools/helpers.sh

parse_config

[ -n "${1}" ] || usage "[nr_times]"

PORTS_AVAIL=$(($PORTS / 2 - 1))

# Needed by archipelago
umask 007

for i in `seq 1 $1`
do 
	# call some function to do work
done
