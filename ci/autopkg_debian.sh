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

set -e

PACKAGES_DIR=$1

shift

TEMP_DIR=$(mktemp -d /tmp/devflow_autopkg_XXXXXXX)

# Create the packages
devflow-autopkg snapshot -b $TEMP_DIR $@

# MOVE the packages
mkdir -p $PACKAGES_DIR
mv -n $TEMP_DIR/* $PACKAGES_DIR

echo "Moved packages to: $(pwd)/$PACKAGES_DIR"

