#!/bin/bash

VERSION=$(head -n 1 debian/changelog | sed -r 's/.*([0-9]+\.[0-9]+\.[0-9]+).*/\1/g')
INSTALL_PATH="usr/src/archipelagos-kernel-dkms-$VERSION"

echo "debian/archipelagos-kernel-dkms-files/Makefile $INSTALL_PATH"
git ls-files --directory xseg | sed 's/.*git.*//' | sed 's,\(.*\)\/\(.*\),\1\/\2 '"$INSTALL_PATH"'\/\1,'
#find xseg -path "*git*" -prune -o -type f -a -print | sed 's,\(.*\)\/\(.*\),\1\/\2 '"$INSTALL_PATH"'\/\1,'

