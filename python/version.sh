#!/bin/sh 
CUR_SOURCE_DIR=$1
CUR_BINARY_DIR=$2

cd $CUR_SOURCE_DIR
mkdir -p $CUR_BINARY_DIR/archipelago
if [ -f archipelago/version.py ] ; then
	cp archipelago/version.py $CUR_BINARY_DIR/archipelago/version.py ;
else
	echo '__version__ = "'`devflow-version python`'"' > $CUR_BINARY_DIR/archipelago/version.py ;
fi
cd $CUR_BINARY_DIR
