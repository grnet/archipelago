#!/bin/bash 


./make_install_file.sh > debian/archipelago-kernel-dkms.install 
git add debian/archipelago-kernel-dkms.install
export LD_LIBRARY_PATH=$PWD/xseg/lib:$LD_LIBRARY_PATH
git-buildpackage --git-upstream-branch=$1 \
		 --git-debian-branch=$2 \
		 --git-export=INDEX \
		 --git-ignore-new
