#!/bin/bash 


./make_install_file.sh > debian/archipelago-kernel-dkms.install 
git add debian/archipelago-kernel-dkms.install 
git-buildpackage --git-upstream-branch=$1 \
		 --git-debian-branch=$2 \
		 --git-export=INDEX \
		 --git-ignore-new
