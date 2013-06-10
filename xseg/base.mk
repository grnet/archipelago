# Copyright 2012 GRNET S.A. All rights reserved.
#
# Redistribution and use in source and binary forms, with or
# without modification, are permitted provided that the following
# conditions are met:
#
#   1. Redistributions of source code must retain the above
#      copyright notice, this list of conditions and the following
#      disclaimer.
#
#   2. Redistributions in binary form must reproduce the above
#      copyright notice, this list of conditions and the following
#      disclaimer in the documentation and/or other materials
#      provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY GRNET S.A. ``AS IS'' AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL GRNET S.A OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
# USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and
# documentation are those of the authors and should not be
# interpreted as representing official policies, either expressed
# or implied, of GRNET S.A.
#

# Setup for xseg Makefiles.

ifndef TARGET
TARGET:=$(shell basename $(shell pwd))
endif

export CC=gcc
ifndef MOPTS
export MOPTS=
endif
ifndef COPTS
export COPTS=-O2 -g -finline-functions $(MOPTS) $(DEBUG)
endif
ifndef CSTD
export CSTD=-std=gnu99 -pedantic
endif

export TOPDIR=$(shell dirname $(CURDIR))
ifeq (,$(VERSION))
export VERSION=$(shell cat $(TOPDIR)/version)
endif

ifeq (,$(DESTDIR))
export DESTDIR=/
endif

ifeq (,$(KVER))
export KVER=$(shell uname -r)
endif


bindir=/usr/bin/
libdir=/usr/lib/
pythondir=/usr/lib/python2.7/
moduledir=/lib/modules/$(KVER)/extra/
srcdir=/usr/src/archipelago-modules-dkms-$(VERSION)/xseg/
ganetidir=/usr/share/ganeti/extstorage/archipelago/

INC=-I$(BASE)
INC+=-I$(BASE)/peers/$(TARGET)
INC+=-I$(BASE)/sys/$(TARGET)
INC+=-I$(BASE)/drivers/$(TARGET)
export INC

export LIB=$(BASE)/lib/$(TARGET)
export CFLAGS=-Wall $(COPTS) $(CSTD)

#ifeq (,$(XSEG_HOME))
#export XSEG_HOME=$(shell ${XSEG_HOME})
#endif

ifeq (,$(XSEG_HOME))
export XSEG_HOME=$(CURDIR)
endif

CONFIG=./config.mk

#default:

#.PHONY: clean-config

#clean: clean-config

#clean-config:
#	rm -f $(CONFIG)

ifndef BASE
exists=$(shell [ -f "$(CONFIG)" ] && echo exists)
ifeq (exists,$(exists))
include $(CONFIG)
else
$(shell $(XSEG_HOME)/envsetup show | sed -e 's/"//g' > "$(CONFIG)")
include $(CONFIG)
endif

ifeq (,$(XSEG_DOMAIN_TARGETS))
export XSEG_DOMAIN_TARGETS=$(shell $(XSEG_HOME)/tools/xseg-domain-targets | sed -e 's/^[^=]*=//;s/"//g')
endif
export BASE=$(XSEG_HOME)
endif
