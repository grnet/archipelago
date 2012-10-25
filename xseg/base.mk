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

default:

.PHONY: clean-config

clean: clean-config

clean-config:
	rm -f $(CONFIG)

ifndef BASE
exists=$(shell [ -f "$(CONFIG)" ] && echo exists)
ifeq (exists,$(exists))
include $(CONFIG)
else
$(shell $(XSEG_HOME)/envsetup show | sed -e 's/"//g' > "$(CONFIG)")
include $(CONFIG)
endif

export XSEG_DOMAIN_TARGETS=$(shell $(XSEG_HOME)/tools/xseg-domain-targets | sed -e 's/^[^=]*=//;s/"//g')
export BASE=$(XSEG_HOME)
endif
