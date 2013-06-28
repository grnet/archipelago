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

.PHONY: clean default install install-src

include $(XSEG_HOME)/base.mk

ifeq (,$(KVER))
KVER := $(shell uname -r)
endif

FILES="Makefile"
FILES+=$(shell ls *.h)
FILES+=$(shell ls *.c)

SUBDIR:=$(subst $(XSEG_HOME),,$(CURDIR))

KDIR := /lib/modules/$(KVER)/build
PWD := $(shell pwd)
EXTRA_CFLAGS += -g -I$(BASE) -I$(BASE)/sys/kernel -DVAL_OVERLOAD
LIBDIR=$(BASE)/lib/kernel

xseg-objs := xsegmod.o
xseg-objs += $(addsuffix .k.o, $(XTYPES))
xseg-objs += xseg.k.o
obj-m += xseg.o segdev.o

DEPENDENCIES = $(addsuffix .k.c, $(XTYPES))
DEPENDENCIES += xseg.k.c

default: $(DEPENDENCIES)
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) V=$(V) modules
	cp -vaf xseg.ko segdev.ko $(LIBDIR)

xq.k.c: $(BASE)/xtypes/xq.c $(BASE)/xtypes/xq.h
	ln -sf $< $@

xpool.k.c: $(BASE)/xtypes/xpool.c $(BASE)/xtypes/xpool.h
	ln -sf $< $@

xhash.k.c: $(BASE)/xtypes/xhash.c $(BASE)/xtypes/xhash.h
	ln -sf $< $@

xheap.k.c: $(BASE)/xtypes/xheap.c $(BASE)/xtypes/xheap.h
	ln -sf $< $@

xobj.k.c: $(BASE)/xtypes/xobj.c $(BASE)/xtypes/xobj.h
	ln -sf $< $@

xworkq.k.c: $(BASE)/xtypes/xworkq.c $(BASE)/xtypes/xworkq.h
	ln -sf $< $@

xwaitq.k.c: $(BASE)/xtypes/xwaitq.c $(BASE)/xtypes/xwaitq.h
	ln -sf $< $@

xseg.k.c: $(BASE)/xseg/xseg.c $(BASE)/xseg/xseg.h
	ln -sf $< $@

install:
	install -d $(DESTDIR)$(moduledir)
	install -o 0 -g 0 -m 644 -t $(DESTDIR)$(moduledir) xseg.ko
	install -o 0 -g 0 -m 644 -t $(DESTDIR)$(moduledir) segdev.ko

install-src:
	install -d $(DESTDIR)$(srcdir)$(SUBDIR)
	@for f in $(FILES); do \
		install -o 0 -g 0 -m 644 -t $(DESTDIR)$(srcdir)$(SUBDIR) $$f ; \
	done

clean:
	rm -f $(DEPENDENCIES)
	make -C /lib/modules/$(KVER)/build M=$(PWD) V=$(V) clean
