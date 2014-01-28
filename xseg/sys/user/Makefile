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

.PHONY: default all clean drivers install install-src

include $(XSEG_HOME)/base.mk

FILES="Makefile"
FILES+=$(shell ls *.h)
FILES+=$(shell ls *.c)

EFILES+="make_symbol_map.sh"

SUBDIR:=$(subst $(XSEG_HOME),,$(CURDIR))

MAJOR=0
MINOR=2
AR=ar

DRIVERS=xseg_posix xseg_segdev xseg_pthread xseg_posixfd
DRVDIR=$(BASE)/drivers/user
DRVOBJS=$(addsuffix .o, $(addprefix $(DRVDIR)/, $(DRIVERS)))
SHELL=/bin/bash

XTYPE_OBJS = $(addsuffix .o, $(XTYPES))
XTYPES_PICS = $(addsuffix .pic.o, $(XTYPES))
XTYPES_EXPORTS = $(addsuffix _exports.h, $(XTYPES))

EXPORT_DEPENDENCIES = $(addprefix $(BASE)/xtypes/, $(XTYPES_EXPORTS))
EXPORT_DEPENDENCIES += $(BASE)/xseg/xseg_exports.h

PIC_DEPENDENCIES = $(foreach xt, $(XTYPES), $(xt)/$(xt).pic.o)
PIC_DEPENDENCIES += xseg.pic.o

OBJ_DEPENDENCIES = $(foreach xt, $(XTYPES), $(xt)/$(xt).o)
OBJ_DEPENDENCIES += xseg.o _initialize.o

default: all

all: libxseg.a libxseg.so
	make -C python all MAJOR=$(MAJOR) MINOR=$(MINOR)
	@for xt in $(XTYPES) ; do \
		make -C $$xt all ; \
	done

COMMA=,
_initialize.c: drivers
	$(BASE)/tools/create_initializer $(DRIVERS) > _initialize.c

xseg.o: $(BASE)/xseg/xseg.c $(BASE)/xseg/xseg.h $(BASE)/xtypes/xq.h
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

xseg.pic.o: $(BASE)/xseg/xseg.c $(BASE)/xseg/xseg.h _initialize.c
	$(CC) $(CFLAGS) $(INC) -fPIC -c -o $@ $<

libxseg.so: libxseg.so.$(MAJOR)
	ln -sf $< $@
	cp -vaf $@ $(LIB)

libxseg.so.$(MAJOR): libxseg.so.$(MAJOR).$(MINOR)
	ln -sf $< $@
	cp -vaf $@ $(LIB)

drivers:
	make -C $(DRVDIR) $(addsuffix .o, $(DRIVERS))

xq/xq.o:
	make -C xq xq.o

xq/xq.pic.o:
	make -C xq xq.pic.o

xpool/xpool.o:
	make -C xpool xpool.o

xpool/xpool.pic.o:
	make -C xpool xpool.pic.o

xhash/xhash.o:
	make -C xhash xhash.o

xhash/xhash.pic.o:
	make -C xhash xhash.pic.o

xheap/xheap.o:
	make -C xheap xheap.o

xheap/xheap.pic.o:
	make -C xheap xheap.pic.o

xobj/xobj.o:
	make -C xobj xobj.o

xobj/xobj.pic.o:
	make -C xobj xobj.pic.o

xworkq/xworkq.o:
	make -C xworkq xworkq.o

xworkq/xworkq.pic.o:
	make -C xworkq xworkq.pic.o

xwaitq/xwaitq.o:
	make -C xwaitq xwaitq.o

xwaitq/xwaitq.pic.o:
	make -C xwaitq xwaitq.pic.o

xbinheap/xbinheap.o:
	make -C xbinheap xbinheap.o

xbinheap/xbinheap.pic.o:
	make -C xbinheap xbinheap.pic.o

xcache/xcache.o:
	make -C xcache xcache.o

xcache/xcache.pic.o:
	make -C xcache xcache.pic.o

xseg_user.o: xseg_user.c
	$(CC) $(CFLAGS) $(INC) -Wall -O2 -finline-functions -fPIC -c -o $@ $<

libxseg.map: $(EXPORT_DEPENDENCIES)
	cat $(EXPORT_DEPENDENCIES) | ./make_symbol_map.sh > $@

libxseg.so.$(MAJOR).$(MINOR): xseg_user.o libxseg.map \
				$(PIC_DEPENDENCIES) $(DRVOBJS)
	$(CC) $(CFLAGS) -shared \
                        -Wl,-soname=libxseg.so.$(MAJOR) \
                        -o libxseg.so.$(MAJOR).$(MINOR) \
                        xseg_user.o \
			$(PIC_DEPENDENCIES) $(DRVOBJS) \
			 _initialize.o \
                        -Wl,--version-script=libxseg.map \
                        -ldl -lrt -pthread
	cp -vaf $@ $(LIB)

libxseg.a: $(OBJ_DEPENDENCIES) drivers
	$(AR) r libxseg.a $(OBJ_DEPENDENCIES) $(DRVOBJS)
	cp -vaf $@ $(LIB)

install:
	make -C python install
	install -d $(DESTDIR)$(libdir)
	install -o 0 -g 0 -m 644 -t $(DESTDIR)$(libdir) libxseg.so.$(MAJOR).$(MINOR)
	cp -vaf libxseg.so.$(MAJOR) $(DESTDIR)$(libdir)
	cp -vaf libxseg.so $(DESTDIR)$(libdir)

install-src:
	@for xt in $(XTYPES) ; do \
		make -C $$xt install-src ; \
	done
	make -C python install-src
	install -d $(DESTDIR)$(srcdir)$(SUBDIR) ;
	@for f in $(FILES) ; do \
		install -o 0 -g 0 -m 644 -t $(DESTDIR)$(srcdir)$(SUBDIR) $$f ; \
	done
	@for f in $(EFILES) ; do \
		install -o 0 -g 0 -m 755 -t $(DESTDIR)$(srcdir)$(SUBDIR) $$f ; \
	done


clean:
	@for xt in $(XTYPES) ; do \
		make -C $$xt clean ; \
	done
	make -C python clean
	rm -f _initialize.c _initialize.o
	rm -f xseg.o xseg.pic.o xseg_user.o
	rm -f libxseg.a libxseg.map
	rm -f libxseg.so libxseg.so.$(MAJOR) libxseg.so.$(MAJOR).$(MINOR)
