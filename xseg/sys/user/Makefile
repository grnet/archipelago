# Copyright 2012 GRNET S.A. All rights reserved.
#
# Redistribution and use in source and binary forms, with or
# without modification, are permitted provided that the following
# conditions are met:
#
#   1. Redistributions of source code must retain the above
#      copyright notice, this list of conditions and the following
#      disclaimer.
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

DRIVERS=xseg_posix xseg_segdev xseg_pthread
DRVDIR=$(BASE)/drivers/user
DRVOBJS=$(addsuffix .o, $(addprefix $(DRVDIR)/, $(DRIVERS)))
SHELL=/bin/bash

default: all

all: libxseg.a libxseg.so
	make -C python all MAJOR=$(MAJOR) MINOR=$(MINOR)
	make -C xq all
	make -C xpool all
	make -C xhash all
	make -C xheap all
	make -C xobj all

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

xseg_user.o: xseg_user.c
	$(CC) $(CFLAGS) $(INC) -Wall -O2 -finline-functions -fPIC -c -o $@ $<

libxseg.map: $(BASE)/xtypes/xq_exports.h $(BASE)/xseg/xseg_exports.h \
		$(BASE)/xtypes/xpool_exports.h $(BASE)/xtypes/xhash_exports.h\
		$(BASE)/xtypes/xobj_exports.h
	cat $(BASE)/xtypes/xq_exports.h $(BASE)/xseg/xseg_exports.h \
		$(BASE)/xtypes/xpool_exports.h $(BASE)/xtypes/xhash_exports.h \
		$(BASE)/xtypes/xobj_exports.h | ./make_symbol_map.sh > $@

libxseg.so.$(MAJOR).$(MINOR): xseg.pic.o xseg_user.o libxseg.map \
				 xq/xq.pic.o xpool/xpool.pic.o xhash/xhash.pic.o \
				 xheap/xheap.pic.o xobj/xobj.pic.o $(DRVOBJS)
	$(CC) $(CFLAGS) -shared \
                        -Wl,-soname=libxseg.so.$(MAJOR) \
                        -o libxseg.so.$(MAJOR).$(MINOR) \
                        xseg.pic.o xseg_user.o xq/xq.pic.o \
			xpool/xpool.pic.o xhash/xhash.pic.o\
			xheap/xheap.pic.o xobj/xobj.pic.o \
			 _initialize.o $(DRVOBJS) \
                        -Wl,--version-script=libxseg.map \
                        -ldl -lrt -pthread
	cp -vaf $@ $(LIB)

libxseg.a: xseg.o xq/xq.o drivers _initialize.o
	$(AR) r libxseg.a xseg.o xq/xq.o _initialize.o $(DRVOBJS)
	cp -vaf $@ $(LIB)

install:
	make -C python install
	install -d $(DESTDIR)$(libdir)
	#install -t $(DESTDIR)$(libdir) libxseg.so
	#install -t $(DESTDIR)$(libdir) libxseg.so.$(MAJOR)
	install -o 0 -g 0 -m 644 -t $(DESTDIR)$(libdir) libxseg.so.$(MAJOR).$(MINOR)
	cp -vaf libxseg.so.$(MAJOR) $(DESTDIR)$(libdir)
	cp -vaf libxseg.so $(DESTDIR)$(libdir)

install-src:
	make -C xq install-src
	make -C xpool install-src
	make -C xhash install-src
	make -C xheap install-src
	make -C xobj install-src
	make -C python install-src
	install -d $(DESTDIR)$(srcdir)$(SUBDIR) ;
	@for f in $(FILES) ; do \
		install -o 0 -g 0 -m 644 -t $(DESTDIR)$(srcdir)$(SUBDIR) $$f ; \
	done
	@for f in $(EFILES) ; do \
		install -o 0 -g 0 -m 755 -t $(DESTDIR)$(srcdir)$(SUBDIR) $$f ; \
	done


clean:
	make -C xq clean
	make -C xpool clean
	make -C xhash clean
	make -C xheap clean
	make -C xobj clean
	make -C python clean
	rm -f _initialize.c _initialize.o
	rm -f xseg.o xseg.pic.o xseg_user.o
	rm -f libxseg.a libxseg.map
	rm -f libxseg.so libxseg.so.$(MAJOR) libxseg.so.$(MAJOR).$(MINOR)
