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

.PHONY: default all clean install install-src

include $(XSEG_HOME)/base.mk

DEBUG=-g

FILES="Makefile"
#FILES+=$(shell ls *.h)
#FILES+=$(shell ls *.c)

SUBDIR:=$(subst $(XSEG_HOME),,$(CURDIR))

default: all

all: xobj.o xobj.pic.o xobj_test

$(BASE)/sys/user/xseg_user.o:
	make -C $(BASE)/sys/user xseg_user.o

xobj_test: $(BASE)/xtypes/xobj_test.c xobj.o $(BASE)/sys/user/xheap/xheap.o $(BASE)/sys/user/xseg_user.o
	$(CC) $(CFLAGS) $(INC) -L$(LIB) -o $@ $< xobj.o \
	$(BASE)/sys/user/xseg_user.o $(BASE)/sys/user/xhash/xhash.o \
	$(BASE)/sys/user/xheap/xheap.o -ldl -lpthread

xobj.o: $(BASE)/xtypes/xobj.c $(BASE)/xtypes/xobj.h $(BASE)/sys/user/xheap/xheap.o $(BASE)/xtypes/xlock.h
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

xobj.pic.o: $(BASE)/xtypes/xobj.c $(BASE)/xtypes/xobj.h $(BASE)/xtypes/xlock.h
	$(CC) $(CFLAGS) $(INC) -fPIC -c -o $@ $<

clean:
	rm -f xobj.o xobj.pic.o xobj_test

install:

install-src:
	install -d $(DESTDIR)$(srcdir)$(SUBDIR) ;
	@for f in $(FILES) ; do \
		install -o 0 -g 0 -m 644 -t $(DESTDIR)$(srcdir)$(SUBDIR) $$f ; \
	done
