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

.PHONY: default all clean xseg lib

include $(XSEG_HOME)/base.mk

FILES="Makefile"
#FILES+=$(shell ls *.h)
FILES+=$(shell ls *.c)

SUBDIR:=$(subst $(XSEG_HOME),,$(CURDIR))


DRIVERS=xseg_posix xseg_segdev xseg_pthread xseg_posixfd
DRVOBJS=$(DRIVERS:=.o)
DRVSOS=$(DRIVERS:=.so)

default: all

all: xseg $(DRIVERS:=.so) lib

$(BASE)/sys/user/xseg_user.o:
	make -C $(BASE)/sys/user xseg_user.o

xseg_posix.o: xseg_posix.c $(BASE)/xseg/xseg.h $(BASE)/drivers/xseg_posix.h
	$(CC) $(CFLAGS) $(INC) -fPIC -c -o $@ $<

xseg_posix.so: xseg_posix.o $(BASE)/sys/user/xseg_user.o
	$(CC) -shared -o $@ $< $(BASE)/sys/user/xseg_user.o 

xseg_segdev.o: xseg_segdev.c $(BASE)/xseg/xseg.h $(BASE)/drivers/xseg_segdev.h
	$(CC) $(CFLAGS) $(INC) -fPIC -c -o $@ $<

xseg_segdev.so: xseg_segdev.o $(BASE)/sys/user/xseg_user.o
	$(CC) -shared -o $@ $< $(BASE)/sys/user/xseg_user.o 

xseg_pthread.o: xseg_pthread.c $(BASE)/xseg/xseg.h $(BASE)/drivers/xseg_pthread.h
	$(CC) $(CFLAGS) $(INC) -fPIC -c -o $@ $<

xseg_pthread.so: xseg_pthread.o $(BASE)/sys/user/xseg_user.o
	$(CC) -shared -lpthread -o $@ $< $(BASE)/sys/user/xseg_user.o 

xseg_posixfd.o: xseg_posixfd.c $(BASE)/xseg/xseg.h $(BASE)/drivers/xseg_posixfd.h
	$(CC) $(CFLAGS) $(INC) -fPIC -c -o $@ $<

xseg_posixfd.so: xseg_posixfd.o $(BASE)/sys/user/xseg_user.o
	$(CC) -shared -o $@ $< $(BASE)/sys/user/xseg_user.o

.PHONY: lib
lib:
	cp -vaf $(DRVSOS) $(LIB)

.PHONY: install-src

install-src:
	install -d $(DESTDIR)$(srcdir)$(SUBDIR) ;
	@for f in $(FILES) ; do \
		install -o 0 -g 0 -m 644 -t $(DESTDIR)$(srcdir)$(SUBDIR) $$f ; \
	done

.PHONY: install
install:


clean:
	rm -f $(DRVOBJS) $(DRVSOS)
