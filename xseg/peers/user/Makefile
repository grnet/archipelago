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

.PHONY: default all clean install install-src

include $(XSEG_HOME)/base.mk
PEERS := xseg mt-sosd dummy mt-mapperd pfiled vlmc-xseg st-vlmcd mt-pfiled

FILES="Makefile"
FILES+=$(shell ls *.h)
FILES+=$(shell ls *.c)
FILES+=""

SUBDIR:=$(subst $(XSEG_HOME),,$(CURDIR))


default: $(PEERS)

#all: filed xseg sosd vlmcd mapperd
#all: filed xseg vlmcd mapperd
all: filed xseg mt-sosd dummy mt-vlmcd mapperd mt-mapperd pfiled monitor vlmc-xseg st-vlmcd mt-pfiled


filed: filed.c $(BASE)/xseg/xseg.h
	$(CC) $(CFLAGS) -o $@ $< $(INC) -L$(LIB) -lxseg -lpthread

vlmcd: vlmcd.c common.c $(BASE)/xseg/xseg.h $(BASE)/xseg/protocol.h common.h
	$(CC) $(CFLAGS) -o $@ $< common.c $(INC) -L$(LIB) -lxseg

mapperd: mapperd.c common.c $(BASE)/xseg/xseg.h $(BASE)/xseg/protocol.h common.h
	$(CC) $(CFLAGS) -o $@ $< common.c $(INC) -L$(LIB) -lxseg

sosd: sosd.c $(BASE)/xseg/xseg.h $(BASE)/util_libs/user/sos/sos.h
	$(CC) $(CFLAGS) -o $@ $< $(INC) -L$(LIB) -lxseg -lsos

xseg: xseg-tool.c $(BASE)/xseg/xseg.h
	$(CC) $(CFLAGS) -o $@ $< $(BASE)/xtypes/xheap.c $(INC) -L$(LIB) -lxseg

mt-sosd: mt-sosd.c peer.c peer.h
	$(CC) $(CFLAGS) -o $@ $< peer.c $(INC) -L$(LIB) -lxseg -lrados -lpthread -DMT

dummy: dummy.c peer.c peer.h
	$(CC) $(CFLAGS) -o $@ $< peer.c $(INC) -L$(LIB) -lxseg -lpthread -DMT

monitor: monitor.c peer.c peer.h
	$(CC) $(CFLAGS) -o $@ $< peer.c $(INC) -L$(LIB) -lxseg -lpthread -DMT

mt-vlmcd: mt-vlmcd.c peer.c peer.h $(BASE)/xseg/protocol.h 
	$(CC) $(CFLAGS) -o $@ $< peer.c $(INC) -L$(LIB) -lxseg -lpthread -DMT

mt-pfiled: mt-pfiled.c peer.c peer.h $(BASE)/xseg/protocol.h 
	$(CC) $(CFLAGS) -o $@ $< peer.c $(INC) -L$(LIB) -lxseg -lpthread -DMT

st-vlmcd: mt-vlmcd.c peer.c peer.h $(BASE)/xseg/protocol.h 
	$(CC) $(CFLAGS) -o $@ $< peer.c $(INC) -L$(LIB) -lxseg 

mt-mapperd: mt-mapperd.c peer.c peer.h $(BASE)/xseg/protocol.h 
	$(CC) $(CFLAGS) -o $@ $< peer.c $(INC) -L$(LIB) -DST_THREADS -lxseg -lst -lcrypto

pfiled: pfiled.c common.c $(BASE)/xseg/xseg.h $(BASE)/xseg/protocol.h common.h
	$(CC) $(CFLAGS) -o $@ $< common.c  $(INC) -L$(LIB) -lxseg -lpthread

vlmc-xseg: vlmc-tool.c $(BASE)/xseg/xseg.h
	$(CC) $(CFLAGS) -o $@ $< $(INC) -L$(LIB) -lxseg

install:
	install -d $(DESTDIR)$(bindir)
	@for p in $(PEERS); do\
		install -o 0 -g 0 -m 755 -t $(DESTDIR)$(bindir) $$p ; \
	done

install-src:
	install -d $(DESTDIR)$(srcdir)$(SUBDIR) 
	@for f in $(FILES) ; do \
		install -o 0 -g 0 -m 644 -t $(DESTDIR)$(srcdir)$(SUBDIR) $$f ; \
	done

clean:
	rm -f filed xseg sosd vlmcd mapperd mt-sosd dummy monitor mt-mapperd \
		pfiled vlmc-xseg st-vlmcd mt-vlmcd mt-pfiled
