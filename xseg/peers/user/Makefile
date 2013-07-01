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
#PEERS := xseg archip-sosd archip-mapperd archip-vlmcd archip-pfiled archip-bench
PEERS := xseg archip-mapperd archip-vlmcd archip-pfiled archip-bench archip-dummy

FILES="Makefile"
FILES+=$(shell ls *.h)
FILES+=$(shell ls *.c)
FILES+=""

CPREQS=$(filter %.c,$^)

SUBDIR:=$(subst $(XSEG_HOME),,$(CURDIR))


default: $(PEERS)

#all: filed xseg sosd vlmcd mapperd
#all: filed xseg vlmcd mapperd
all: xseg archip-sosd archip-dummy archip-vlmcd mapperd archip-mapperd pfiled monitor vlmc-xseg archip-vlmcd archip-pfiled archip-bench


vlmcd: vlmcd.c common.c $(BASE)/xseg/xseg.h $(BASE)/xseg/protocol.h common.h
	$(CC) $(CFLAGS) -o $@ $< common.c $(INC) -L$(LIB) -lxseg

mapperd: mapperd.c common.c $(BASE)/xseg/xseg.h $(BASE)/xseg/protocol.h common.h
	$(CC) $(CFLAGS) -o $@ $< common.c $(INC) -L$(LIB) -lxseg

sosd: sosd.c $(BASE)/xseg/xseg.h $(BASE)/util_libs/user/sos/sos.h
	$(CC) $(CFLAGS) -o $@ $< $(INC) -L$(LIB) -lxseg -lsos

monitor: monitor.c peer.c peer.h
	$(CC) $(CFLAGS) -o $@ $< peer.c $(INC) -L$(LIB) -lxseg -lpthread -DMT

pfiled: pfiled.c common.c $(BASE)/xseg/xseg.h $(BASE)/xseg/protocol.h common.h
	$(CC) $(CFLAGS) -o $@ $< common.c  $(INC) -L$(LIB) -lxseg -lpthread

vlmc-xseg: vlmc-tool.c $(BASE)/xseg/xseg.h
	$(CC) $(CFLAGS) -o $@ $< $(INC) -L$(LIB) -lxseg

xseg: xseg-tool.c $(BASE)/xtypes/xheap.c $(BASE)/xseg/xseg.h
	$(CC) $(CFLAGS) -o $@ $< $(BASE)/xtypes/xheap.c $(INC) -L$(LIB) -lxseg

archip-sosd: mt-sosd.c peer.c peer.h
	$(CC) $(CFLAGS) -o $@ $< peer.c $(INC) -L$(LIB) -lxseg -lrados -lpthread \
							-lcrypto -DMT
archip-dummy: dummy.c peer.c peer.h
	$(CC) $(CFLAGS) -o $@ $< peer.c $(INC) -L$(LIB) -lxseg -lpthread -DMT

BENCH_PREQ=bench-xseg.c peer.c bench-lfsr.c bench-timer.c bench-utils.c \
	   bench-xseg.h peer.h bench-lfsr.h $(BASE)/xseg/protocol.h

archip-bench: $(BENCH_PREQ)
	$(CC) $(CFLAGS) -o $@ $(CPREQS) $(INC) -L$(LIB) -lxseg -lpthread -lm

archip-pfiled: filed.c peer.c peer.h hash.c hash.h $(BASE)/xseg/protocol.h
	$(CC) $(CFLAGS) -o $@ $(CPREQS) $(INC) -L$(LIB) -lxseg -lpthread -DMT \
							-lcrypto

archip-vlmcd: mt-vlmcd.c peer.c peer.h $(BASE)/xseg/protocol.h
	$(CC) $(CFLAGS) -o $@ $< peer.c $(INC) -L$(LIB) -lxseg

MAPPER_PREQ=mapper.c mapper.h peer.c peer.h hash.h hash.c mapper-handling.c \
	    mapper-versions.h mapper-versions.c mapper-version0.h mapper-version0.c \
	    mapper-version1.h mapper-version1.c mapper-version2.h mapper-version2.c \
	    $(BASE)/xseg/protocol.h

archip-mapperd: $(MAPPER_PREQ)
	$(CC) $(CFLAGS) -o $@ $(CPREQS) $(INC) -L$(LIB) -DST_THREADS \
							-lxseg -lst -lcrypto

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
	rm -f xseg sosd vlmcd mapperd archip-sosd monitor archip-mapperd \
		pfiled vlmc-xseg archip-vlmcd archip-pfiled archip-bench \
		archip-dummy
