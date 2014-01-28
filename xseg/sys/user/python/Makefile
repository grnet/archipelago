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

FILES="Makefile"
FILES+=$(shell ls *.py)

SUBDIR:=$(subst $(XSEG_HOME),,$(CURDIR))


H2XML = h2xml
XML2PY = xml2py

default: all

all: xseg/xseg_api.py xseg/xprotocol.py
	if [ ! -e xseg/version.py ] ; then \
		echo '__version__ = "'`devflow-version python`'"' > xseg/version.py ; \
	fi
	python setup.py build

$(BASE)/sys/user/libxseg.so:
	make -C $(BASE)/sys/user libxseg.so

xseg.xml: $(BASE)/xseg/xseg.h $(BASE)/xtypes/xq.h $(BASE)/xtypes/xlock.h \
	$(BASE)/xtypes/xpool.h $(BASE)/xtypes/xhash.h \
	$(BASE)/xtypes/xheap.h $(BASE)/xtypes/xobj.h \
	$(BASE)/sys/domain.h $(BASE)/sys/util.h $(BASE)/sys/user/_sysutil.h $(BASE)/xseg/protocol.h
	$(H2XML) -c $(INC) -o $@ $(BASE)/xseg/xseg.h

xprotocol.xml: 
	$(H2XML) -c $(INC) -o $@ $(BASE)/xseg/protocol.h

xseg/xseg_api.py: xseg.xml
	$(XML2PY) -d -k defst -l $(BASE)/lib/user/libxseg.so.$(MAJOR) -c $< -o $@
	sed -i -e 's/xseg_get_data_nonstatic.restype = STRING/xseg_get_data_nonstatic.restype = POINTER(c_char)/g' xseg/xseg_api.py
	sed -i -e 's/xseg_get_target_nonstatic.restype = STRING/xseg_get_target_nonstatic.restype = POINTER(c_char)/g' xseg/xseg_api.py
	sed -i -e 's/xseg_get_signal_desc_nonstatic.restype = STRING/xseg_get_signal_desc_nonstatic.restype = POINTER(c_char)/g' xseg/xseg_api.py
	sed -i -e 's/STRING = 1//g' xseg/xseg_api.py
	sed -i -e 's,$(BASE)/lib/user/libxseg.so.$(MAJOR),libxseg.so.$(MAJOR),g' xseg/xseg_api.py


xseg/xprotocol.py: xprotocol.xml
	$(XML2PY) -d -k defst -c $< -o $@
	sed -i -e 's/xseg_reply_map_scatterlist \* 0/POINTER(xseg_reply_map_scatterlist)/g' xseg/xprotocol.py


install:
	if [ ! -e xseg/version.py ] ; then \
		echo '__version__ = "'`devflow-version python`'"' > xseg/version.py ; \
	fi
	python setup.py install --install-layout=deb --root=$(DESTDIR)

install-src:
	install -d $(DESTDIR)$(srcdir)$(SUBDIR) ;
	@for f in $(FILES) ; do \
		install -o 0 -g 0 -m 644 -t $(DESTDIR)$(srcdir)$(SUBDIR) $$f ; \
	done
	install -d $(DESTDIR)$(srcdir)$(SUBDIR)/xseg ;
	install -o 0 -g 0 -m 644 -t $(DESTDIR)$(srcdir)$(SUBDIR)/xseg xseg/__init__.py ; \



clean:
	rm -rf build/ xseg.egg-info/ xseg.xml xprotocol.xml xseg/xseg_api.py \
		xseg/xseg_api.pyc xseg/xprotocol.py xseg/xprotocol.pyc \
		xseg/__init__.pyc
