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

default:
	if [ ! -e archipelago/version.py ] ; then \
		echo '__version__ = "'`devflow-version python`'"' > archipelago/version.py ; \
	fi
	python setup.py build

clean:
	rm -rf build/ archipelago.egg-info/ distribute_setup.pyc \
		archipelago/__init__.pyc archipelago/archipelago.pyc \
		archipelago/version.pyc

install:
	if [ ! -e archipelago/version.py ] ; then \
		echo '__version__ = "'`devflow-version python`'"' > archipelago/version.py ; \
	fi
	python setup.py install --install-layout=deb --root=$(DESTDIR)

install-src:
	install -d $(DESTDIR)$(srcdir)$(SUBDIR) ;
	@for f in $(FILES) ; do \
		install -o 0 -g 0 -m 644 -t $(DESTDIR)$(srcdir)$(SUBDIR) $$f ; \
	done
	install -d $(DESTDIR)$(srcdir)$(SUBDIR)/archipelago ;
	install -o 0 -g 0 -m 644 -t $(DESTDIR)$(srcdir)$(SUBDIR)/archipelago archipelago/__init__.py ; 
	install -o 0 -g 0 -m 644 -t $(DESTDIR)$(srcdir)$(SUBDIR)/archipelago archipelago/archipelago.py ; 
	install -o 0 -g 0 -m 644 -t $(DESTDIR)$(srcdir)$(SUBDIR)/archipelago archipelago/vlmc.py ; 
	install -o 0 -g 0 -m 644 -t $(DESTDIR)$(srcdir)$(SUBDIR)/archipelago archipelago/version.py ; 


