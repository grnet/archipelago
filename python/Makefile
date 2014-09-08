# Copyright (C) 2010-2014 GRNET S.A.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
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


