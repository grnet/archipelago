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

.PHONY: default clean target-list distclean

TARGET=default
include ./base.mk

FILES="base.mk"
FILES+="config.env"
FILES+="envsetup"
FILES+="Makefile"
FILES+="launch"


XSEG_BUILD_TARGETS=$(patsubst %,build-%,$(XSEG_DIRS))
XSEG_CLEAN_TARGETS=$(patsubst %,clean-%,$(XSEG_DIRS))
XSEG_INSTALL_TARGETS=$(patsubst %,install-%,$(XSEG_DIRS))
XSEG_INSTALLSRC_TARGETS=$(patsubst %,install-src-%,$(XSEG_DIRS))

default: targets

target-list:
	@echo $(XSEG_DOMAIN_TARGETS)

targets: $(XSEG_BUILD_TARGETS)

clean: $(XSEG_CLEAN_TARGETS)
	rm $(CONFIG)

install: $(XSEG_INSTALL_TARGETS)

install-src: $(XSEG_INSTALLSRC_TARGETS) $(XSEG_INSTALLSRC_DIRS)
	install -d $(DESTDIR)$(srcdir)/lib
	install -d $(DESTDIR)$(srcdir)/lib/user
	install -d $(DESTDIR)$(srcdir)/lib/kernel
	install -d $(DESTDIR)$(srcdir)/
	install -m 755 -t $(DESTDIR)$(srcdir) envsetup
	install -m 755 -t $(DESTDIR)$(srcdir) launch
	install -m 644 -t $(DESTDIR)$(srcdir) config.env
	install -m 644 -t $(DESTDIR)$(srcdir) Makefile
	install -m 644 -t $(DESTDIR)$(srcdir) base.mk

#	@for f in $(FILES); do \
#		install -m 644 -t $(DESTDIR)$(srcdir) $$f ; \
#	done


.PHONY: $(XSEG_BUILD_TARGETS)
$(XSEG_BUILD_TARGETS):
	@echo "" ;
	@echo "=== $@ ===";
	@make -C $(@:build-%=%) default || exit 1;
	@echo "" ;

.PHONY: $(XSEG_INSTALL_TARGETS)
$(XSEG_INSTALL_TARGETS):
	@echo "" ;
	@echo "=== $@ ===";
	@make -C $(@:install-%=%) install || true;
	@echo "" ;

.PHONY: $(XSEG_INSTALLSRC_TARGETS)
$(XSEG_INSTALLSRC_TARGETS):
	@echo "" ;
	@echo "=== $@ ===";
	@make -C $(@:install-src-%=%) install-src || true;
	@echo "" ;

.PHONY: $(XSEG_CLEAN_TARGETS)
$(XSEG_CLEAN_TARGETS):
	@echo "" ;
	@echo "=== $@ ===";
	@make -C $(@:clean-%=%) clean || true;
	@echo "" ;

distclean: $(XSEG_CLEAN_TARGETS)
	rm -f lib/user/*.so* lib/user/*.a
	rm -f lib/kernel/*.ko
	rm -f $(XSEG_HOME)/config.mk
