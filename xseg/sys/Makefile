# Copyright 2013 GRNET S.A. All rights reserved.
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

.PHONY: install-src

include $(XSEG_HOME)/base.mk

XTYPES = xq
XTYPES += xpool
XTYPES += xhash
XTYPES += xheap
XTYPES += xworkq
XTYPES += xwaitq
XTYPES += xbinheap
XTYPES += xcache
XTYPES += xobj

export XTYPES

FILES="Makefile"
FILES+=$(shell ls *.h)

SUBDIR:=$(subst $(XSEG_HOME)/,,$(CURDIR))
XSEG_CLEAN_TARGETS=$(patsubst %,clean-%,$(XSEG_DOMAIN_TARGETS))
XSEG_INSTALL_TARGETS=$(patsubst %,install-%,$(XSEG_DOMAIN_TARGETS))
XSEG_INSTALLSRC_TARGETS=$(patsubst %,install-src-%,$(XSEG_DOMAIN_TARGETS))


default: $(XSEG_DOMAIN_TARGETS)

install: $(XSEG_INSTALL_TARGETS)

clean: $(XSEG_CLEAN_TARGETS)

.PHONY: $(XSEG_DOMAIN_TARGETS)
$(XSEG_DOMAIN_TARGETS):
	@echo " ";
	@echo "=== $@ in $(SUBDIR) ===";
	@echo " ";
	@make -C $@ TARGET=$@ default || exit 1;
	@echo " ";

.PHONY: $(XSEG_INSTALL_TARGETS)
$(XSEG_INSTALL_TARGETS):
	@echo " ";
	@echo "=== $@ in $(SUBDIR)===";
	@echo " ";
	@make -C $(@:install-%=%) TARGET=$@ install || true;
	@echo " ";


.PHONY: $(XSEG_INSTALLSRC_TARGETS)
$(XSEG_INSTALLSRC_TARGETS):
	@echo " ";
	@echo "=== $@ in $(SUBDIR)===";
	@echo " ";
	@make -C $(@:install-src-%=%) TARGET=$@ install-src || true;
	@echo " ";

.PHONY: $(XSEG_CLEAN_TARGETS)
$(XSEG_CLEAN_TARGETS):
	@echo " ";
	@echo "=== $@ in $(SUBDIR)===";
	@echo " ";
	@make -C $(@:clean-%=%) TARGET=$@ clean || true;
	@echo " ";



install-src: $(XSEG_INSTALLSRC_TARGETS)
	@install -d $(DESTDIR)$(srcdir)$(SUBDIR) ;
	@for f in $(FILES) ; do \
		install -o 0 -g 0 -m 644 -t $(DESTDIR)$(srcdir)$(SUBDIR) $$f ; \
	done

