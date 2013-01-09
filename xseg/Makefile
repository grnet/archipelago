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

XSEG_CLEAN_TARGETS=$(patsubst %,clean-%,$(XSEG_DOMAIN_TARGETS))
XSEG_INSTALL_TARGETS=$(patsubst %,install-%,$(XSEG_DOMAIN_TARGETS))

default: targets

target-list:
	@echo $(XSEG_DOMAIN_TARGETS)

targets: $(XSEG_DOMAIN_TARGETS)

clean: $(XSEG_CLEAN_TARGETS)

install: install-src $(XSEG_INSTALL_TARGETS)

install-src:
	mkdir -p $(DESTDIR)$(srcdir)
	cp -r * $(DESTDIR)$(srcdir)

.PHONY: $(XSEG_DOMAIN_TARGETS)
$(XSEG_DOMAIN_TARGETS):
	@for f in $(XSEG_DOMAIN_DIRS); do \
		echo " "; \
		echo "=== $@ in $$f ==="; \
		echo " "; \
		make -C $$f/$@ TARGET=$@ default || exit 1; \
		echo " "; \
	done
	@echo " "

.PHONY: $(XSEG_INSTALL_TARGETS)
$(XSEG_INSTALL_TARGETS):
	@for f in $(XSEG_DOMAIN_DIRS); do \
		echo " "; \
		echo "=== $@ in $$f ==="; \
		echo " "; \
		make -C $$f/$(@:install-%=%) TARGET=$@ install || true; \
		echo " "; \
	done
	@echo " "

.PHONY: $(XSEG_CLEAN_TARGETS)
$(XSEG_CLEAN_TARGETS):
	@for f in $(XSEG_DOMAIN_DIRS); do \
		echo " "; \
		echo "=== $@ in $$f ==="; \
		echo " "; \
		make -C $$f/$(@:clean-%=%) TARGET=$@ clean || true; \
		echo " "; \
	done
	@echo " "

distclean: $(XSEG_CLEAN_TARGETS)
	rm -f lib/user/*.so* lib/user/*.a
	rm -f lib/kernel/*.ko
	rm -f $(XSEG_HOME)/config.mk
