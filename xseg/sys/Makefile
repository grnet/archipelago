.PHONY: install-src

include $(XSEG_HOME)/base.mk

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
		install -m 644 -t $(DESTDIR)$(srcdir)$(SUBDIR) $$f ; \
	done

