.PHONY: default clean install install-src

include $(XSEG_HOME)/base.mk

FILES="Makefile"
FILES+="xseg_devshell.sh"

EFILES="archipelago"
EFILES+="vlmc"
EFILES+="create_initializer"
EFILES+="xseg-domain-targets"

SUBDIR:=$(subst $(XSEG_HOME),,$(CURDIR))

default:

clean:

install:
	make -C ext_scripts install
	install -d $(DESTDIR)$(bindir)
	install -m 755 -t $(DESTDIR)$(bindir) archipelago
	install -m 755 -t $(DESTDIR)$(bindir) vlmc

install-src:
	make -C ext_scripts install-src
	install -d $(DESTDIR)$(srcdir)$(SUBDIR) ;
	@for f in $(FILES) ; do \
		install -m 644 -t $(DESTDIR)$(srcdir)$(SUBDIR) $$f ; \
	done
	@for f in $(EFILES) ; do \
		install -m 755 -t $(DESTDIR)$(srcdir)$(SUBDIR) $$f ; \
	done

