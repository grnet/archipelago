.PHONY: default clean install install-src

include $(XSEG_HOME)/base.mk

FILES="Makefile"
FILES+="xseg_devshell.sh"

EFILES+="create_initializer"
EFILES+="xseg-domain-targets"

SUBDIR:=$(subst $(XSEG_HOME),,$(CURDIR))

default:

clean:
	make -C archipelago clean
	make -C ext_scripts clean

install:
	make -C archipelago install
	make -C ext_scripts install

install-src:
	make -C archipelago install-src
	make -C ext_scripts install-src
	install -d $(DESTDIR)$(srcdir)$(SUBDIR) ;
	@for f in $(FILES) ; do \
		install -o 0 -g 0 -m 644 -t $(DESTDIR)$(srcdir)$(SUBDIR) $$f ; \
	done
	@for f in $(EFILES) ; do \
		install -o 0 -g 0 -m 755 -t $(DESTDIR)$(srcdir)$(SUBDIR) $$f ; \
	done

