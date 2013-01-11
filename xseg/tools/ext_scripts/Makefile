.PHONY: default clean install install-src

include $(XSEG_HOME)/base.mk

FILES="Makefile"
FILES+="parameters.list"

EFILES="vlmc_wrapper.py"
EFILES+="attach"
EFILES+="detach"
EFILES+="create"
EFILES+="grow"
EFILES+="remove"
EFILES+="verify"

SUBDIR:=$(subst $(XSEG_HOME),,$(CURDIR))

default:

clean:

install:
	install -d $(DESTDIR)$(ganetidir)
	@for f in $(EFILES) ; do \
		install -m 755 -t $(DESTDIR)$(ganetidir) $$f ; \
	done

install-src:
	install -d $(DESTDIR)$(srcdir)$(SUBDIR) ;
	@for f in $(FILES) ; do \
		install -m 644 -t $(DESTDIR)$(srcdir)$(SUBDIR) $$f ; \
	done
	@for f in $(EFILES) ; do \
		install -m 755 -t $(DESTDIR)$(srcdir)$(SUBDIR) $$f ; \
	done

