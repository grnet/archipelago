.PHONY: default clean install install-src

include $(XSEG_HOME)/base.mk

DEVFILES="Makefile"

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
	install -m 750 -d $(DESTDIR)/var/log/ganeti/extstorage/
	@for f in $(FILES) ; do \
		install -o 0 -g 0 -m 644 -t $(DESTDIR)$(ganetidir) $$f ; \
	done
	@for f in $(EFILES) ; do \
		install -o 0 -g 0 -m 755 -t $(DESTDIR)$(ganetidir) $$f ; \
	done

install-src:
	install -d $(DESTDIR)$(srcdir)$(SUBDIR) ;
	@for f in $(DEVFILES) ; do \
		install -o 0 -g 0 -m 644 -t $(DESTDIR)$(srcdir)$(SUBDIR) $$f ; \
	done
	@for f in $(FILES) ; do \
		install -o 0 -g 0 -m 644 -t $(DESTDIR)$(srcdir)$(SUBDIR) $$f ; \
	done
	@for f in $(EFILES) ; do \
		install -o 0 -g 0 -m 755 -t $(DESTDIR)$(srcdir)$(SUBDIR) $$f ; \
	done

