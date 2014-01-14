.PHONY: default clean install install-src

include $(XSEG_HOME)/base.mk

DEVFILES="Makefile"

EFILES="archip-openvolumes"

SUBDIR:=$(subst $(XSEG_HOME),,$(CURDIR))

default:

clean:

install:
	install -d $(DESTDIR)$(ganetihooksdir)/instance-migrate-pre.d/
	@for f in $(EFILES) ; do \
		install -o 0 -g 0 -m 755 -t $(DESTDIR)$(ganetihooksdir)/instance-migrate-pre.d/ $$f ; \
	done

install-src:
	install -d $(DESTDIR)$(srcdir)$(SUBDIR) ;
	@for f in $(DEVFILES) ; do \
		install -o 0 -g 0 -m 644 -t $(DESTDIR)$(srcdir)$(SUBDIR) $$f ; \
	done
	@for f in $(EFILES) ; do \
		install -o 0 -g 0 -m 755 -t $(DESTDIR)$(srcdir)$(SUBDIR) $$f ; \
	done

