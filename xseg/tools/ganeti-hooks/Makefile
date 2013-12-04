.PHONY: default clean install install-src

include $(XSEG_HOME)/base.mk

DEVFILES="Makefile"

HOOKS="instance-migrate-pre.d"

SUBDIR:=$(subst $(XSEG_HOME),,$(CURDIR))

default:

clean:

install:
	install -d $(DESTDIR)$(ganetihooksdir)
	@for f in $(HOOKS) ; do \
		make -C $$f install ; \
	done

install-src:
	install -d $(DESTDIR)$(srcdir)$(SUBDIR) ;
	@for f in $(DEVFILES) ; do \
		install -o 0 -g 0 -m 644 -t $(DESTDIR)$(srcdir)$(SUBDIR) $$f ; \
	done
	@for f in $(HOOKS) ; do \
		make -C $$f install-src ; \
	done

