.PHONY: default clean install install-src

include $(XSEG_HOME)/base.mk

FILES="Makefile"
FILES+=$(shell ls *.h)
FILES+=$(shell ls *.c)
#FILES+="xseg.h"
#FILES+="xseg.c"
#FILES+="xseg_exports.h"
#FILES+="domain.h"
#FILES+="protocol.h"

SUBDIR:=$(subst $(XSEG_HOME),,$(CURDIR))

default:

clean:

install:

install-src:
	install -d $(DESTDIR)$(srcdir)$(SUBDIR) ;
	@for f in $(FILES) ; do \
		install -o 0 -g 0 -m 644 -t $(DESTDIR)$(srcdir)$(SUBDIR) $$f ; \
	done

