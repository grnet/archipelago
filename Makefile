.PHONY: default xseg clean distclean build

default: xseg

build:
	make -C xseg XSEG_DOMAIN_TARGETS="user"
	rm xseg/config.mk

xseg:
	make -C xseg
	rm xseg/config.mk

clean:
	make -C xseg clean
	rm xseg/config.mk

install:
	make -C xseg install
	make -C xseg install-src
	rm xseg/config.mk

distclean:
	make -C xseg distclean
