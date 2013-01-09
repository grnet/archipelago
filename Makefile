.PHONY: default xseg clean distclean build

default: xseg

build: xseg

xseg:
	make -C xseg XSEG_DOMAIN_TARGETS="user kernel"

clean:
	make -C xseg clean
	rm ./config.mk

install:
	make -C xseg install

distclean:
	make -C xseg distclean
