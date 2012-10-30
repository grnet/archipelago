.PHONY: default xseg clean distclean build

default: xseg

build: xseg

xseg:
	make -C xseg XSEG_DOMAIN_TARGETS="user"

clean:
	make -C xseg clean
	rm ./config.mk

distclean:
	make -C xseg distclean
