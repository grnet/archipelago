.PHONY: default xseg clean distclean build

default: xseg

build: xseg

xseg:
	make -C xseg

clean:
	make -C xseg clean
	rm ./config.mk

install:
	make -C xseg install

distclean:
	make -C xseg distclean
