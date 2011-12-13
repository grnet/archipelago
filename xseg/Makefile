.PHONY: clean

XSEG_HOME=$(shell pwd)
export XSEG_HOME

include config.mk
include base.mk

default:
	for f in $(MAKEDIRS); do \
		make -C $$f || break; \
		echo "-------------------------------------------------------------------"; \
		echo " "; \
	done

clean:
	for f in $(MAKEDIRS); do \
		make -C $$f clean || break; \
		echo " "; \
	done

