.PHONY: clean

ifndef XSEG_HOME
$(error The XSEG_HOME variable must be set)
else
BASE=$(XSEG_HOME)
endif

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
EXTRA_CFLAGS += -I$(BASE)

xseg-objs := xsegmod.o xq.k.o xseg.k.o 
obj-m += xsegbd.o xsegdev.o xseg.o

default: xq.k.c xseg.k.c
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

xq.k.c: $(BASE)/xq/xq.c $(BASE)/xq/xq.h
	ln -sf $< $@

xseg.k.c: $(BASE)/xseg/xseg.c $(BASE)/xseg/xseg.h
	ln -sf $< $@

xseg_user.o: xseg_user.c
	$(CC) -I$(BASE) -Wall -O2 -finline-functions -fPIC -c -o $@ $<

libxseg.map: $(BASE)/xq/xq_exports.h $(BASE)/xseg/xseg_exports.h
	cat $(BASE)/xq/xq_exports.h $(BASE)/xseg/xseg_exports.h | ./make_symbol_map.sh > $@

clean:
	rm -f xseg_user.o libxseg.map xq.k.c xseg.k.c
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

