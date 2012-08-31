.PHONY: clean

include $(XSEG_HOME)/base.mk

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
EXTRA_CFLAGS += -g -I$(BASE) -I$(BASE)/sys/kernel -DVAL_OVERLOAD
LIBDIR=$(BASE)/lib/kernel

xseg-objs := xsegmod.o xq.k.o xpool.k.o xhash.k.o xheap.k.o xobj.k.o xseg.k.o 
obj-m += xseg.o segdev.o

default: xq.k.c xpool.k.c xhash.k.c xheap.k.c xobj.k.c xseg.k.c
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) V=$(V) modules
	cp -vaf xseg.ko segdev.ko $(LIBDIR)

xq.k.c: $(BASE)/xtypes/xq.c $(BASE)/xtypes/xq.h
	ln -sf $< $@

xpool.k.c: $(BASE)/xtypes/xpool.c $(BASE)/xtypes/xpool.h
	ln -sf $< $@

xhash.k.c: $(BASE)/xtypes/xhash.c $(BASE)/xtypes/xhash.h
	ln -sf $< $@

xheap.k.c: $(BASE)/xtypes/xheap.c $(BASE)/xtypes/xheap.h
	ln -sf $< $@

xobj.k.c: $(BASE)/xtypes/xobj.c $(BASE)/xtypes/xobj.h
	ln -sf $< $@

xseg.k.c: $(BASE)/xseg/xseg.c $(BASE)/xseg/xseg.h
	ln -sf $< $@

clean:
	rm -f xq.k.c xpool.k.c xhash.k.c xheap.k.c xobj.k.c xseg.k.c
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) V=$(V) clean
