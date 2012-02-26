.PHONY: default all clean

include $(XSEG_HOME)/base.mk

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
EXTRA_CFLAGS += -g -I$(BASE) -I$(BASE)/sys/kernel
LIBDIR=$(BASE)/lib/kernel

obj-m += xsegbd.o

default: all

$(BASE)/drivers/kernel/Module.symvers:
	$(MAKE) -C $(BASE)/drivers/kernel TARGET=kernel default

all: $(BASE)/drivers/kernel/Module.symvers
	cp -vaf $< .
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) V=$(V) modules
	cp -vaf xsegbd.ko $(LIBDIR)

clean:
	rm -f Module.symvers
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) V=$(V) clean
