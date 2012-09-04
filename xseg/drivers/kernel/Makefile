.PHONY: default all clean

include $(XSEG_HOME)/base.mk

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
EXTRA_CFLAGS += -g -I$(BASE) -I$(BASE)/sys/kernel
LIBDIR=$(BASE)/lib/kernel

obj-m += xseg_segdev.o
obj-m += xseg_posix.o
obj-m += xseg_pthread.o

default: all

$(BASE)/sys/kernel/Module.symvers:
	$(MAKE) -C $(BASE)/sys/kernel TARGET=kernel default

all: $(BASE)/sys/kernel/Module.symvers
	cp -vaf $< .
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) V=$(V) modules
	cp -vaf xseg_pthread.ko xseg_segdev.ko xseg_posix.ko $(LIBDIR)

clean:
	rm -f Module.symvers
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) V=$(V) clean
