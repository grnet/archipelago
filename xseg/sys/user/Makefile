.PHONY: default all clean drivers

include $(XSEG_HOME)/base.mk

MAJOR=0
MINOR=0.1
AR=ar

DRIVERS=xseg_posix xseg_segdev
DRVDIR=$(BASE)/drivers/user
DRVOBJS=$(addsuffix .o, $(addprefix $(DRVDIR)/, $(DRIVERS)))
SHELL=/bin/bash

default: all

all: libxseg.a libxseg.so
	make -C xq all

COMMA=,
_initialize.c: drivers
	$(BASE)/tools/create_initializer $(DRIVERS) > _initialize.c

xseg.o: $(BASE)/xseg/xseg.c $(BASE)/xseg/xseg.h $(BASE)/xq/xq.h
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

xseg.pic.o: $(BASE)/xseg/xseg.c $(BASE)/xseg/xseg.h _initialize.c
	$(CC) $(CFLAGS) $(INC) -fPIC -c -o $@ $<

libxseg.so: libxseg.so.$(MAJOR)
	ln -sf $< $@
	cp -vaf $@ $(LIB)

libxseg.so.$(MAJOR): libxseg.so.$(MAJOR).$(MINOR)
	ln -sf $< $@
	cp -vaf $@ $(LIB)

drivers:
	make -C $(DRVDIR) $(addsuffix .o, $(DRIVERS))

xq/xq.o:
	make -C xq xq.o

xq/xq.pic.o:
	make -C xq xq.pic.o

xseg_user.o: xseg_user.c
	$(CC) $(CFLAGS) $(INC) -Wall -O2 -finline-functions -fPIC -c -o $@ $<

libxseg.map: $(BASE)/xq/xq_exports.h $(BASE)/xseg/xseg_exports.h
	cat $(BASE)/xq/xq_exports.h $(BASE)/xseg/xseg_exports.h | ./make_symbol_map.sh > $@

libxseg.so.$(MAJOR).$(MINOR): xseg.pic.o xseg_user.o libxseg.map \
				 xq/xq.pic.o $(DRVOBJS)
	$(CC) $(CFLAGS) -shared \
                        -Wl,-soname=libxseg.so.$(MAJOR) \
                        -o libxseg.so.$(MAJOR).$(MINOR) \
                        xseg.pic.o xseg_user.o xq/xq.pic.o \
			 _initialize.o $(DRVOBJS) \
                        -Wl,--version-script=libxseg.map \
                        -ldl -lrt
	cp -vaf $@ $(LIB)

libxseg.a: xseg.o xq/xq.o drivers _initialize.o
	$(AR) r libxseg.a xseg.o xq/xq.o _initialize.o $(DRVOBJS)
	cp -vaf $@ $(LIB)

clean:
	make -C xq clean
	rm -f _initialize.c _initialize.o
	rm -f xseg.o xseg.pic.o xseg_user.o
	rm -f libxseg.a libxseg.map
	rm -f libxseg.so libxseg.so.$(MAJOR) libxseg.so.$(MAJOR).$(MINOR)
