.PHONY: all clean drivers

BASE=..

include $(BASE)/config.mk
include $(BASE)/base.mk

MAJOR=0
MINOR=0.1
AR=ar

SEGMENTS=xseg_posix
DRVDIR=$(BASE)/drivers
DRVOBJS=$(addsuffix .o, $(addprefix $(DRVDIR)/, $(SEGMENTS)))

all: libxseg.a libxseg.so


COMMA=,
_initialize.c: drivers
	echo "void __xseg_preinit(void) {" \
	     $(addprefix "void ",$(addsuffix _init"(void);",$(SEGMENTS))) \
	     $(addsuffix _init"(); ",$(SEGMENTS)) '}' > _initialize.c

xseg.o: xseg.c xseg.h $(BASE)/xq/xq.h
	$(CC) $(CFLAGS) -c -o $@ $<

xseg.pic.o: xseg.c xseg.h _initialize.c
	$(CC) $(CFLAGS) -fPIC -c -o $@ $<

libxseg.so: libxseg.so.$(MAJOR)
	ln -sf $< $@
	cp -vaf $@ ../lib

libxseg.so.$(MAJOR): libxseg.so.$(MAJOR).$(MINOR)
	ln -sf $< $@
	cp -vaf $@ ../lib

$(BASE)/sys/xseg_user.o:
	make -C $(BASE)/sys xseg_user.o

drivers:
	make -C $(DRVDIR) $(addsuffix .o, $(SEGMENTS))

$(BASE)/xq/xq.o:
	make -C $(BASE)/xq xq.o

$(BASE)/xq/xq.pic.o:
	make -C $(BASE)/xq xq.pic.o

$(BASE)/sys/libxseg.map:
	make -C $(BASE)/sys libxseg.map

libxseg.so.$(MAJOR).$(MINOR): xseg.pic.o $(BASE)/sys/xseg_user.o $(BASE)/sys/libxseg.map \
				 $(BASE)/xq/xq.pic.o $(DRVOBJS)
	$(CC) $(CFLAGS) -shared \
                        -Wl,-soname=libxseg.so.$(MAJOR) \
                        -o libxseg.so.$(MAJOR).$(MINOR) \
                        xseg.pic.o $(BASE)/sys/xseg_user.o $(BASE)/xq/xq.pic.o \
			 _initialize.o $(DRVOBJS) \
                        -Wl,--version-script=$(BASE)/sys/libxseg.map \
                        -ldl -lrt
	cp -vaf $@ ../lib

libxseg.a: xseg.o $(BASE)/xq/xq.o drivers _initialize.o
	$(AR) r libxseg.a xseg.o $(BASE)/xq/xq.o _initialize.o $(DRVOBJS)
	cp -vaf $@ ../lib

clean:
	make -C $(DRVDIR) clean
	rm -f _initialize.c _initialize.o
	rm -f xseg.o xseg.pic.o
	rm -f libxseg.a
	rm -f libxseg.so libxseg.so.$(MAJOR) libxseg.so.$(MAJOR).$(MINOR)

