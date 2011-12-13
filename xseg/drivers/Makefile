.PHONY: all clean xseg lib

BASE=..

include $(BASE)/config.mk
include $(BASE)/base.mk

DRIVERS=xseg_posix xseg_xsegdev
DRVOBJS=$(DRIVERS:=.o)
DRVSOS=$(DRIVERS:=.so)

all: xseg $(DRIVERS:=.so) lib

$(BASE)/sys/xseg_user.o:
	make -C $(BASE)/sys xseg_user.o

xseg_posix.o: xseg_posix.c $(BASE)/xseg/xseg.h
	$(CC) $(CFLAGS) -fPIC -c -o $@ $<

xseg_posix.so: xseg_posix.o $(BASE)/sys/xseg_user.o
	$(CC) -shared -o $@ $< $(BASE)/sys/xseg_user.o 

xseg_xsegdev.o: xseg_xsegdev.c $(BASE)/xseg/xseg.h
	$(CC) $(CFLAGS) -I$(BASE)/sys -fPIC -c -o $@ $<

xseg_xsegdev.so: xseg_xsegdev.o $(BASE)/sys/xseg_user.o
	$(CC) -shared -o $@ $< $(BASE)/sys/xseg_user.o 

lib:
	cp -vaf $(DRVSOS) ../lib
clean:
	rm -f $(DRVOBJS) $(DRVSOS)
