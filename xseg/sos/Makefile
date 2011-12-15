.PHONY: all clean

BASE=..
DEBUG=-g

include $(BASE)/config.mk
include $(BASE)/base.mk

all: libsos.so 

sos.o: sos.c sos.h
	$(CC) $(CFLAGS) -c -fPIC -o $@ $<

libsos.so: libsos.so.1
	ln -sf $< $@
	cp -vaf $@ ../lib

libsos.so.1: libsos.so.1.0
	ln -sf $< $@
	cp -vaf $@ ../lib

libsos.so.1.0: sos.o sos.h
	$(CC) -shared -Wl,-soname=libsos.so.1 -lrados -o $@ $<
	cp -vaf libsos.so.1.0 ../lib

clean:
	rm -f sos.o
