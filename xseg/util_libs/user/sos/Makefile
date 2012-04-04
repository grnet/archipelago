.PHONY: default all clean

include $(XSEG_HOME)/base.mk

default: all
all: libsos.so

sos.o: sos.c sos.h
	$(CC) $(CFLAGS) -c -fPIC -o $@ $<

libsos.so: libsos.so.1
	ln -sf $< $@
	cp -vaf $@ $(LIB)

libsos.so.1: libsos.so.1.0
	ln -sf $< $@
	cp -vaf $@ $(LIB)

libsos.so.1.0: sos.o sos.h
	$(CC) -shared -Wl,-soname=libsos.so.1 -lrados -o $@ $<
	cp -vaf $@ $(LIB)

clean:
	rm -f sos.o
	rm -f libsos.so libsos.so.1 libsos.so.1.0
