.PHONY: all clean

BASE=..

include $(BASE)/config.mk
include $(BASE)/base.mk

all: blockd xseg

blockd: blockd.c $(BASE)/xseg/xseg.h
	$(CC) $(CFLAGS) -o $@ $< -I$(BASE) -L$(BASE)/lib -lxseg

xseg: xseg-tool.c $(BASE)/xseg/xseg.h
	$(CC) $(CFLAGS) -o $@ $< -L$(BASE)/lib -lxseg

clean:
	rm -f blockd xseg
