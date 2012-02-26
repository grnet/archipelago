.PHONY: all clean

BASE=..

include $(BASE)/config.mk
include $(BASE)/base.mk

all: blockd filed vlmcd xseg

# Please fix this ugly occurence of common.c
vlmcd: vlmcd.c common.c $(BASE)/xseg/xseg.h
	$(CC) $(CFLAGS) -o $@ $< common.c -I$(BASE) -L$(BASE)/lib -lxseg -lpthread

filed: filed.c $(BASE)/xseg/xseg.h
	$(CC) $(CFLAGS) -o $@ $< -I$(BASE) -L$(BASE)/lib -lxseg -lpthread

blockd: blockd.c $(BASE)/xseg/xseg.h
	$(CC) $(CFLAGS) -o $@ $< -I$(BASE) -L$(BASE)/lib -lxseg

xseg: xseg-tool.c $(BASE)/xseg/xseg.h
	$(CC) $(CFLAGS) -o $@ $< -L$(BASE)/lib -lxseg

clean:
	rm -f blockd filed vlmcd xseg
