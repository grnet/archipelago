.PHONY: default all clean

include $(XSEG_HOME)/base.mk

default: all

all: blockd filed xseg

filed: filed.c $(BASE)/xseg/xseg.h
	$(CC) $(CFLAGS) -o $@ $< $(INC) -L$(LIB) -lxseg -lpthread

blockd: blockd.c $(BASE)/xseg/xseg.h
	$(CC) $(CFLAGS) -o $@ $< $(INC) -L$(LIB) -lxseg

xseg: xseg-tool.c $(BASE)/xseg/xseg.h
	$(CC) $(CFLAGS) -o $@ $< $(INC) -L$(LIB) -lxseg

clean:
	rm -f blockd filed xseg
