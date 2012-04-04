.PHONY: default all clean

include $(XSEG_HOME)/base.mk

default: all

all: blockd filed xseg sosd

filed: filed.c $(BASE)/xseg/xseg.h
	$(CC) $(CFLAGS) -o $@ $< $(INC) -L$(LIB) -lxseg -lpthread

vlmcd: vlmcd.c common.c $(BASE)/xseg/xseg.h common.h 
	$(CC) $(CFLAGS) -o $@ $< common.c $(INC) -L$(LIB) -lxseg

blockd: blockd.c $(BASE)/xseg/xseg.h
	$(CC) $(CFLAGS) -o $@ $< $(INC) -L$(LIB) -lxseg

sosd: sosd.c $(BASE)/xseg/xseg.h $(BASE)/util_libs/user/sos/sos.h
	$(CC) $(CFLAGS) -o $@ $< $(INC) -L$(LIB) -lxseg -lsos

xseg: xseg-tool.c $(BASE)/xseg/xseg.h
	$(CC) $(CFLAGS) -o $@ $< $(INC) -L$(LIB) -lxseg

clean:
	rm -f blockd filed xseg
