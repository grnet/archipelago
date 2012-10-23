.PHONY: default all clean

include $(XSEG_HOME)/base.mk

default: all

#all: filed xseg sosd vlmcd mapperd
#all: filed xseg vlmcd mapperd
all: filed xseg mt-sosd dummy mt-vlmcd mapperd mt-mapperd pfiled monitor vlmc-xseg st-vlmcd


filed: filed.c $(BASE)/xseg/xseg.h
	$(CC) $(CFLAGS) -o $@ $< $(INC) -L$(LIB) -lxseg -lpthread

vlmcd: vlmcd.c common.c $(BASE)/xseg/xseg.h $(BASE)/xseg/protocol.h common.h 
	$(CC) $(CFLAGS) -o $@ $< common.c $(INC) -L$(LIB) -lxseg

mapperd: mapperd.c common.c $(BASE)/xseg/xseg.h $(BASE)/xseg/protocol.h common.h 
	$(CC) $(CFLAGS) -o $@ $< common.c $(INC) -L$(LIB) -lxseg

sosd: sosd.c $(BASE)/xseg/xseg.h $(BASE)/util_libs/user/sos/sos.h
	$(CC) $(CFLAGS) -o $@ $< $(INC) -L$(LIB) -lxseg -lsos

xseg: xseg-tool.c $(BASE)/xseg/xseg.h
	$(CC) $(CFLAGS) -o $@ $< $(INC) -L$(LIB) -lxseg

mt-sosd: mt-sosd.c mpeer.c mpeer.h
	$(CC) $(CFLAGS) -o $@ $< mpeer.c $(INC) -L$(LIB) -lxseg -lrados -lpthread

dummy: dummy.c mpeer.c mpeer.h
	$(CC) $(CFLAGS) -o $@ $< mpeer.c $(INC) -L$(LIB) -lxseg -lpthread

monitor: monitor.c mpeer.c mpeer.h
	$(CC) $(CFLAGS) -o $@ $< mpeer.c $(INC) -L$(LIB) -lxseg -lpthread

mt-vlmcd: mt-vlmcd.c mpeer.c mpeer.h $(BASE)/xseg/protocol.h 
	$(CC) $(CFLAGS) -o $@ $< mpeer.c $(INC) -L$(LIB) -lxseg -lpthread

st-vlmcd: mt-vlmcd.c speer.c speer.h $(BASE)/xseg/protocol.h 
	$(CC) $(CFLAGS) -o $@ $< speer.c $(INC) -L$(LIB) -lxseg -lst

mt-mapperd: mt-mapperd.c speer.c speer.h $(BASE)/xseg/protocol.h 
	$(CC) $(CFLAGS) -o $@ $< speer.c $(INC) -L$(LIB) -lxseg -lpthread -lgcrypt -lst

pfiled: pfiled.c common.c $(BASE)/xseg/xseg.h $(BASE)/xseg/protocol.h common.h
	$(CC) $(CFLAGS) -o $@ $< common.c  $(INC) -L$(LIB) -lxseg -lpthread

vlmc-xseg: vlmc-tool.c $(BASE)/xseg/xseg.h
	$(CC) $(CFLAGS) -o $@ $< $(INC) -L$(LIB) -lxseg

clean:
	rm -f filed xseg sosd vlmcd mapperd mt-sosd dummy monitor mt-mapperd pfiled vlmc-xseg st-vlmcd mt-vlmcd
