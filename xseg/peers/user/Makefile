.PHONY: default all clean

include $(XSEG_HOME)/base.mk

default: all

#all: filed xseg sosd vlmcd mapperd
#all: filed xseg vlmcd mapperd
all: filed xseg mt-sosd dummy mt-vlmcd mapperd mt-mapperd pfiled monitor vlmc-xseg st-vlmcd mt-pfiled


filed: filed.c $(BASE)/xseg/xseg.h
	$(CC) $(CFLAGS) -o $@ $< $(INC) -L$(LIB) -lxseg -lpthread

vlmcd: vlmcd.c common.c $(BASE)/xseg/xseg.h $(BASE)/xseg/protocol.h common.h
	$(CC) $(CFLAGS) -o $@ $< common.c $(INC) -L$(LIB) -lxseg

mapperd: mapperd.c common.c $(BASE)/xseg/xseg.h $(BASE)/xseg/protocol.h common.h
	$(CC) $(CFLAGS) -o $@ $< common.c $(INC) -L$(LIB) -lxseg

sosd: sosd.c $(BASE)/xseg/xseg.h $(BASE)/util_libs/user/sos/sos.h
	$(CC) $(CFLAGS) -o $@ $< $(INC) -L$(LIB) -lxseg -lsos

xseg: xseg-tool.c $(BASE)/xseg/xseg.h
	$(CC) $(CFLAGS) -o $@ $< $(BASE)/xtypes/xheap.c $(INC) -L$(LIB) -lxseg

mt-sosd: mt-sosd.c peer.c peer.h
	$(CC) $(CFLAGS) -o $@ $< peer.c $(INC) -L$(LIB) -lxseg -lrados -lpthread -DMT

dummy: dummy.c peer.c peer.h
	$(CC) $(CFLAGS) -o $@ $< peer.c $(INC) -L$(LIB) -lxseg -lpthread -DMT

monitor: monitor.c peer.c peer.h
	$(CC) $(CFLAGS) -o $@ $< peer.c $(INC) -L$(LIB) -lxseg -lpthread -DMT

mt-vlmcd: mt-vlmcd.c peer.c peer.h $(BASE)/xseg/protocol.h 
	$(CC) $(CFLAGS) -o $@ $< peer.c $(INC) -L$(LIB) -lxseg -lpthread -DMT

mt-pfiled: mt-pfiled.c peer.c peer.h $(BASE)/xseg/protocol.h 
	$(CC) $(CFLAGS) -o $@ $< peer.c $(INC) -L$(LIB) -lxseg -lpthread -DMT

st-vlmcd: mt-vlmcd.c peer.c peer.h $(BASE)/xseg/protocol.h 
	$(CC) $(CFLAGS) -o $@ $< peer.c $(INC) -L$(LIB) -lxseg 

mt-mapperd: mt-mapperd.c peer.c peer.h $(BASE)/xseg/protocol.h 
	$(CC) $(CFLAGS) -o $@ $< peer.c $(INC) -L$(LIB) -DST_THREADS -lxseg -lst

pfiled: pfiled.c common.c $(BASE)/xseg/xseg.h $(BASE)/xseg/protocol.h common.h
	$(CC) $(CFLAGS) -o $@ $< common.c  $(INC) -L$(LIB) -lxseg -lpthread

vlmc-xseg: vlmc-tool.c $(BASE)/xseg/xseg.h
	$(CC) $(CFLAGS) -o $@ $< $(INC) -L$(LIB) -lxseg

clean:
	rm -f filed xseg sosd vlmcd mapperd mt-sosd dummy monitor mt-mapperd \
		pfiled vlmc-xseg st-vlmcd mt-vlmcd mt-pfiled
