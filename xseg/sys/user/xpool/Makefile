.PHONY: default all clean

include $(XSEG_HOME)/base.mk

DEBUG=-g

default: all

all: xpool.o xpool.pic.o 

$(BASE)/sys/user/xseg_user.o:
	make -C $(BASE)/sys/user xseg_user.o

xpool.o: $(BASE)/xtypes/xpool.c $(BASE)/xtypes/xpool.h $(BASE)/xtypes/xlock.h
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

xpool.pic.o: $(BASE)/xtypes/xpool.c $(BASE)/xtypes/xpool.h $(BASE)/xtypes/xlock.h
	$(CC) $(CFLAGS) $(INC) -fPIC -c -o $@ $<

clean:
	rm -f xpool.o xpool.pic.o
