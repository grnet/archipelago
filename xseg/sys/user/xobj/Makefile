.PHONY: default all clean

include $(XSEG_HOME)/base.mk

DEBUG=-g

default: all

all: xobj.o xobj.pic.o xobj_test

$(BASE)/sys/user/xseg_user.o:
	make -C $(BASE)/sys/user xseg_user.o

xobj_test: $(BASE)/xtypes/xobj_test.c xobj.o $(BASE)/sys/user/xheap/xheap.o $(BASE)/sys/user/xseg_user.o
	$(CC) $(CFLAGS) $(INC) -L$(LIB) -o $@ $< xobj.o \
	$(BASE)/sys/user/xseg_user.o $(BASE)/sys/user/xhash/xhash.o \
	$(BASE)/sys/user/xheap/xheap.o -ldl -lpthread

xobj.o: $(BASE)/xtypes/xobj.c $(BASE)/xtypes/xobj.h $(BASE)/sys/user/xheap/xheap.o $(BASE)/xtypes/xlock.h
	$(CC) $(CFLAGS) $(INC) -c -o $@ $< $(BASE)/sys/user/xheap/xheap.o

xobj.pic.o: $(BASE)/xtypes/xobj.c $(BASE)/xtypes/xobj.h $(BASE)/xtypes/xlock.h
	$(CC) $(CFLAGS) $(INC) -fPIC -c -o $@ $< $(BASE)/sys/user/xheap/xheap.pic.o

clean:
	rm -f xobj.o xobj.pic.o xobj_test
