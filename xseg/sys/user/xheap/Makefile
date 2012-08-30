.PHONY: default all clean

include $(XSEG_HOME)/base.mk

DEBUG=-g

default: all

all: xheap.o xheap.pic.o xheap_test 

$(BASE)/sys/user/xseg_user.o:
	make -C $(BASE)/sys/user xseg_user.o

xheap_test: $(BASE)/xtypes/xheap_test.c xheap.o $(BASE)/sys/user/xseg_user.o
	$(CC) $(CFLAGS) $(INC) -L$(LIB) -o $@ $< xheap.o \
	$(BASE)/sys/user/xseg_user.o -ldl -lpthread

xheap.o: $(BASE)/xtypes/xheap.c $(BASE)/xtypes/xheap.h $(BASE)/xtypes/xlock.h
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

xheap.pic.o: $(BASE)/xtypes/xheap.c $(BASE)/xtypes/xheap.h $(BASE)/xtypes/xlock.h
	$(CC) $(CFLAGS) $(INC) -fPIC -c -o $@ $<

clean:
	rm -f xheap.o xheap.pic.o xheap_test
