.PHONY: default all clean

include $(XSEG_HOME)/base.mk

DEBUG=-g

default: all

all: xhash.o xhash.pic.o xhash_test 

$(BASE)/sys/user/xseg_user.o:
	make -C $(BASE)/sys/user xseg_user.o

xhash_test: $(BASE)/xtypes/xhash_test.c xhash.o $(BASE)/sys/user/xseg_user.o
	$(CC) $(CFLAGS) $(INC) -L$(LIB) -o $@ $< xhash.o \
	$(BASE)/sys/user/xseg_user.o -ldl

xhash.o: $(BASE)/xtypes/xhash.c $(BASE)/xtypes/xhash.h $(BASE)/xtypes/xlock.h
	$(CC) $(CFLAGS) $(INC) -DVAL_OVERLOAD -c -o $@ $<

xhash.pic.o: $(BASE)/xtypes/xhash.c $(BASE)/xtypes/xhash.h $(BASE)/xtypes/xlock.h
	$(CC) $(CFLAGS) $(INC) -DVAL_OVERLOAD -fPIC -c -o $@ $<

clean:
	rm -f xhash.o xhash.pic.o xhash_test
