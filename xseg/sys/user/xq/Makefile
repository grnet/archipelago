.PHONY: default all clean

include $(XSEG_HOME)/base.mk

DEBUG=-g

default: all

all: xq.o xq.pic.o xq_test xq_lock_test

$(BASE)/sys/user/xseg_user.o:
	make -C $(BASE)/sys/user xseg_user.o

xq_test: $(BASE)/xq/xq_test.c xq.o $(BASE)/sys/user/xseg_user.o
	$(CC) $(CFLAGS) $(INC) -L$(LIB) -o $@ $< xq.o \
	$(BASE)/sys/user/xseg_user.o -lrt -lm -ldl -lpthread

xq_lock_test: $(BASE)/xq/xq_lock_test.c xq.o $(BASE)/sys/user/xseg_user.o
	$(CC) $(CFLAGS) $(INC) -L$(LIB) -o $@ $< xq.o \
	$(BASE)/sys/user/xseg_user.o -lrt -lm -ldl -lpthread

xq.o: $(BASE)/xq/xq.c $(BASE)/xq/xq.h $(BASE)/xq/xq_lock.h
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

xq.pic.o: $(BASE)/xq/xq.c $(BASE)/xq/xq.h $(BASE)/xq/xq_lock.h
	$(CC) $(CFLAGS) $(INC) -fPIC -c -o $@ $<

clean:
	rm -f xq_lock_test xq_test xq.o xq.pic.o
