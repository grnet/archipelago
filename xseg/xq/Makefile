.PHONY: all clean

BASE=..
DEBUG=-g

include $(BASE)/config.mk
include $(BASE)/base.mk

all: xq.o xq.pic.o xq_test xq_lock_test

$(BASE)/sys/xseg_user.o:
	make -C $(BASE)/sys xseg_user.o

xq_test: xq_test.c xq.o $(BASE)/sys/xseg_user.o
	$(CC) $(CFLAGS) -o $@ $< xq.o $(BASE)/sys/xseg_user.o -lrt -lm -ldl -lpthread

xq_lock_test: xq_lock_test.c xq.o $(BASE)/sys/xseg_user.o
	$(CC) $(CFLAGS) -o $@ $< xq.o $(BASE)/sys/xseg_user.o -lrt -lm -ldl -lpthread

xq.o: xq.c xq.h xq_lock.h
	$(CC) $(CFLAGS) -DRELATIVE_POINTERS -c -o $@ $<

xq.pic.o: xq.c xq.h xq_lock.h
	$(CC) $(CFLAGS) -DRELATIVE_POINTERS -fPIC -c -o $@ $<

clean:
	rm -f xq_lock_test xq_test xq.o xq.pic.o
