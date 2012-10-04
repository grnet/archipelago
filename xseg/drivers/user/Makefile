.PHONY: default all clean xseg lib

include $(XSEG_HOME)/base.mk

DRIVERS=xseg_posix xseg_segdev xseg_pthread
DRVOBJS=$(DRIVERS:=.o)
DRVSOS=$(DRIVERS:=.so)

default: all

all: xseg $(DRIVERS:=.so) lib

$(BASE)/sys/user/xseg_user.o:
	make -C $(BASE)/sys/user xseg_user.o

xseg_posix.o: xseg_posix.c $(BASE)/xseg/xseg.h $(BASE)/drivers/xseg_posix.h
	$(CC) $(CFLAGS) $(INC) -fPIC -c -o $@ $<

xseg_posix.so: xseg_posix.o $(BASE)/sys/user/xseg_user.o
	$(CC) -shared -o $@ $< $(BASE)/sys/user/xseg_user.o 

xseg_segdev.o: xseg_segdev.c $(BASE)/xseg/xseg.h $(BASE)/drivers/xseg_segdev.h
	$(CC) $(CFLAGS) $(INC) -fPIC -c -o $@ $<

xseg_segdev.so: xseg_segdev.o $(BASE)/sys/user/xseg_user.o
	$(CC) -shared -o $@ $< $(BASE)/sys/user/xseg_user.o 

xseg_pthread.o: xseg_pthread.c $(BASE)/xseg/xseg.h $(BASE)/drivers/xseg_pthread.h
	$(CC) $(CFLAGS) $(INC) -fPIC -c -o $@ $<

xseg_pthread.so: xseg_pthread.o $(BASE)/sys/user/xseg_user.o
	$(CC) -shared -lpthread -o $@ $< $(BASE)/sys/user/xseg_user.o 

.PHONY: lib
lib:
	cp -vaf $(DRVSOS) $(LIB)
clean:
	rm -f $(DRVOBJS) $(DRVSOS)
