# Default setup for subdirectory Makefiles.

CC=gcc
ifndef MOPTS
MOPTS=
endif
ifndef COPTS
COPTS=-O2 -g -finline-functions $(MOPTS) $(DEBUG)
endif
ifndef CSTD
CSTD=-std=gnu99 -pedantic
endif
INC=-I$(BASE)
CFLAGS=-Wall $(INC) $(COPTS) $(CSTD)

