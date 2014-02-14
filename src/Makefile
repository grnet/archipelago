PEERS := archip-sosd archip-mapperd archip-vlmcd archip-filed archip-bench archip-dummy archip-benchfd


monitor: monitor.c peer.c peer.h
	$(CC) $(CFLAGS) -o $@ $< peer.c $(INC) -L$(LIB) -lxseg -lpthread -DMT



archip-sosd: mt-sosd.c hash.c hash.h peer.c peer.h
	$(CC) $(CFLAGS) -o $@ $(CPREQS) $(INC) -L$(LIB) -lxseg -lrados -lpthread \
							-lcrypto -DMT
archip-dummy: dummy.c peer.c peer.h
	$(CC) $(CFLAGS) -o $@ $< peer.c $(INC) -L$(LIB) -lxseg -lpthread -DMT

BENCH_PREQ=bench-xseg.c peer.c bench-lfsr.c bench-timer.c bench-utils.c \
	   bench-report.c bench-verify.c				\
	   bench-xseg.h peer.h bench-lfsr.h $(BASE)/xseg/protocol.h

archip-bench: $(BENCH_PREQ)
	$(CC) $(CFLAGS) -o $@ $(CPREQS) $(INC) -L$(LIB) -lxseg -lpthread -lm

archip-benchfd: $(BENCH_PREQ)
	$(CC) $(CFLAGS) -o $@ $(CPREQS) $(INC) -L$(LIB) -lxseg -lpthread -lm -DFD

archip-filed: filed.c peer.c peer.h hash.c hash.h $(BASE)/xseg/protocol.h
	$(CC) $(CFLAGS) -o $@ $(CPREQS) $(INC) -L$(LIB) -lxseg -lpthread -DMT \
							-lcrypto

archip-vlmcd: mt-vlmcd.c peer.c peer.h $(BASE)/xseg/protocol.h
	$(CC) $(CFLAGS) -o $@ $< peer.c $(INC) -L$(LIB) -lxseg

MAPPER_PREQ=mapper.c mapper.h peer.c peer.h hash.h hash.c mapper-handling.c \
	    mapper-versions.h mapper-versions.c mapper-version0.h mapper-version0.c \
	    mapper-version1.h mapper-version1.c mapper-version2.h mapper-version2.c \
	    $(BASE)/xseg/protocol.h

archip-mapperd: $(MAPPER_PREQ)
	$(CC) $(CFLAGS) -o $@ $(CPREQS) $(INC) -L$(LIB) -DST_THREADS \
							-lxseg -lst -lcrypto
