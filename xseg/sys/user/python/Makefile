.PHONY: default all clean

include $(XSEG_HOME)/base.mk

H2XML = h2xml
XML2PY = xml2py

default: all

all: xseg/xseg_api.py xseg/xprotocol.py

$(BASE)/sys/user/libxseg.so:
	make -C $(BASE)/sys/user libxseg.so

xseg.xml: $(BASE)/xseg/xseg.h $(BASE)/xtypes/xq.h $(BASE)/xtypes/xlock.h \
	$(BASE)/xtypes/xpool.h $(BASE)/xtypes/xhash.h \
	$(BASE)/xtypes/xheap.h $(BASE)/xtypes/xobj.h \
	$(BASE)/sys/domain.h $(BASE)/sys/util.h $(BASE)/sys/user/_sysutil.h $(BASE)/xseg/protocol.h
	$(H2XML) -c $(INC) -o $@ $(BASE)/xseg/xseg.h

xprotocol.xml: 
	$(H2XML) -c $(INC) -o $@ $(BASE)/xseg/protocol.h

xseg/xseg_api.py: xseg.xml
	$(XML2PY) -d -k defst -l $(BASE)/lib/user/libxseg.so -c $< -o $@

xseg/xprotocol.py: xprotocol.xml
	$(XML2PY) -d -k defst -c $< -o $@

clean:
	rm -f xseg.xml xprotocol.xml xseg/xseg_api.py xseg/xseg_api.pyc xseg/xprotocol.py xseg/xprotocol.pyc xseg/__init__.pyc
