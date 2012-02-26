.PHONY: default clean target-list

include ./base.mk

XSEG_CLEAN_TARGETS=$(patsubst %,clean-%,$(XSEG_DOMAIN_TARGETS))

default: targets

target-list:
	@echo $(XSEG_DOMAIN_TARGETS)

targets: $(XSEG_DOMAIN_TARGETS)

clean: $(XSEG_CLEAN_TARGETS)

.PHONY: $(XSEG_DOMAIN_TARGETS)
$(XSEG_DOMAIN_TARGETS):
	@for f in $(XSEG_DOMAIN_DIRS); do \
		echo " "; \
		echo "=== $@ in $$f ==="; \
		echo " "; \
		make -C $$f/$@ TARGET=$@ default || exit 1; \
		echo " "; \
	done
	@echo " "

.PHONY: $(XSEG_CLEAN_TARGETS)
$(XSEG_CLEAN_TARGETS):
	@for f in $(XSEG_DOMAIN_DIRS); do \
		echo " "; \
		echo "=== $@ in $$f ==="; \
		echo " "; \
		make -C $$f/$(@:clean-%=%) TARGET=$@ clean || true; \
		echo " "; \
	done
	rm -f ./config.mk
	@echo " "

