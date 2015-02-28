test:
	$(MAKE) -C cod test
	$(MAKE) -C sig test

clean:
	$(MAKE) -C cod clean
	$(MAKE) -C sig clean

all:
	$(MAKE) -C cod all
	$(MAKE) -C sig all

.PHONY: test clean all
