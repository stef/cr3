LDFLAGS = -Wl,--gc-sections -Wl,-z,relro,-PIE -fPIC
LIBS = -lseccomp -lssl -lcrypto
CFLAGS = -O3 -Wall -march=native -Werror -fPIC -fstack-protector --param=ssp-buffer-size=4 -Wformat -Werror=format-security  $(INCLUDES)
# for debugging
#CFLAGS = -g -Wall -march=native -Werror -fPIC -fstack-protector --param=ssp-buffer-size=4 -Wformat -Werror=format-security  $(INCLUDES)

objs = utils.o keccak.o

all : cod

cod : cod.c $(objs)
	$(CC) $(CFLAGS) $(LDFLAGS) -o cod cod.c $(objs) $(LIBS)

clean:
	rm -rf cod *.o

install: cod
	strip -s cod
	cp cod /usr/bin/cod

test: cod
	@echo "generating keys (and wasting entropy, don't do this often please)"
	@$(eval tmpdir:=$(shell mktemp -d))
	@mkdir -p $(tmpdir)
	@openssl genrsa -out $(tmpdir)/my.key 4096 2>/dev/null
	@openssl rsa -in $(tmpdir)/my.key -pubout >> $(tmpdir)/my.pub 2>/dev/null
	@cat $(tmpdir)/my.key $(tmpdir)/my.pub >>$(tmpdir)/my.pem
	@rm $(tmpdir)/my.key
	./cod e $(tmpdir)/my.pub <cod.c | ./cod d $(tmpdir)/my.pem | md5sum
	md5sum cod.c
	for i in {0..42} {8170..8210} 1000000; do \
	    echo -ne "\r$$i      "; \
	    dd if=/dev/zero bs=$$i count=1 2>/dev/null | \
	         ./cod e $(tmpdir)/my.pub | \
	         ./cod d $(tmpdir)/my.pem >/dev/null || \
				{ echo "test failed"; break; } \
	done
	@echo
	@rm -rf $(tmpdir)

.PHONY: clean all install test
