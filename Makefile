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
	@echo "generating password-protected keys (and wasting entropy, don't do this often please)"
	@$(eval tmpdir:=$(shell mktemp -d))
	@mkdir -p $(tmpdir)
	@openssl genrsa -aes256 -passout pass:password -out $(tmpdir)/my.key 4096 2>/dev/null
	@openssl rsa -passin pass:password -in $(tmpdir)/my.key -pubout >> $(tmpdir)/my.pub 2>/dev/null
	@echo It works | ./cod e $(tmpdir)/my.pub | ./cod d $(tmpdir)/my.key password
	./cod e $(tmpdir)/my.pub <cod.c | ./cod d $(tmpdir)/my.key password | md5sum
	@md5sum cod.c
	for i in {0..42} {8170..8210} 1000000; do \
	    echo -ne "\r$$i      "; \
	    dd if=/dev/zero bs=$$i count=1 2>/dev/null | \
	         ./cod e $(tmpdir)/my.pub | \
	         ./cod d $(tmpdir)/my.key password >/dev/null || \
				{ echo "test failed"; break; } \
	done
	@echo
	@echo "generating passwordless keys (such a waste of precious entropy :/)"
	@openssl genrsa -out $(tmpdir)/my1.key 4096 2>/dev/null
	@openssl rsa -in $(tmpdir)/my1.key -pubout >> $(tmpdir)/my1.pub 2>/dev/null
	@echo It works | ./cod e $(tmpdir)/my1.pub | ./cod d $(tmpdir)/my1.key
	./cod e $(tmpdir)/my1.pub <cod.c | ./cod d $(tmpdir)/my1.key | md5sum
	@md5sum cod.c
	for i in {0..42} {8170..8210} 1000000; do \
	    echo -ne "\r$$i      "; \
	    dd if=/dev/zero bs=$$i count=1 2>/dev/null | \
	         ./cod e $(tmpdir)/my1.pub | \
	         ./cod d $(tmpdir)/my1.key >/dev/null || \
				{ echo "test failed"; break; } \
	done
	@echo
	@rm -rf $(tmpdir)

.PHONY: clean all install test
