# uncomment if you do not need passwords in private keys
# WITHOUT_PASSWORDS=-DNOPASSWORD

INCLUDES = -I../crypto/keccak -I..
LDFLAGS = -Wl,--gc-sections -Wl,-z,relro,-PIE -fPIC
LIBS = -lseccomp -lssl -lcrypto
CFLAGS = -O3 -Wall -march=native -Werror -fPIC -fstack-protector \
	--param=ssp-buffer-size=4 -Wformat -Werror=format-security \
	$(WITHOUT_PASSWORDS) $(INCLUDES)
# for debugging
#CFLAGS = -g -Wall -march=native -Werror -fPIC -fstack-protector --param=ssp-buffer-size=4 -Wformat -Werror=format-security  $(INCLUDES)

objs = ../utils.o ../crypto/keccak/keccak.o crypto.o sandbox.o

all : cod

cod : main.c $(objs)
	$(CC) $(CFLAGS) $(LDFLAGS) -o cod main.c $(objs) $(LIBS)

clean:
	rm -rf cod $(objs)

install: cod
	strip -s cod
	cp cod /usr/bin/cod

test: cod
	@echo "generating passwordless keys (and wasting entropy, don't do this often please)"
	@$(eval tmpdir:=$(shell mktemp -d))
	@mkdir -p $(tmpdir)
	@openssl genrsa -out $(tmpdir)/my1.key 4096 2>/dev/null
	@openssl rsa -in $(tmpdir)/my1.key -pubout >> $(tmpdir)/my1.pub 2>/dev/null
	@echo It works | ./cod e $(tmpdir)/my1.pub | ./cod d $(tmpdir)/my1.key
	./cod e $(tmpdir)/my1.pub <crypto.c | ./cod d $(tmpdir)/my1.key | md5sum
	@md5sum crypto.c
	for i in {0..42} {8170..8210} 1000000; do \
	    echo -ne "\r$$i      "; \
	    dd if=/dev/zero bs=$$i count=1 2>/dev/null | \
	         ./cod e $(tmpdir)/my1.pub | \
	         ./cod d $(tmpdir)/my1.key >/dev/null || \
				{ echo "test failed"; break; } \
	done
	@echo
	@echo "generating password-protected keys (such a waste of precious entropy :/)"
	@openssl genrsa -aes256 -passout pass:password -out $(tmpdir)/my.key 4096 2>/dev/null
	@openssl rsa -passin pass:password -in $(tmpdir)/my.key -pubout >> $(tmpdir)/my.pub 2>/dev/null
	@echo It works | ./cod e $(tmpdir)/my.pub | COD_PASSWORD=password ./cod d $(tmpdir)/my.key
	./cod e $(tmpdir)/my.pub <crypto.c | COD_PASSWORD=password ./cod d $(tmpdir)/my.key | md5sum
	@md5sum crypto.c
	for i in {0..42} {8170..8210} 1000000; do \
	  echo -ne "\r$$i      "; \
	  dd if=/dev/zero bs=$$i count=1 2>/dev/null | \
			 ./cod e $(tmpdir)/my.pub | \
			 COD_PASSWORD=password ./cod d $(tmpdir)/my.key >/dev/null || \
			 { echo "test failed"; break; } \
	done
	@echo
	@rm -rf $(tmpdir)

.PHONY: clean all install test
