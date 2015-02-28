# uncomment if you do not need passwords in private keys
# WITHOUT_PASSWORDS=-DNOPASSWORD

INCLUDES = -I../crypto/blake -I../crypto/chacha12 -I../crypto/sphincs256 -I. -I..
LDFLAGS = -Wl,--gc-sections -Wl,-z,relro,-PIE -fPIC
LIBS = -lseccomp
CFLAGS = -O3 -Wall -march=native -Werror -fPIC -fstack-protector \
	--param=ssp-buffer-size=4 -Wformat -Werror=format-security \
	$(INCLUDES)
# for debugging
#CFLAGS = -g -Wall -march=native -Werror -fPIC -fstack-protector --param=ssp-buffer-size=4 -Wformat -Werror=format-security  $(INCLUDES)

_objs = ../crypto/sphincs256/consts.o ../crypto/sphincs256/hash.o \
	../crypto/sphincs256/horst.o ../crypto/sphincs256/permute.o \
	../crypto/sphincs256/prg.o  ../crypto/sphincs256/sign.o \
	../crypto/sphincs256/wots.o ../crypto/blake/blake256.o \
	../crypto/blake/blake512.o ../crypto/chacha12/chacha.o \
	../utils.o crypto.o sandbox.o

objs = $(_objs) randombytes.o

test_objs = $(_objs) tests/notrandom.o

all : sphincs sphincs-test

sphincs : main.c $(objs)
	$(CC) $(CFLAGS) $(LDFLAGS) -o sphincs main.c $(objs) $(LIBS)

sphincs-test : tests/test.c $(test_objs)
	$(CC) $(CFLAGS) $(LDFLAGS) -o sphincs-test tests/test.c $(test_objs) $(LIBS)

clean:
	rm -rf sphincs sphincs-test *.o $(objs) tests/notrandom.o

test: sphincs-test sphincs
	./sphincs-test
	@$(eval tmpdir:=$(shell mktemp -d))
	@mkdir -p $(tmpdir)
	./sphincs g $(tmpdir)/asdf
	echo "hello world" | ./sphincs s $(tmpdir)/asdf.key | ./sphincs v $(tmpdir)/asdf.pub
	@rm -rf $(tmpdir)
	./sphincs v /tmp/asdf.pub </tmp/b || exit 0

.PHONY: clean all test
