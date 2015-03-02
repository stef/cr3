# uncomment if you do not need passwords in private keys
# WITHOUT_PASSWORDS=y
# uncomment if you do not want/have seccomp
# WITHOUT_SECCOMP=y

INCLUDES = -I../crypto/keccak -I.. -I../common
LDFLAGS = -Wl,--gc-sections -Wl,-z,relro,-PIE -fPIC
LIBS = -lssl -lcrypto
CFLAGS = -O3 -Wall -march=native -Werror -fPIC -fstack-protector \
	--param=ssp-buffer-size=4 -Wformat -Werror=format-security \
	$(INCLUDES)
# for debugging
#CFLAGS = -g -Wall -march=native -Werror -fPIC -fstack-protector --param=ssp-buffer-size=4 -Wformat -Werror=format-security  $(INCLUDES)

objs = ../common/utils.o ../crypto/keccak/keccak.o crypto.o

ifeq ($(WITHOUT_PASSWORDS), y)
 CFLAGS := $(CFLAGS) -DNOPASSWORD
endif

ifeq ($(WITHOUT_SECCOMP), y)
	CFLAGS := $(CFLAGS) -DNOSECCOMP
else
	LIBS := $(LIBS) -lseccomp
	objs := $(objs) sandbox.o
endif

all : cod

cod : main.c $(objs)
	$(CC) $(CFLAGS) $(LDFLAGS) -o cod main.c $(objs) $(LIBS)

clean:
	rm -rf cod $(objs)

install: cod
	strip -s cod
	cp cod /usr/bin/cod

test: cod
	./tests/test.sh

.PHONY: clean all install test
