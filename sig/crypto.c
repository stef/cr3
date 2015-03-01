#include <stdio.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <sys/stat.h>

#include "crypto.h"
#include "utils.h"
#include "sphincs256.h"
#include "keccak.h"

#define BUFSIZE (1<<16)

// for sandboxing overkill, we open the files, then process later in
// the sandbox
FILE* keyopen(char* prefix, char* postfix) {
  size_t fnlen = strlen(prefix)+strlen(postfix)+1;
  char name[fnlen];
  if( snprintf(name, fnlen, "%s%s", prefix, postfix) != fnlen-1) {
    fprintf(stderr, "couldn't compose filename\n");
    return NULL;
  }
  FILE *fp = fopen(name, "wb");
  if(fp==NULL) {
    fprintf(stderr, "failed to open %s\n", name);
    return NULL;
  }
  return fp;
}

int sig_keyfds(char* name, FILE** key, FILE** pub) {
  if((*pub=keyopen(name, ".pub"))==NULL) return 1;
  if((*key=keyopen(name, ".key"))==NULL) return 1;
  return 0;
}

int sig_genkey(FILE* keyfp, FILE* pubfp) {
  u8 pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
  // mlock key material
  if (mlock(pk, CRYPTO_PUBLICKEYBYTES) < 0) {
    fprintf(stderr, "couldn't mlock %d bytes for pubkey.\n", CRYPTO_PUBLICKEYBYTES);
    return -1;
  }
  if (mlock(pk, CRYPTO_SECRETKEYBYTES) < 0) {
    fprintf(stderr, "couldn't mlock %d bytes for secret key.\n", CRYPTO_PUBLICKEYBYTES);
    return -1;
  }

  // generate sphincs256 keypair
  if(crypto_sign_keypair(pk,sk)!=0) {
    return -1;
  }

  // write key to files
  if(fwrite(pk,CRYPTO_PUBLICKEYBYTES,1,pubfp) != 1) {
    fprintf(stderr, "failed to write pubkey: %s\n", strerror(errno));
    return 1;
  }
  fclose(pubfp);
  zerobytes(pk, CRYPTO_PUBLICKEYBYTES);

  fchmod(fileno(keyfp), 0600);
  if(fwrite(sk,CRYPTO_SECRETKEYBYTES,1,keyfp) != 1) {
    fprintf(stderr, "failed to write secret key: %s\n", strerror(errno));
    return 1;
  }
  fclose(keyfp);
  zerobytes(sk, CRYPTO_SECRETKEYBYTES);

  return 0;
}

int sig_sign(void* sk) {
  size_t size;
  unsigned char buf[BUFSIZE];
  struct KeccakContext ctx;
  keccak_init(&ctx, 1024);
  // buffered hashing and output
  while((size=fread(buf, 1, BUFSIZE, stdin)) > 0) {
    if(!_write(buf, size)) {
      return 1;
    }
    keccak_absorb( &ctx, buf, size );
  }

  // calculate sig and output
  u8 hash[SHA3_512_BYTES];
  u8 sm[CRYPTO_BYTES+SHA3_512_BYTES];
  unsigned long long smlen;
  sha3_512_digest( &ctx, hash, SHA3_512_BYTES);

  if(crypto_sign(sm, &smlen, hash, SHA3_512_BYTES, sk) == -1) {
    fprintf(stderr, "signing failed\n");
    return 1;
  }
  zerobytes(sk, CRYPTO_SECRETKEYBYTES);

  if(!_write(sm, CRYPTO_BYTES)) {
    return 1;
  }
  return 0;
}

int sig_verify(void* pk) {
  unsigned char buf[BUFSIZE], *hash = buf + CRYPTO_BYTES;
  size_t size;
  struct KeccakContext ctx;
  keccak_init(&ctx, 1024);

  // hash incoming stdin to stdout while always retaining the last
  // CRYPTO_BYTES to be able to use them to verify the message tag
  size=fread(buf, 1, BUFSIZE, stdin);
  if(size < CRYPTO_BYTES) {
    fprintf(stderr, "\ntruncated signature\n");
    return 1;
  }
  size-=CRYPTO_BYTES;
  while(size > 0) {
    if(!_write(buf, size)) {
      return 1;
    }
    keccak_absorb( &ctx, buf, size );
    // move last unhashed bytes to the beginning of buf
    memmove(buf, buf+size, CRYPTO_BYTES);
    size = fread(buf+CRYPTO_BYTES, 1, BUFSIZE-CRYPTO_BYTES, stdin);
  }
  fflush(stdout);

  sha3_512_digest( &ctx, hash, SHA3_512_BYTES);

  u8 msg[SHA3_512_BYTES];
  unsigned long long msglen;

  if(crypto_sign_open(msg, &msglen, buf, CRYPTO_BYTES+SHA3_512_BYTES, pk) == -1) {
    fprintf(stderr, "\nverification failed\n");
    return 1;
  }

  zerobytes(pk, CRYPTO_PUBLICKEYBYTES);
  return 0;
}
