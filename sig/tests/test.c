#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "utils.h"
#include "sphincs256.h"

#include "testvectors.h"

int main(const int argc, const char** argv) {
  u8 pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
  if(crypto_sign_keypair(pk,sk)!=0) {
    return -1;
  }

  if(cmp(SK, sk, CRYPTO_SECRETKEYBYTES)!=0) {
    fprintf(stderr,"[er] failed to generate expected secret key\n");
    return 1;
  }

  if(cmp(PK, pk, CRYPTO_PUBLICKEYBYTES)!=0) {
    fprintf(stderr,"[er] failed to generate expected secret key\n");
    return 1;
  }

  char msg[] = "Cthulhu Fthagn --What a wonderful phrase!Cthulhu Fthagn --Say it and you're crazed!";

  u8 sm[CRYPTO_BYTES+sizeof(msg)];
  unsigned long long smlen;
  if(crypto_sign(sm, &smlen, (u8*) msg, sizeof(msg)-1, sk) == -1) {
    fprintf(stderr, "signing failed\n");
    return 1;
  }

  if(cmp(MSG, sm, CRYPTO_BYTES+sizeof(msg)-1)!=0) {
    fprintf(stderr,"[er] failed to generate expected message\n");
    return 1;
  }

  fprintf(stderr,"[ok] Test vectors compute.\n");
  return 0;
}
