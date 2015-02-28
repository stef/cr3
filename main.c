#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include "utils.h"
#include "crypto.h"

void usage(void) {
  fprintf(stderr,"cod usage:`\n");
  fprintf(stderr,"`... | ./cod e pub.pem | ...`        encryption\n");
  fprintf(stderr,"`... | ./cod d privkey.pem | ...`    decryption\n\n");
#ifndef NOPASSWORD
  fprintf(stderr,"if your private key is encrypted, supply the passphrase in the COD_PASSWORD env variable:\n");
  fprintf(stderr,"`... | COD_PASSWORD='secret' ./cod d privkey.pem | ...`    decryption\n");
#endif
}

int main(const int argc, const char** argv) {
  if(argc!=3) {
    usage();
    exit(1);
  }

  // open key file, leave the reading/parsing after the sandboxing
  int keyfd;
  if((keyfd=open(argv[2],O_RDONLY))==-1) {
    fprintf(stderr, "couldn't open %s (%s)\n", argv[2], strerror(errno));
    exit(1);
  }

  // drop privileges if we have any, deny any privilege escalation
  drop_privs();
  // sandbox
  // most importantly this sandboxes the parsing of the RSA keys
  lock_seccomp();

  ERR_load_crypto_strings();

  // load the key into memory
  struct stat st;
  if(fstat(keyfd, &st)==-1) {
    fprintf(stderr, "couldn't stat %s (%s)\n", argv[2], strerror(errno));
    exit(1);
  }
  if(st.st_size>1024*16) { // 16K secret key pem is a recklessly generous limit
    fprintf(stderr, "%s too big - are you sure this is a rsa key?\n", argv[2]);
    exit(1);
  }
  char key[st.st_size];
  if (mlock(key, st.st_size) < 0) {
    fprintf(stderr, "couldn't mlock %ld bytes for key.\n", st.st_size);
    exit(1);
  }
  int ret;
  if((ret=read(keyfd, key, st.st_size))!=st.st_size) {
    fprintf(stderr, "couldn't read complete key, only %d bytes read out of %ld.\n", ret, st.st_size);
    exit(1);
  }
  close(keyfd);

  ret=1;
  // decide what to do and act on it
  if(argv[1][0]=='e') {
    ret = cod_encrypt(key);
  } else if(argv[1][0]=='d') {
#ifndef NOPASSWORD
    // try reading password for private key from env COD_PASSWORD
    char* password = getenv("COD_PASSWORD");
    unsigned int pw_len = 0;
    if(password!=NULL) {
      pw_len = strlen(password);
      if (mlock(password, pw_len) < 0) {
        fprintf(stderr,"error locking password into memory: %s", strerror(errno));
        clear((u8*) password, pw_len);
        exit(1);
      }
      OpenSSL_add_all_algorithms();
    }

    ret = cod_decrypt(key, (u8*) password);
    if(password) clear((u8*) password, pw_len);
#else // !defined(NOPASSWORD)
    ret = cod_decrypt(key, NULL);
#endif
  } else {
    usage();
  }

  // clear rsa key from mem
  clear(key, st.st_size);

  return ret;
}
