#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "keccak.h"
#include "utils.h"
#include <sys/mman.h>

#define TAGLEN 16
#define KEYLEN 32
#define BUFSIZE 8192

char _PAD_KEYSTREAM   = 3;
char _PAD_PLAINSTREAM = 2;

typedef unsigned char u8;

void printLastError(char *msg) {
  char *err;
  err = ERR_error_string(ERR_get_error(), NULL);
  printf("%s ERROR: %s\n", msg, err);
}

void loadkey(struct KeccakContext *ctx, unsigned char *mkey) {
  int max, i, avail;
  keccak_init(ctx, 1536);
  max = ctx->rbytes - 1;
  for(i=0;i<KEYLEN;i+=(KEYLEN-i>avail)?avail:(KEYLEN-i)) {
    avail = max - ctx->pos;
    if(avail==0) {
      keccak_pad(ctx, &_PAD_PLAINSTREAM, 1);
      continue;
    }
    keccak_absorb(ctx, mkey+i, (KEYLEN-i>avail)?avail:KEYLEN-i);
  }
  clear(mkey, KEYLEN);
}

int encrypt(void* pem) {
  RSA *rsa= NULL;
  BIO *keybio ;
  char unsigned mkey[KEYLEN];
  unsigned char cmkey[4098];
  int cmkey_len;
  struct KeccakContext ctx;
  int max, i, avail;
  unsigned char buf[BUFSIZE], dst[BUFSIZE];
  size_t size;
  unsigned char tag[TAGLEN];

  // load RSA key
  keybio = BIO_new_mem_buf(pem, -1);
  if (keybio==NULL) {
    printLastError("Failed to create key bio ");
    return 1;
  }
  rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
  if(rsa == NULL) {
    printLastError("Failed to load RSA public key ");
    BIO_free(keybio);
    return 1;
  }

  if (mlock(mkey, KEYLEN) < 0) {
    fprintf(stderr,"error locking mkey into memory: %s", strerror(errno));
    RSA_free(rsa);
    BIO_free(keybio);
    return 1;
  }

  // Generate and encrypt message key
  if(RAND_bytes(mkey, KEYLEN) != 1) {
    printLastError("Failed to get random ");
    RSA_free(rsa);
    BIO_free(keybio);
    return 1;
  }

  if((cmkey_len = RSA_public_encrypt(KEYLEN,mkey,cmkey,rsa,RSA_PKCS1_OAEP_PADDING)) == -1) {
    printLastError("Public Encrypt failed ");
    RSA_free(rsa);
    BIO_free(keybio);
    clear(mkey, KEYLEN);
    return 1;
  }

  // throw away RSA key
  RSA_free(rsa);
  BIO_free(keybio);

  // write out message key
  if(fwrite(&cmkey_len, 2, 1, stdout)!=1) {
    fprintf(stderr,"failed to write to stdout: %s\n", strerror(errno));
    clear(mkey, KEYLEN);
    return 1;
  }
  if(fwrite(cmkey, cmkey_len, 1, stdout)!=1) {
    fprintf(stderr,"failed to write to stdout: %s\n", strerror(errno));
    clear(mkey, KEYLEN);
    return 1;
  }

  if (mlock(&ctx, sizeof(ctx)) < 0) {
    fprintf(stderr,"error locking ctx into memory: %s", strerror(errno));
    clear(mkey, KEYLEN);
    return 1;
  }

  // seed sponge with the message key
  loadkey(&ctx, mkey);

  max = ctx.rbytes - 1;

  // buffered encrypt and output
  keccak_pad(&ctx, &_PAD_KEYSTREAM, 1);
  size=read(0, buf, BUFSIZE);
  while(size > 0) {
    for(i=0;i<size;i+=avail) {
      avail = max - ctx.pos;
      if(avail==0) {
        keccak_pad(&ctx, &_PAD_KEYSTREAM, 1);
        continue;
      }
      keccak_encrypt(&ctx, dst+i, buf+i, (size-i>avail)?avail:size-i);
    }
    if(fwrite(dst, size, 1, stdout)!=1) {
      fprintf(stderr,"failed to write to stdout: %s\n", strerror(errno));
      keccak_forget(&ctx);
      return 1;
    }
    size=read(0, buf, BUFSIZE);
  }
  // calculate tag and output
  keccak_pad(&ctx, &_PAD_PLAINSTREAM, 1);
  keccak_squeeze(&ctx, tag, TAGLEN);
  if(fwrite(tag, TAGLEN, 1, stdout)!=1) {
      fprintf(stderr,"failed to write to stdout: %s\n", strerror(errno));
      keccak_forget(&ctx);
      return 1;
  }
  keccak_forget(&ctx);
  return 0;
}

int decrypt(void* pem, u8* password) {
  RSA *rsa= NULL;
  BIO *keybio;
  unsigned char mkey[1024];
  unsigned char cmkey[4098];
  int cmkey_len = 0;
  struct KeccakContext ctx;
  int max, i, avail, ret;
  unsigned char buf[BUFSIZE], dst[BUFSIZE];
  size_t size;
  unsigned char tag[TAGLEN];

  // load RSA private key
  keybio = BIO_new_mem_buf(pem, -1);
  if (keybio==NULL) {
    printLastError("Failed to create key bio ");
    return 1;
  }
  rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, password);
  if(rsa == NULL) {
    printLastError("Failed to load RSA private key ");
    BIO_free(keybio);
    return 1;
  }

  // load encrypted message key from stdin and decrypt
  if(read(0, &cmkey_len, 2)!=2 ||
     cmkey_len > 1024 ||
     read(0, &cmkey, cmkey_len)!=cmkey_len) {
    fprintf(stderr, "corrupt input\n");
    RSA_free(rsa);
    BIO_free(keybio);
    return 1;
  }

  if (mlock(mkey, KEYLEN) < 0) {
    fprintf(stderr,"error locking mkey into memory: %s", strerror(errno));
    RSA_free(rsa);
    BIO_free(keybio);
    return 1;
  }

  if(RSA_private_decrypt(cmkey_len,cmkey,mkey,rsa,RSA_PKCS1_OAEP_PADDING) == -1) {
    clear(mkey, KEYLEN);
  }

  // forget RSA key
  RSA_free(rsa);
  BIO_free(keybio);

  if (mlock(&ctx, sizeof(ctx)) < 0) {
    fprintf(stderr,"error locking ctx into memory: %s", strerror(errno));
    clear(mkey, KEYLEN);
    return 1;
  }

  // seed sponge with message key
  loadkey(&ctx, mkey);
  max = ctx.rbytes - 1;

  // decrypt incoming stdin to stdout while always retaining the last
  // 16 bytes to be able to use them to verify the message tag
  keccak_pad(&ctx, &_PAD_KEYSTREAM, 1);
  size=read(0, buf, BUFSIZE);
  while(size > TAGLEN) {
    for(i=0;i<size-TAGLEN;i+=((size-TAGLEN)-i>avail)?avail:((size-TAGLEN)-i)) {
      avail = max - ctx.pos;
      if(avail==0) {
        keccak_pad(&ctx, &_PAD_KEYSTREAM, 1);
        continue;
      }
      keccak_decrypt(&ctx, dst+i, buf+i, ((size-TAGLEN)-i>avail)?avail:(size-TAGLEN)-i);
    }
    if(fwrite(dst, size-TAGLEN, 1, stdout)!=1) {
      fprintf(stderr,"failed to write to stdout: %s\n", strerror(errno));
      keccak_forget(&ctx);
      return 1;
    }
    // move last 16 to the beginning of buf
    memcpy(buf, buf+(size-TAGLEN), TAGLEN);
    if((ret = read(0, buf+TAGLEN, BUFSIZE-TAGLEN))>0) {
      size=TAGLEN+ret;
    } else {
      size=16;
    }
  }
  // calculate tag
  keccak_pad(&ctx, &_PAD_PLAINSTREAM, 1);
  keccak_squeeze(&ctx, tag, TAGLEN);
  keccak_forget(&ctx);

  // verify tag which we retained during buffered reading with
  // calculated tag
  if(cmp(tag, buf, TAGLEN)!=0) {
    fprintf(stderr,"failed to decrypt\n");
    return 1;
  }
  return 0;
}

void usage(void) {
  fprintf(stderr,"cod usage:`\n");
  fprintf(stderr,"`... | ./cod e pub.pem | ...`        encryption\n");
  fprintf(stderr,"`... | ./cod d privkey.pem | ...`    decryption (plaintext rsa key) or:\n");
  fprintf(stderr,"`... | ./cod d privkey.pem '(password for encrypted rsa key)' | ...`\n");
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
  char *key;
  if((key=malloc(st.st_size))==NULL) {
    fprintf(stderr, "couldn't malloc %ld bytes for key.\n", st.st_size);
    exit(1);
  }
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
    ret = encrypt(key);
  } else if(argv[1][0]=='d') {
    // try reading password for private key from env COD_PASSWORD
    char* password = getenv("COD_PASSWORD");
    unsigned int pw_len = 0;
    if(password!=NULL) {
      pw_len = strlen(password);
      if(pw_len>512) {
        fprintf(stderr, "password is a bit too long: (%d)\n", pw_len);
        exit(1);
      }
      if (mlock(password, pw_len) < 0) {
        fprintf(stderr,"error locking password into memory: %s", strerror(errno));
        clear((u8*) password, pw_len);
        exit(1);
      }
      OpenSSL_add_all_algorithms();
    }

    ret = decrypt(key, (u8*) password);
    if(password) clear((u8*) password, pw_len);
  } else {
    usage();
  }

  // clear rsa key from mem
  clear(key, st.st_size);

  return ret;
}
