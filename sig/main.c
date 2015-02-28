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
#include "crypto.h"
#include "sandbox.h"

void usage(void) {
  fprintf(stderr,"sig usage:`\n");
  fprintf(stderr,"`./sig g <key name>`        key generation into <key name>.(key|pub)\n");
  fprintf(stderr,"`... | ./sig s privkey.pem | ...`    signing\n\n");
  fprintf(stderr,"`... | ./sig v pub.pem | ...`        verification\n");
}

int main(const int argc, const char** argv) {
  int ret = 1;
  if(argc!=3) {
    usage();
    exit(1);
  }

  if(argv[1][0]=='g') {
    FILE* skfd = NULL, *pkfd = NULL;
    if(argc == 3 && argv[1][0]=='g') {
      // open key files to be written
      if(sig_keyfds((char*) argv[2], &skfd, &pkfd)==0) {

        // drop privileges if we have any, deny any privilege escalation
        drop_privs();
        // sandbox
        seccomp_genkey(skfd, pkfd);

        // generate and save keys
        ret = sig_genkey(skfd, pkfd);

      } else {
        fprintf(stderr,"failed to write keys\n");
        ret = 1;
      }
    }

  } else if(argv[1][0]=='s' || argv[1][0]=='v') {
    // open key file, leave the reading/parsing after the sandboxing
    int keyfd;
    if((keyfd=open(argv[2],O_RDONLY))==-1) {
      fprintf(stderr, "couldn't open %s (%s)\n", argv[2], strerror(errno));
      exit(1);
    }

    // drop privileges if we have any, deny any privilege escalation
    drop_privs();
    // sandbox
    lock_seccomp(keyfd);

    // load the key into memory
    struct stat st;
    if(fstat(keyfd, &st)==-1) {
      fprintf(stderr, "couldn't stat %s (%s)\n", argv[2], strerror(errno));
      exit(1);
    }
    if(st.st_size>2048) { // 2K secret key pem is a recklessly generous limit
      fprintf(stderr, "%s too big - are you sure this is a valid key?\n", argv[2]);
      exit(1);
    }
    char key[st.st_size];
    if (mlock(key, st.st_size) < 0) {
      fprintf(stderr, "couldn't mlock %ld bytes for key.\n", st.st_size);
      exit(1);
    }
    if((ret=read(keyfd, key, st.st_size))!=st.st_size) {
      fprintf(stderr, "couldn't read complete key, only %d bytes read out of %ld.\n", ret, st.st_size);
      exit(1);
    }
    close(keyfd);

    ret=1;
    // decide what to do and act on it
    if(argv[1][0]=='v') {
      ret = sig_verify(key);
      // clear key from mem
    } else {
      ret = sig_sign(key);
      // clear key from mem
    }
    zerobytes((u8*) key, st.st_size);
  } else {
    usage();
    ret=1;
  }

  return ret;
}
