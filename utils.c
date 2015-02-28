#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/prctl.h> /* prctl */
#include "utils.h"

#define USERID 65534
#define GROUPID 65534

void* clear(void *v,size_t n) {
  volatile char *p=v; while (n--) *p++=0; return v;
}

int cmp(const void * a, const void *b, const size_t size) {
  const unsigned char *_a = (const unsigned char *) a;
  const unsigned char *_b = (const unsigned char *) b;
  unsigned char result = 0;
  size_t i;

  for (i = 0; i < size; i++) {
    result |= _a[i] ^ _b[i];
  }

  return result; /* returns 0 if equal, nonzero otherwise */
}

int _write(const u8* src, const size_t len) {
  if(fwrite(src, len, 1, stdout)!=1) {
    fprintf(stderr,"failed to write to stdout: %s\n", strerror(errno));
    return 0;
  }
  return 1;
}

void drop_privs(void) {
  // do not gain new privs
  prctl(PR_SET_NO_NEW_PRIVS, 1);
  // disable ptrace
  prctl(PR_SET_DUMPABLE, 0);

  if(geteuid()==0) {
    // process is running as root, drop privileges
    if(setgid(GROUPID)!=0) {
      fprintf(stderr, "setgid: Unable to drop group privileges: %s", strerror(errno));
      exit(1);
    }
    if(setuid(USERID)!=0) {
      fprintf(stderr, "setuid: Unable to drop user privileges: %s", strerror(errno));
      exit(1);
    }
  }
  if(setuid(0)!=-1 && geteuid()==0) {
    fprintf(stderr, "ERROR: Managed to regain root privileges.");
    exit(1);
  }
}
