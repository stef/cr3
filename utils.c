#include <sys/types.h>
#include <seccomp.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/prctl.h> /* prctl */
#include <sys/stat.h>
#include <fcntl.h>

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

void lock_seccomp(void) {
#ifdef __GLIBC__
  //int i;
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_KILL); // default action: kill

  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mlock), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(poll), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 1, SCMP_A0(SCMP_CMP_EQ, 3));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 1, SCMP_A0(SCMP_CMP_EQ, 3));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 1, SCMP_A0(SCMP_CMP_EQ, 0));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_EQ, 1));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_EQ, 2));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1, SCMP_A0(SCMP_CMP_EQ, 1));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(time), 1, SCMP_A0(SCMP_CMP_EQ, NULL));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1, SCMP_A1(SCMP_CMP_EQ, O_RDONLY|O_NOCTTY|O_NONBLOCK));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
#ifdef __x86_64__
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 1, SCMP_A0(SCMP_CMP_EQ, 1));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 1, SCMP_A0(SCMP_CMP_EQ, NULL));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 1, SCMP_A0(SCMP_CMP_EQ, 3));
#else // assume 32bit
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat64), 1, SCMP_A0(SCMP_CMP_EQ, 1));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap2), 1, SCMP_A0(SCMP_CMP_EQ, NULL));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid32), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat64), 1, SCMP_A0(SCMP_CMP_EQ, 3));
#endif // __x86_64__

  // enable seccomp rules
  seccomp_load(ctx);
#endif // __GLIBC__
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
