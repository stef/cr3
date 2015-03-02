#include <seccomp.h>
#include <stdlib.h>
#include <fcntl.h>

void lock_seccomp(int fd) {
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_KILL); // default action: kill

  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mlock), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(poll), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 1, SCMP_A0(SCMP_CMP_EQ, fd));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 1, SCMP_A0(SCMP_CMP_EQ, fd));
#ifdef __GLIBC__
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 1, SCMP_A0(SCMP_CMP_EQ, 0));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_EQ, 1));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_EQ, 2));
#else // assume musl-libc
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readv), 1, SCMP_A0(SCMP_CMP_EQ, 0));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 1, SCMP_A0(SCMP_CMP_EQ, 1));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 1, SCMP_A0(SCMP_CMP_EQ, 2));
#endif // __GLIBC__

  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1, SCMP_A0(SCMP_CMP_EQ, 1));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(time), 1, SCMP_A0(SCMP_CMP_EQ, NULL));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1, SCMP_A1(SCMP_CMP_EQ, O_RDONLY|O_NOCTTY|O_NONBLOCK));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
#ifdef __x86_64__
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 1, SCMP_A0(SCMP_CMP_EQ, 0));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 1, SCMP_A0(SCMP_CMP_EQ, 1));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 1, SCMP_A0(SCMP_CMP_EQ, fd));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 1, SCMP_A0(SCMP_CMP_EQ, NULL));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid), 0);
#else // assume 32bit
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat64), 1, SCMP_A0(SCMP_CMP_EQ, 0));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat64), 1, SCMP_A0(SCMP_CMP_EQ, 1));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat64), 1, SCMP_A0(SCMP_CMP_EQ, fd));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap2), 1, SCMP_A0(SCMP_CMP_EQ, NULL));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid32), 0);
#endif // __x86_64__

  // enable seccomp rules
  seccomp_load(ctx);
}
