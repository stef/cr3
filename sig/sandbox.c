#include <seccomp.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

void lock_seccomp(int fd) {
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_KILL); // default action: kill

  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mlock), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 1, SCMP_A0(SCMP_CMP_EQ, fd));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 1, SCMP_A0(SCMP_CMP_EQ, fd));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1, SCMP_A0(SCMP_CMP_EQ, 1));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1, SCMP_A0(SCMP_CMP_EQ, 2));
#ifdef __GLIBC__
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 1, SCMP_A0(SCMP_CMP_EQ, 0));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_EQ, 1));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_EQ, 2));
#else // assume musl-libc
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readv), 1, SCMP_A0(SCMP_CMP_EQ, 0));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 1, SCMP_A0(SCMP_CMP_EQ, 1));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 1, SCMP_A0(SCMP_CMP_EQ, 2));
#endif // __GLIBC__

  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

#ifdef __x86_64__
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 1, SCMP_A0(SCMP_CMP_EQ, 0));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 1, SCMP_A0(SCMP_CMP_EQ, 1));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 1, SCMP_A0(SCMP_CMP_EQ, fd));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 1, SCMP_A0(SCMP_CMP_EQ, NULL));
#else // assume 32bit
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat64), 1, SCMP_A0(SCMP_CMP_EQ, 0));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat64), 1, SCMP_A0(SCMP_CMP_EQ, 1));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat64), 1, SCMP_A0(SCMP_CMP_EQ, fd));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap2), 1, SCMP_A0(SCMP_CMP_EQ, NULL));
#endif // __x86_64__

  // enable seccomp rules
  seccomp_load(ctx);
}

void seccomp_genkey(FILE* sk, FILE* pk) {
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_KILL); // default action: kill

  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mlock), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
  // for randbytes
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1, SCMP_A1(SCMP_CMP_EQ, O_RDONLY));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 1, SCMP_A0(SCMP_CMP_EQ, fileno(sk)+1));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 1, SCMP_A0(SCMP_CMP_EQ, fileno(sk)+1));

  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 1, SCMP_A0(SCMP_CMP_EQ, fileno(pk)));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 1, SCMP_A0(SCMP_CMP_EQ, fileno(sk)));
#ifdef __GLIBC__
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_EQ, fileno(pk)));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_EQ, fileno(sk)));
#else // assume musl-libc
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 1, SCMP_A0(SCMP_CMP_EQ, fileno(pk)));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 1, SCMP_A0(SCMP_CMP_EQ, fileno(sk)));
#endif // __GLIBC__

  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchmod), 2,
                   SCMP_A0(SCMP_CMP_EQ, fileno(sk)),
                   SCMP_A1(SCMP_CMP_EQ, 0600));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
#ifdef __x86_64__
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 1, SCMP_A0(SCMP_CMP_EQ, fileno(pk)));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 1, SCMP_A0(SCMP_CMP_EQ, fileno(sk)));
  /* mmap2(NULL, *, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) */
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 5,
                   SCMP_A0(SCMP_CMP_EQ, NULL),
                   SCMP_A2(SCMP_CMP_EQ, PROT_READ|PROT_WRITE),
                   SCMP_A3(SCMP_CMP_EQ, MAP_PRIVATE|MAP_ANONYMOUS),
                   SCMP_A4(SCMP_CMP_EQ, -1),
                   SCMP_A5(SCMP_CMP_EQ, 0)
                   );
#else // assume 32bit
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat64), 1, SCMP_A0(SCMP_CMP_EQ, fileno(sk)));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat64), 1, SCMP_A0(SCMP_CMP_EQ, fileno(pk)));
  /* mmap2(NULL, *, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) */
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap2), 5,
                   SCMP_A0(SCMP_CMP_EQ, NULL),
                   SCMP_A2(SCMP_CMP_EQ, PROT_READ|PROT_WRITE),
                   SCMP_A3(SCMP_CMP_EQ, MAP_PRIVATE|MAP_ANONYMOUS),
                   SCMP_A4(SCMP_CMP_EQ, -1),
                   SCMP_A5(SCMP_CMP_EQ, 0)
                   );
#endif // __x86_64__

  // enable seccomp rules
  seccomp_load(ctx);
}
