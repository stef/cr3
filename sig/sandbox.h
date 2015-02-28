#ifndef SANDBOX_H
#define SANDBOX_H

void lock_seccomp(int fp);
void seccomp_genkey(FILE* sk, FILE* pk);

#endif // SANDBOX_H
