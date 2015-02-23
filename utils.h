#ifndef UTILS_H
#define UTILS_H

void * clear(void *v,size_t n);
int cmp(const void * a, const void *b, const size_t size);
void lock_seccomp(void);
void drop_privs(void);

#endif // UTILS_H
