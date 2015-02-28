#ifndef UTILS_H
#define UTILS_H

typedef unsigned char u8;

void * zerobytes(void *v,size_t n);
int cmp(const void * a, const void *b, const size_t size);
void drop_privs(void);
int _write(const u8* src, const size_t len);

#endif // UTILS_H
