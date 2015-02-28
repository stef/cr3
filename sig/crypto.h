#ifndef CRYPTO_H
#define CRYPTO_H
#include "utils.h"
#include <stdio.h>

FILE* keyopen(char* prefix, char* postfix);
int sig_keyfds(char* name, FILE** key, FILE** pub);
int sig_genkey(FILE* keyfp, FILE* pubfp);
int sig_verify(void* pk);
int sig_sign(void* sk);

#endif // CRYPTO_H
