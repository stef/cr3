#ifndef CRYPTO_H
#define CRYPTO_H
#include "utils.h"

int cod_encrypt(void* pem);
int cod_decrypt(void* pem, u8* password);
#endif // CRYPTO_H
