#ifndef CRYPTO_H
#define CRYPTO_H
typedef unsigned char u8;

int cod_encrypt(void* pem);
int cod_decrypt(void* pem, u8* password);
#endif // CRYPTO_H
