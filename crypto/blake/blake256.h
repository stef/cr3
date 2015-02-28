#ifndef BLAKE256_H
#define BLAKE256_H

typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned char u8;

typedef struct  { 
  u32 h[8], s[4], t[2];
  int buflen, nullt;
  u8  buf[64];
} blake256_state;

void blake256_init( blake256_state *S );
void blake256_update( blake256_state *S, const u8 *data, u64 datalen );
void blake256_final( blake256_state *S, u8 *digest );
int blake256( unsigned char *out, const unsigned char *in, unsigned long long inlen );
#endif // BLAKE256_H
