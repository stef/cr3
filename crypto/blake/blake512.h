#ifndef BLAKE512_H
#define BLAKE512_H

#define BLAKE512_BYTES 64

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

typedef struct  { 
  u64 h[8], s[4], t[2];
  int buflen, nullt;
  u8 buf[128];
} blake512_state;

void blake512_init( blake512_state * S );
void blake512_update( blake512_state * S, const u8 * data, u64 datalen );
void blake512_final( blake512_state * S, u8 * digest );
int blake512( unsigned char *out, const unsigned char *in, unsigned long long inlen );
#endif // BLAKE512_H
