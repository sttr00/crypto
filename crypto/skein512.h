#ifndef __skein512_h__
#define __skein512_h__

#include <stdint.h>
#include <stddef.h>

typedef struct
{
 uint64_t state[9];
 uint64_t t[3];
 unsigned ptr;
 unsigned offset;
 union /* double buffer to handle Final Bit */
 {
  uint64_t w[16];
  uint8_t  b[128];
 } buf;
 int buf_filled;
} SKEIN512_CTX;

#ifdef __cplusplus
extern "C"
{
#endif

void skein512_224_init(void *ctx);
void skein512_update(void *ctx, const void *data, size_t size);
const void *skein512_224_final(void *ctx);
#define skein512_224_update skein512_update

void skein512_256_init(void *ctx);
const void *skein512_256_final(void *ctx);
#define skein512_256_update skein512_update

void skein512_384_init(void *ctx);
const void *skein512_384_final(void *ctx);
#define skein512_384_update skein512_update

void skein512_512_init(void *ctx);
const void *skein512_512_final(void *ctx);
#define skein512_512_update skein512_update

void *skein512mac_alloc();
void skein512mac_set_key(void *ctx, const void *key, size_t key_size, unsigned out_bits);
void skein512mac_update(void *ctx, const void *data, size_t size);
const void *skein512mac_final(void *ctx);
void skein512mac_reset(void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* __skein512_h__ */
