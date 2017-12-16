#ifndef __skein256_h__
#define __skein256_h__

#include <stdint.h>
#include <stddef.h>

typedef struct
{
 uint64_t state[5];
 uint64_t t[3];
 unsigned ptr;
 unsigned offset;
 union /* double buffer to handle Final Bit */
 {
  uint64_t w[8];
  uint8_t  b[64];
 } buf;
 int buf_filled;
} SKEIN256_CTX;

#ifdef __cplusplus
extern "C"
{
#endif

void skein256_128_init(void *ctx);
void skein256_update(void *ctx, const void *data, size_t size);
const void *skein256_128_final(void *ctx);
#define skein256_128_update skein256_update

void skein256_160_init(void *ctx);
const void *skein256_160_final(void *ctx);
#define skein256_160_update skein256_update

void skein256_224_init(void *ctx);
const void *skein256_224_final(void *ctx);
#define skein256_224_update skein256_update

void skein256_256_init(void *ctx);
const void *skein256_256_final(void *ctx);
#define skein256_256_update skein256_update

void *skein256mac_alloc();
void skein256mac_set_key(void *ctx, const void *key, size_t key_size, unsigned out_bits);
void skein256mac_update(void *ctx, const void *data, size_t size);
const void *skein256mac_final(void *ctx);
void skein256mac_reset(void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* __skein256_h__ */
