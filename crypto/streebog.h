#ifndef __streebog_h__
#define __streebog_h__

#include <stdint.h>
#include <stddef.h>

typedef struct
{
 union
 {
  uint64_t w[8];
  uint8_t  b[64];
 } state;
 union
 {
  uint64_t w[8];
  uint8_t  b[64];
 } sigma;
 union
 {
  uint64_t w[8];
  uint8_t  b[64];
 } buf;
 uint64_t hashed_size;
 unsigned ptr;
} STREEBOG_CTX;

#ifdef __cplusplus
extern "C"
{
#endif

void streebog512_init(void *ctx);
void streebog512_update(void *ctx, const void *data, size_t size);
const void *streebog512_final(void *ctx);

void streebog256_init(void *ctx);
#define streebog256_update streebog512_update
const void *streebog256_final(void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* __streebog_h__ */
