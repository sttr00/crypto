#ifndef __sha256_h__
#define __sha256_h__

#include <stdint.h>
#include <stddef.h>

typedef struct
{
 uint32_t state[8];
 union
 {
  uint32_t w[16];
  uint8_t  b[64];
 } buf;
 uint64_t hashed_size;
 unsigned ptr;
} SHA256_CTX;

typedef SHA256_CTX SHA224_CTX;

#ifdef __cplusplus
extern "C"
{
#endif

void sha256_init(void *ctx);
void sha256_update(void *ctx, const void *data, size_t size);
const void *sha256_final(void *ctx);

void sha224_init(void *ctx);
#define sha224_update sha256_update
const void *sha224_final(void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* __sha256_h__ */
