#ifndef __sha512_h__
#define __sha512_h__

#include <stdint.h>
#include <stddef.h>

typedef struct
{
 uint64_t state[8];
 union
 {
  uint64_t w[16];
  uint8_t  b[128];
 } buf;
 uint64_t hashed_size;
 unsigned ptr;
} SHA512_CTX;

typedef SHA512_CTX SHA384_CTX;

#ifdef __cplusplus
extern "C"
{
#endif

void sha512_init(void *ctx);
void sha512_update(void *ctx, const void *data, size_t size);
const void *sha512_final(void *ctx);

void sha384_init(void *ctx);
#define sha384_update sha512_update
const void *sha384_final(void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* __sha512_h__ */
