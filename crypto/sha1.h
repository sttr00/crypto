#ifndef __sha1_h__
#define __sha1_h__

#include <stdint.h>
#include <stddef.h>

typedef struct
{
 uint32_t state[5];
 union
 {
  uint32_t w[16];
  uint8_t  b[64];
 } buf;
 uint64_t hashed_size;
 unsigned ptr;
} SHA1_CTX;

#ifdef __cplusplus
extern "C"
{
#endif

void sha1_init(void *ctx);
void sha1_update(void *ctx, const void *data, size_t size);
const void *sha1_final(void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* __sha1_h__ */
