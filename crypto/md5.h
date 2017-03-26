#ifndef __md5_h__
#define __md5_h__

#include <stdint.h>
#include <stddef.h>

typedef struct
{
 uint32_t state[4];
 union
 {
  uint32_t w[16];
  uint8_t  b[64];
 } buf;
 uint64_t hashed_size;
 unsigned ptr;
} MD5_CTX;

#ifdef __cplusplus
extern "C"
{
#endif

void md5_init(void *ctx);
void md5_update(void *ctx, const void *data, size_t size);
const void *md5_final(void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* __md5_h__ */
