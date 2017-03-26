#ifndef __sha3_h__
#define __sha3_h__

#include <stdint.h>
#include <stddef.h>

/* r = 448 */
typedef struct
{
 uint64_t state[25];
 unsigned ptr;
 union
 {
  uint64_t w[18];
  uint8_t  b[144];
 } buf;
} SHA3_224_CTX;

/* r = 512 */
typedef struct
{
 uint64_t state[25];
 unsigned ptr;
 union
 {
  uint64_t w[17];
  uint8_t  b[136];
 } buf;
} SHA3_256_CTX;

/* r = 768 */
typedef struct
{
 uint64_t state[25];
 unsigned ptr;
 union
 {
  uint64_t w[13];
  uint8_t  b[104];
 } buf;
} SHA3_384_CTX;

/* r = 1024 */
typedef struct
{
 uint64_t state[25];
 unsigned ptr;
 union
 {
  uint64_t w[9];
  uint8_t  b[72];
 } buf;
} SHA3_512_CTX;

#ifdef __cplusplus
extern "C"
{
#endif

void sha3_512_init(void *ctx);
void sha3_512_update(void *ctx, const void *data, size_t size);
const void *sha3_512_final(void *ctx);

#define sha3_384_init sha3_512_init
void sha3_384_update(void *ctx, const void *data, size_t size);
const void *sha3_384_final(void *ctx);

#define sha3_256_init sha3_512_init
void sha3_256_update(void *ctx, const void *data, size_t size);
const void *sha3_256_final(void *ctx);

#define sha3_224_init sha3_512_init
void sha3_224_update(void *ctx, const void *data, size_t size);
const void *sha3_224_final(void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* __sha3_h__ */
