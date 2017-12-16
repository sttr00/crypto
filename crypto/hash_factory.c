#include "hash_factory.h"
#include "oid_const.h"
#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "sha512.h"
#ifdef CRYPTO_ENABLE_HASH_SHA3
#include "sha3.h"
#endif
#ifdef CRYPTO_ENABLE_HASH_SKEIN256
#include "skein256.h"
#endif
#ifdef CRYPTO_ENABLE_HASH_SKEIN512
#include "skein512.h"
#endif
#ifdef CRYPTO_ENABLE_HASH_STREEBOG
#include "streebog.h"
#endif

#define DECLARE_HASH_DEF(name, name_prefix, hash_size, block_size) \
 static const hash_def hash_def_ ## name_prefix = \
 {                        \
  ID_HASH_ ## name,       \
  hash_size, block_size,  \
  sizeof(name ## _CTX),   \
  name_prefix ## _init,   \
  name_prefix ## _update, \
  name_prefix ## _final   \
 };

DECLARE_HASH_DEF(MD5,          md5,          16, 64)
DECLARE_HASH_DEF(SHA1,         sha1,         20, 64)
DECLARE_HASH_DEF(SHA256,       sha256,       32, 64)
DECLARE_HASH_DEF(SHA224,       sha224,       28, 64)
DECLARE_HASH_DEF(SHA512,       sha512,       64, 128)
DECLARE_HASH_DEF(SHA384,       sha384,       48, 128)

#ifdef CRYPTO_ENABLE_HASH_SHA3
DECLARE_HASH_DEF(SHA3_512,     sha3_512,     64, 72)
DECLARE_HASH_DEF(SHA3_384,     sha3_384,     48, 104)
DECLARE_HASH_DEF(SHA3_256,     sha3_256,     32, 136)
DECLARE_HASH_DEF(SHA3_224,     sha3_224,     28, 144)
#endif

#ifdef CRYPTO_ENABLE_HASH_SKEIN256
#define SKEIN256_128_CTX SKEIN256_CTX
#define SKEIN256_160_CTX SKEIN256_CTX
#define SKEIN256_224_CTX SKEIN256_CTX
#define SKEIN256_256_CTX SKEIN256_CTX
DECLARE_HASH_DEF(SKEIN256_128, skein256_128, 16, 32)
DECLARE_HASH_DEF(SKEIN256_160, skein256_160, 20, 32)
DECLARE_HASH_DEF(SKEIN256_224, skein256_224, 28, 32)
DECLARE_HASH_DEF(SKEIN256_256, skein256_256, 32, 32)
#endif

#ifdef CRYPTO_ENABLE_HASH_SKEIN512
#define SKEIN512_224_CTX SKEIN512_CTX
#define SKEIN512_256_CTX SKEIN512_CTX
#define SKEIN512_384_CTX SKEIN512_CTX
#define SKEIN512_512_CTX SKEIN512_CTX
DECLARE_HASH_DEF(SKEIN512_224, skein512_224, 28, 64)
DECLARE_HASH_DEF(SKEIN512_256, skein512_256, 32, 64)
DECLARE_HASH_DEF(SKEIN512_384, skein512_384, 48, 64)
DECLARE_HASH_DEF(SKEIN512_512, skein512_512, 64, 64)
#endif

#ifdef CRYPTO_ENABLE_HASH_STREEBOG
typedef STREEBOG_CTX STREEBOG512_CTX;
typedef STREEBOG_CTX STREEBOG256_CTX;
DECLARE_HASH_DEF(STREEBOG512,  streebog512,  64, 64)
DECLARE_HASH_DEF(STREEBOG256,  streebog256,  32, 64)
#endif

#define HASH_CASE(name, name_prefix) \
 case ID_HASH_ ## name: \
  return &hash_def_ ## name_prefix;

const hash_def *hash_factory(int id)
{
 switch (id)
 {
  HASH_CASE(MD5,          md5)
  HASH_CASE(SHA1,         sha1)
  HASH_CASE(SHA256,       sha256)
  HASH_CASE(SHA224,       sha224)
  HASH_CASE(SHA512,       sha512)
  HASH_CASE(SHA384,       sha384)

  #ifdef CRYPTO_ENABLE_HASH_SHA3
  HASH_CASE(SHA3_512,     sha3_512)
  HASH_CASE(SHA3_384,     sha3_384)
  HASH_CASE(SHA3_256,     sha3_256)
  HASH_CASE(SHA3_224,     sha3_224)
  #endif
  
  #ifdef CRYPTO_ENABLE_HASH_SKEIN256
  HASH_CASE(SKEIN256_128, skein256_128)
  HASH_CASE(SKEIN256_160, skein256_160)
  HASH_CASE(SKEIN256_224, skein256_224)
  HASH_CASE(SKEIN256_256, skein256_256)
  #endif

  #ifdef CRYPTO_ENABLE_HASH_SKEIN512
  HASH_CASE(SKEIN512_224, skein512_224)
  HASH_CASE(SKEIN512_256, skein512_256)
  HASH_CASE(SKEIN512_384, skein512_384)
  HASH_CASE(SKEIN512_512, skein512_512)
  #endif

  #ifdef CRYPTO_ENABLE_HASH_STREEBOG
  HASH_CASE(STREEBOG512,  streebog512)
  HASH_CASE(STREEBOG256,  streebog256)
  #endif
 }
 return NULL;
}
