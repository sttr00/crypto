#include "hash_factory.h"
#include "oid_const.h"
#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "sha512.h"
#ifdef CRYPTO_ENABLE_HASH_SHA3
#include "sha3.h"
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

DECLARE_HASH_DEF(MD5,         md5,         16, 64)
DECLARE_HASH_DEF(SHA1,        sha1,        20, 64)
DECLARE_HASH_DEF(SHA256,      sha256,      32, 64)
DECLARE_HASH_DEF(SHA224,      sha224,      28, 64)
DECLARE_HASH_DEF(SHA512,      sha512,      64, 128)
DECLARE_HASH_DEF(SHA384,      sha384,      48, 128)

#ifdef CRYPTO_ENABLE_HASH_SHA3
DECLARE_HASH_DEF(SHA3_512,    sha3_512,    64, 72)
DECLARE_HASH_DEF(SHA3_384,    sha3_384,    48, 104)
DECLARE_HASH_DEF(SHA3_256,    sha3_256,    32, 136)
DECLARE_HASH_DEF(SHA3_224,    sha3_224,    28, 144)
#endif

#ifdef CRYPTO_ENABLE_HASH_STREEBOG
typedef STREEBOG_CTX STREEBOG512_CTX;
typedef STREEBOG_CTX STREEBOG256_CTX;
DECLARE_HASH_DEF(STREEBOG512, streebog512, 64, 64)
DECLARE_HASH_DEF(STREEBOG256, streebog256, 32, 64)
#endif

#define HASH_CASE(name, name_prefix) \
 case ID_HASH_ ## name: \
  return &hash_def_ ## name_prefix;

const hash_def *hash_factory(int id)
{
 switch (id)
 {
  HASH_CASE(MD5,         md5)
  HASH_CASE(SHA1,        sha1)
  HASH_CASE(SHA256,      sha256)
  HASH_CASE(SHA224,      sha224)
  HASH_CASE(SHA512,      sha512)
  HASH_CASE(SHA384,      sha384)

  #ifdef CRYPTO_ENABLE_HASH_SHA3
  HASH_CASE(SHA3_512,    sha3_512)
  HASH_CASE(SHA3_384,    sha3_384)
  HASH_CASE(SHA3_256,    sha3_256)
  HASH_CASE(SHA3_224,    sha3_224)
  #endif

  #ifdef CRYPTO_ENABLE_HASH_STREEBOG
  HASH_CASE(STREEBOG512, streebog512)
  HASH_CASE(STREEBOG256, streebog256)
  #endif
 }
 return NULL;
}
