#include "sha3.h"

#define HASH_WORD_SIZE     8
#define HASH_DIGEST_SIZE   64
#define HASH_BLOCK_SIZE    72
#define HASH_CONTEXT       SHA3_512_CTX
#define HASH_FUNC_COMPRESS sha3_512_compress
#define HASH_FUNC_UPDATE   sha3_512_update
#define HASH_FUNC_FINAL    sha3_512_final
#define HASH_PAD_START     6
#define HASH_PAD_END       0x80

static void sha3_512_compress(void *pctx, const void *data);

#include "hash_common.inc"

typedef struct
{
 uint64_t state[25];
 unsigned ptr;
} SHA3_COMMON_CTX;

void sha3_512_init(void *pctx)
{
 SHA3_COMMON_CTX *ctx = (SHA3_COMMON_CTX *) pctx;
 int i;
 for (i=0; i<25; i++) ctx->state[i] = 0;
 ctx->ptr = 0;
}

static const uint64_t rc[24] =
{
 0x0000000000000001ull, 0x0000000000008082ull, 0x800000000000808Aull, 0x8000000080008000ull,
 0x000000000000808Bull, 0x0000000080000001ull, 0x8000000080008081ull, 0x8000000000008009ull,
 0x000000000000008Aull, 0x0000000000000088ull, 0x0000000080008009ull, 0x000000008000000Aull,
 0x000000008000808Bull, 0x800000000000008Bull, 0x8000000000008089ull, 0x8000000000008003ull,
 0x8000000000008002ull, 0x8000000000000080ull, 0x000000000000800Aull, 0x800000008000000Aull,
 0x8000000080008081ull, 0x8000000000008080ull, 0x0000000080000001ull, 0x8000000080008008ull
};

#define rol(w, r) ((w)<<(r) | (w)>>(HASH_WORD_BITS-(r)))

static void sha3_permutation(uint64_t *s)
{
 uint64_t w[25], t;
 int r;
 for (r = 0; r < 24; r++)
 {
  #define THETA_CALC(i) w[i] = s[i] ^ s[i+5] ^ s[i+10] ^ s[i+15] ^ s[i+20];
  THETA_CALC(0)
  THETA_CALC(1)
  THETA_CALC(2)
  THETA_CALC(3)
  THETA_CALC(4)
  #define THETA_UPDATE(i) s[i] ^= t; s[i+5] ^= t; s[i+10] ^= t; s[i+15] ^= t; s[i+20] ^= t;
  t = w[4] ^ rol(w[1], 1); THETA_UPDATE(0)
  t = w[0] ^ rol(w[2], 1); THETA_UPDATE(1)
  t = w[1] ^ rol(w[3], 1); THETA_UPDATE(2)
  t = w[2] ^ rol(w[4], 1); THETA_UPDATE(3)
  t = w[3] ^ rol(w[0], 1); THETA_UPDATE(4)
  #define PI(src, dst, rc) w[dst] = rol(s[src], rc);
  w[0] = s[0];   PI( 1, 10,  1) PI( 2, 20, 62) PI( 3,  5, 28) PI( 4, 15, 27) 
  PI( 5, 16, 36) PI( 6,  1, 44) PI( 7, 11,  6) PI( 8, 21, 55) PI( 9,  6, 20) 
  PI(10,  7,  3) PI(11, 17, 10) PI(12,  2, 43) PI(13, 12, 25) PI(14, 22, 39) 
  PI(15, 23, 41) PI(16,  8, 45) PI(17, 18, 15) PI(18,  3, 21) PI(19, 13,  8) 
  PI(20, 14, 18) PI(21, 24,  2) PI(22,  9, 61) PI(23, 19, 56) PI(24,  4, 14) 
  #define CHI_CELL(i, j) s[5*i + j] = w[5*i + j] ^ (~w[5*i + (j + 1) % 5] & w[5*i + (j + 2) % 5]);
  #define CHI_ROW(i) CHI_CELL(i, 0) CHI_CELL(i, 1) CHI_CELL(i, 2) CHI_CELL(i, 3) CHI_CELL(i, 4)
  CHI_ROW(0)
  CHI_ROW(1)
  CHI_ROW(2)
  CHI_ROW(3)
  CHI_ROW(4)
  s[0] ^= rc[r];
 }
}

static void sha3_512_compress(void *pctx, const void *data)
{
 uint64_t *s = ((SHA3_512_CTX *) pctx)->state;
 const uint64_t *wdata = (const uint64_t *) data;
 int i;
 for (i=0; i<HASH_BLOCK_SIZE/HASH_WORD_SIZE; i++) s[i] ^= HASH_VALUE(wdata[i]);
 sha3_permutation(s);
}

#undef HASH_DIGEST_SIZE
#undef HASH_BLOCK_SIZE
#undef HASH_CONTEXT
#undef HASH_FUNC_COMPRESS
#undef HASH_FUNC_UPDATE
#undef HASH_FUNC_FINAL

#define HASH_DIGEST_SIZE   48
#define HASH_BLOCK_SIZE    104
#define HASH_CONTEXT       SHA3_384_CTX
#define HASH_FUNC_COMPRESS sha3_384_compress
#define HASH_FUNC_UPDATE   sha3_384_update
#define HASH_FUNC_FINAL    sha3_384_final

static void sha3_384_compress(void *pctx, const void *data)
{
 uint64_t *s = ((SHA3_384_CTX *) pctx)->state;
 const uint64_t *wdata = (const uint64_t *) data;
 int i;
 for (i=0; i<HASH_BLOCK_SIZE/HASH_WORD_SIZE; i++) s[i] ^= HASH_VALUE(wdata[i]);
 sha3_permutation(s);
}

#include "hash_common.inc"

#undef HASH_DIGEST_SIZE
#undef HASH_BLOCK_SIZE
#undef HASH_CONTEXT
#undef HASH_FUNC_COMPRESS
#undef HASH_FUNC_UPDATE
#undef HASH_FUNC_FINAL

#define HASH_DIGEST_SIZE   32
#define HASH_BLOCK_SIZE    136
#define HASH_CONTEXT       SHA3_256_CTX
#define HASH_FUNC_COMPRESS sha3_256_compress
#define HASH_FUNC_UPDATE   sha3_256_update
#define HASH_FUNC_FINAL    sha3_256_final

static void sha3_256_compress(void *pctx, const void *data)
{
 uint64_t *s = ((SHA3_256_CTX *) pctx)->state;
 const uint64_t *wdata = (const uint64_t *) data;
 int i;
 for (i=0; i<HASH_BLOCK_SIZE/HASH_WORD_SIZE; i++) s[i] ^= HASH_VALUE(wdata[i]);
 sha3_permutation(s);
}

#include "hash_common.inc"

#undef HASH_DIGEST_SIZE
#undef HASH_BLOCK_SIZE
#undef HASH_CONTEXT
#undef HASH_FUNC_COMPRESS
#undef HASH_FUNC_UPDATE
#undef HASH_FUNC_FINAL

#define HASH_DIGEST_SIZE   28
#define HASH_BLOCK_SIZE    144
#define HASH_CONTEXT       SHA3_224_CTX
#define HASH_FUNC_COMPRESS sha3_224_compress
#define HASH_FUNC_UPDATE   sha3_224_update
#define HASH_FUNC_FINAL    sha3_224_final

static void sha3_224_compress(void *pctx, const void *data)
{
 uint64_t *s = ((SHA3_224_CTX *) pctx)->state;
 const uint64_t *wdata = (const uint64_t *) data;
 int i;
 for (i=0; i<HASH_BLOCK_SIZE/HASH_WORD_SIZE; i++) s[i] ^= HASH_VALUE(wdata[i]);
 sha3_permutation(s);
}

#include "hash_common.inc"
