#include "sha1.h"

#define HASH_CONTEXT        SHA1_CTX
#define HASH_FUNC_COMPRESS  sha1_compress
#define HASH_FUNC_UPDATE    sha1_update
#define HASH_FUNC_FINAL     sha1_final
#define HASH_DIGEST_SIZE    20
#define HASH_BLOCK_SIZE     64
#define HASH_WORD_SIZE      4
#define HASH_PAD_START      0x80
#define HASH_HAS_TOTAL_SIZE
#define HASH_BIG_ENDIAN

void sha1_init(void *pctx)
{
 SHA1_CTX *ctx = (SHA1_CTX *) pctx;
 ctx->hashed_size = 0;
 ctx->ptr = 0;
 ctx->state[0] = 0x67452301ul;
 ctx->state[1] = 0xEFCDAB89ul;
 ctx->state[2] = 0x98BADCFEul;
 ctx->state[3] = 0x10325476ul;
 ctx->state[4] = 0xC3D2E1F0ul;
}

static void sha1_compress(void *pctx, const void *data);

#include "hash_common.inc"

#define rol(w, r) ((w)<<(r) | (w)>>(HASH_WORD_BITS-(r)))

static void sha1_compress(void *pctx, const void *data)
{
 uint32_t *state = ((SHA1_CTX *) pctx)->state;
 const uint32_t *wdata = (const uint32_t *) data;
 uint32_t w[80];
 register uint32_t a, b, c, d, e;
 int i;

 for (i=0; i<16; i++) w[i] = HASH_VALUE(wdata[i]);

 for (i=16; i<80; i++)
 {
  w[i] = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16];
  w[i] = rol(w[i], 1);
 }

 a = state[0];
 b = state[1];
 c = state[2];
 d = state[3];
 e = state[4];

 #define R(a, b, c, d, e, i) \
 { \
  e += rol(a, 5) + f(b, c, d) + k + w[i]; \
  b = rol(b, 30); \
 }

 #define f(x, y, z) ((z) ^ ((x) & ((y) ^ (z)))) /* selection */
 #define k 0x5A827999ul
 R(a, b, c, d, e, 0)
 R(e, a, b, c, d, 1)
 R(d, e, a, b, c, 2)
 R(c, d, e, a, b, 3)
 R(b, c, d, e, a, 4)
 R(a, b, c, d, e, 5)
 R(e, a, b, c, d, 6)
 R(d, e, a, b, c, 7)
 R(c, d, e, a, b, 8)
 R(b, c, d, e, a, 9)
 R(a, b, c, d, e, 10)
 R(e, a, b, c, d, 11)
 R(d, e, a, b, c, 12)
 R(c, d, e, a, b, 13)
 R(b, c, d, e, a, 14)
 R(a, b, c, d, e, 15)
 R(e, a, b, c, d, 16)
 R(d, e, a, b, c, 17)
 R(c, d, e, a, b, 18)
 R(b, c, d, e, a, 19)
 #undef f
 #undef k
 
 #define f(x, y, z) ((x) ^ (y) ^ (z)) /* parity */
 #define k 0x6ED9EBA1ul
 R(a, b, c, d, e, 20)
 R(e, a, b, c, d, 21)
 R(d, e, a, b, c, 22)
 R(c, d, e, a, b, 23)
 R(b, c, d, e, a, 24)
 R(a, b, c, d, e, 25)
 R(e, a, b, c, d, 26)
 R(d, e, a, b, c, 27)
 R(c, d, e, a, b, 28)
 R(b, c, d, e, a, 29)
 R(a, b, c, d, e, 30)
 R(e, a, b, c, d, 31)
 R(d, e, a, b, c, 32)
 R(c, d, e, a, b, 33)
 R(b, c, d, e, a, 34)
 R(a, b, c, d, e, 35)
 R(e, a, b, c, d, 36)
 R(d, e, a, b, c, 37)
 R(c, d, e, a, b, 38)
 R(b, c, d, e, a, 39)
 #undef f
 #undef k
 
 #define f(x, y, z) (((x) & (y)) | ((z) & ((x) | (y)))) /* majority */
 #define k 0x8F1BBCDCul
 R(a, b, c, d, e, 40)
 R(e, a, b, c, d, 41)
 R(d, e, a, b, c, 42)
 R(c, d, e, a, b, 43)
 R(b, c, d, e, a, 44)
 R(a, b, c, d, e, 45)
 R(e, a, b, c, d, 46)
 R(d, e, a, b, c, 47)
 R(c, d, e, a, b, 48)
 R(b, c, d, e, a, 49)
 R(a, b, c, d, e, 50)
 R(e, a, b, c, d, 51)
 R(d, e, a, b, c, 52)
 R(c, d, e, a, b, 53)
 R(b, c, d, e, a, 54)
 R(a, b, c, d, e, 55)
 R(e, a, b, c, d, 56)
 R(d, e, a, b, c, 57)
 R(c, d, e, a, b, 58)
 R(b, c, d, e, a, 59)
 #undef f
 #undef k

 #define f(x, y, z) ((x) ^ (y) ^ (z)) /* parity */
 #define k 0xCA62C1D6ul
 R(a, b, c, d, e, 60)
 R(e, a, b, c, d, 61)
 R(d, e, a, b, c, 62)
 R(c, d, e, a, b, 63)
 R(b, c, d, e, a, 64)
 R(a, b, c, d, e, 65)
 R(e, a, b, c, d, 66)
 R(d, e, a, b, c, 67)
 R(c, d, e, a, b, 68)
 R(b, c, d, e, a, 69)
 R(a, b, c, d, e, 70)
 R(e, a, b, c, d, 71)
 R(d, e, a, b, c, 72)
 R(c, d, e, a, b, 73)
 R(b, c, d, e, a, 74)
 R(a, b, c, d, e, 75)
 R(e, a, b, c, d, 76)
 R(d, e, a, b, c, 77)
 R(c, d, e, a, b, 78)
 R(b, c, d, e, a, 79)
 #undef f
 #undef k
 
 #undef R
 state[0] += a;
 state[1] += b;
 state[2] += c;
 state[3] += d;
 state[4] += e;
}
