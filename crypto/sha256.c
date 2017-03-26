#include "sha256.h"

#define HASH_CONTEXT        SHA256_CTX
#define HASH_FUNC_COMPRESS  sha256_compress
#define HASH_FUNC_UPDATE    sha256_update
#define HASH_FUNC_FINAL     sha256_final
#define HASH_DIGEST_SIZE    32
#define HASH_BLOCK_SIZE     64
#define HASH_WORD_SIZE      4
#define HASH_PAD_START      0x80
#define HASH_HAS_TOTAL_SIZE
#define HASH_BIG_ENDIAN

void sha256_init(void *pctx)
{
 SHA256_CTX *ctx = (SHA256_CTX *) pctx;
 ctx->hashed_size = 0;
 ctx->ptr = 0;
 ctx->state[0] = 0x6A09E667;
 ctx->state[1] = 0xBB67AE85;
 ctx->state[2] = 0x3C6EF372;
 ctx->state[3] = 0xA54FF53A;
 ctx->state[4] = 0x510E527F;
 ctx->state[5] = 0x9B05688C;
 ctx->state[6] = 0x1F83D9AB;
 ctx->state[7] = 0x5BE0CD19;
}

void sha224_init(void *pctx)
{
 SHA224_CTX *ctx = (SHA224_CTX *) pctx;
 ctx->hashed_size = 0;
 ctx->ptr = 0;
 ctx->state[0] = 0xC1059ED8;
 ctx->state[1] = 0x367CD507;
 ctx->state[2] = 0x3070DD17;
 ctx->state[3] = 0xF70E5939;
 ctx->state[4] = 0xFFC00B31;
 ctx->state[5] = 0x68581511;
 ctx->state[6] = 0x64F98FA7;
 ctx->state[7] = 0xBEFA4FA4;
}

static void sha256_compress(void *pctx, const void *data);

#include "hash_common.inc"

#define ror(w, r) ((w)>>(r) | (w)<<(HASH_WORD_BITS-(r)))

#define S0(x) (ror((x), 7) ^ ror((x), 18) ^ ((x) >> 3))
#define S1(x) (ror((x), 17) ^ ror((x), 19) ^ ((x) >> 10))

#define cho(x, y, z) ((z) ^ ((x) & ((y) ^ (z)))) /* selection */
#define maj(x, y, z) (((x) & (y)) | ((z) & ((x) | (y)))) /* majority */
#define sigma0(x) (ror((x), 2) ^ ror((x), 13) ^ ror((x), 22))
#define sigma1(x) (ror((x), 6) ^ ror((x), 11) ^ ror((x), 25))
  
#define R(a, b, c, d, e, f, g, h, k)            \
 t = h + sigma1(e) + cho(e, f, g) + k + w[i++]; \
 d += t;                                        \
 h = t + sigma0(a) + maj(a, b, c);

static void sha256_compress(void *pctx, const void *data)
{
 uint32_t *state = ((SHA256_CTX *) pctx)->state;
 const uint32_t *wdata = (const uint32_t *) data;
 register uint32_t a, b, c, d, e, f, g, h, t;
 uint32_t w[64];
 int i;
  
 a = state[0];
 b = state[1];
 c = state[2];
 d = state[3];
 e = state[4];
 f = state[5];
 g = state[6];
 h = state[7];
 
 for (i=0; i<16; i++) w[i] = HASH_VALUE(wdata[i]);
 for (; i<64; i++) w[i] = S1(w[i-2]) + w[i-7] + S0(w[i-15]) + w[i-16];

 i = 0;
 R(a, b, c, d, e, f, g, h, 0x428A2F98)
 R(h, a, b, c, d, e, f, g, 0x71374491)
 R(g, h, a, b, c, d, e, f, 0xB5C0FBCF)
 R(f, g, h, a, b, c, d, e, 0xE9B5DBA5)
 R(e, f, g, h, a, b, c, d, 0x3956C25B)
 R(d, e, f, g, h, a, b, c, 0x59F111F1)
 R(c, d, e, f, g, h, a, b, 0x923F82A4)
 R(b, c, d, e, f, g, h, a, 0xAB1C5ED5)
 R(a, b, c, d, e, f, g, h, 0xD807AA98)
 R(h, a, b, c, d, e, f, g, 0x12835B01)
 R(g, h, a, b, c, d, e, f, 0x243185BE)
 R(f, g, h, a, b, c, d, e, 0x550C7DC3)
 R(e, f, g, h, a, b, c, d, 0x72BE5D74)
 R(d, e, f, g, h, a, b, c, 0x80DEB1FE)
 R(c, d, e, f, g, h, a, b, 0x9BDC06A7)
 R(b, c, d, e, f, g, h, a, 0xC19BF174)
 R(a, b, c, d, e, f, g, h, 0xE49B69C1)
 R(h, a, b, c, d, e, f, g, 0xEFBE4786)
 R(g, h, a, b, c, d, e, f, 0x0FC19DC6)
 R(f, g, h, a, b, c, d, e, 0x240CA1CC)
 R(e, f, g, h, a, b, c, d, 0x2DE92C6F)
 R(d, e, f, g, h, a, b, c, 0x4A7484AA)
 R(c, d, e, f, g, h, a, b, 0x5CB0A9DC)
 R(b, c, d, e, f, g, h, a, 0x76F988DA)
 R(a, b, c, d, e, f, g, h, 0x983E5152)
 R(h, a, b, c, d, e, f, g, 0xA831C66D)
 R(g, h, a, b, c, d, e, f, 0xB00327C8)
 R(f, g, h, a, b, c, d, e, 0xBF597FC7)
 R(e, f, g, h, a, b, c, d, 0xC6E00BF3)
 R(d, e, f, g, h, a, b, c, 0xD5A79147)
 R(c, d, e, f, g, h, a, b, 0x06CA6351)
 R(b, c, d, e, f, g, h, a, 0x14292967)
 R(a, b, c, d, e, f, g, h, 0x27B70A85)
 R(h, a, b, c, d, e, f, g, 0x2E1B2138)
 R(g, h, a, b, c, d, e, f, 0x4D2C6DFC)
 R(f, g, h, a, b, c, d, e, 0x53380D13)
 R(e, f, g, h, a, b, c, d, 0x650A7354)
 R(d, e, f, g, h, a, b, c, 0x766A0ABB)
 R(c, d, e, f, g, h, a, b, 0x81C2C92E)
 R(b, c, d, e, f, g, h, a, 0x92722C85)
 R(a, b, c, d, e, f, g, h, 0xA2BFE8A1)
 R(h, a, b, c, d, e, f, g, 0xA81A664B)
 R(g, h, a, b, c, d, e, f, 0xC24B8B70)
 R(f, g, h, a, b, c, d, e, 0xC76C51A3)
 R(e, f, g, h, a, b, c, d, 0xD192E819)
 R(d, e, f, g, h, a, b, c, 0xD6990624)
 R(c, d, e, f, g, h, a, b, 0xF40E3585)
 R(b, c, d, e, f, g, h, a, 0x106AA070)
 R(a, b, c, d, e, f, g, h, 0x19A4C116)
 R(h, a, b, c, d, e, f, g, 0x1E376C08)
 R(g, h, a, b, c, d, e, f, 0x2748774C)
 R(f, g, h, a, b, c, d, e, 0x34B0BCB5)
 R(e, f, g, h, a, b, c, d, 0x391C0CB3)
 R(d, e, f, g, h, a, b, c, 0x4ED8AA4A)
 R(c, d, e, f, g, h, a, b, 0x5B9CCA4F)
 R(b, c, d, e, f, g, h, a, 0x682E6FF3)
 R(a, b, c, d, e, f, g, h, 0x748F82EE)
 R(h, a, b, c, d, e, f, g, 0x78A5636F)
 R(g, h, a, b, c, d, e, f, 0x84C87814)
 R(f, g, h, a, b, c, d, e, 0x8CC70208)
 R(e, f, g, h, a, b, c, d, 0x90BEFFFA)
 R(d, e, f, g, h, a, b, c, 0xA4506CEB)
 R(c, d, e, f, g, h, a, b, 0xBEF9A3F7)
 R(b, c, d, e, f, g, h, a, 0xC67178F2)

 state[0] += a;
 state[1] += b;
 state[2] += c;
 state[3] += d;
 state[4] += e;
 state[5] += f;
 state[6] += g;
 state[7] += h;
}

#undef  HASH_FUNC_UPDATE
#undef  HASH_FUNC_FINAL
#undef  HASH_DIGEST_SIZE

#define HASH_FUNC_FINAL  sha224_final
#define HASH_DIGEST_SIZE 28

#include "hash_common.inc"
