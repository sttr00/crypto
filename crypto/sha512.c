#include "sha512.h"

#define HASH_CONTEXT        SHA512_CTX
#define HASH_FUNC_COMPRESS  sha512_compress
#define HASH_FUNC_UPDATE    sha512_update
#define HASH_FUNC_FINAL     sha512_final
#define HASH_DIGEST_SIZE    64
#define HASH_BLOCK_SIZE     128
#define HASH_WORD_SIZE      8
#define HASH_PAD_START      0x80
#define HASH_HAS_TOTAL_SIZE
#define HASH_BIG_ENDIAN

void sha512_init(void *pctx)
{
 SHA512_CTX *ctx = (SHA512_CTX *) pctx;
 ctx->hashed_size = 0;
 ctx->ptr = 0;
 ctx->state[0] = 0x6A09E667F3BCC908ull;
 ctx->state[1] = 0xBB67AE8584CAA73Bull;
 ctx->state[2] = 0x3C6EF372FE94F82Bull;
 ctx->state[3] = 0xA54FF53A5F1D36F1ull;
 ctx->state[4] = 0x510E527FADE682D1ull;
 ctx->state[5] = 0x9B05688C2B3E6C1Full;
 ctx->state[6] = 0x1F83D9ABFB41BD6Bull;
 ctx->state[7] = 0x5BE0CD19137E2179ull;
}

void sha384_init(void *pctx)
{
 SHA384_CTX *ctx = (SHA384_CTX *) pctx;
 ctx->hashed_size = 0;
 ctx->ptr = 0;
 ctx->state[0] = 0xCBBB9D5DC1059ED8ull;
 ctx->state[1] = 0x629A292A367CD507ull;
 ctx->state[2] = 0x9159015A3070DD17ull;
 ctx->state[3] = 0x152FECD8F70E5939ull;
 ctx->state[4] = 0x67332667FFC00B31ull;
 ctx->state[5] = 0x8EB44A8768581511ull;
 ctx->state[6] = 0xDB0C2E0D64F98FA7ull;
 ctx->state[7] = 0x47B5481DBEFA4FA4ull;
}

static void sha512_compress(void *pctx, const void *data);

#include "hash_common.inc"

#define ror(w, r) ((w)>>(r) | (w)<<(HASH_WORD_BITS-(r)))

#define S0(x) (ror((x), 1) ^ ror((x), 8) ^ ((x) >> 7))
#define S1(x) (ror((x), 19) ^ ror((x), 61) ^ ((x) >> 6))

#define cho(x, y, z) ((z) ^ ((x) & ((y) ^ (z)))) /* selection */
#define maj(x, y, z) (((x) & (y)) | ((z) & ((x) | (y)))) /* majority */
#define sigma0(x) (ror((x), 28) ^ ror((x), 34) ^ ror((x), 39))
#define sigma1(x) (ror((x), 14) ^ ror((x), 18) ^ ror((x), 41))
  
#define R(a, b, c, d, e, f, g, h, k)            \
 t = h + sigma1(e) + cho(e, f, g) + k + w[i++]; \
 d += t;                                        \
 h = t + sigma0(a) + maj(a, b, c);

static void sha512_compress(void *pctx, const void *data)
{
 uint64_t *state = ((SHA512_CTX *) pctx)->state;
 const uint64_t *wdata = (const uint64_t *) data;
 register uint64_t a, b, c, d, e, f, g, h, t;
 uint64_t w[80];
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
 for (; i<80; i++) w[i] = S1(w[i-2]) + w[i-7] + S0(w[i-15]) + w[i-16];

 i = 0;
 R(a, b, c, d, e, f, g, h, 0x428A2F98D728AE22ull)
 R(h, a, b, c, d, e, f, g, 0x7137449123EF65CDull)
 R(g, h, a, b, c, d, e, f, 0xB5C0FBCFEC4D3B2Full)
 R(f, g, h, a, b, c, d, e, 0xE9B5DBA58189DBBCull)
 R(e, f, g, h, a, b, c, d, 0x3956C25BF348B538ull)
 R(d, e, f, g, h, a, b, c, 0x59F111F1B605D019ull)
 R(c, d, e, f, g, h, a, b, 0x923F82A4AF194F9Bull)
 R(b, c, d, e, f, g, h, a, 0xAB1C5ED5DA6D8118ull)
 R(a, b, c, d, e, f, g, h, 0xD807AA98A3030242ull)
 R(h, a, b, c, d, e, f, g, 0x12835B0145706FBEull)
 R(g, h, a, b, c, d, e, f, 0x243185BE4EE4B28Cull)
 R(f, g, h, a, b, c, d, e, 0x550C7DC3D5FFB4E2ull)
 R(e, f, g, h, a, b, c, d, 0x72BE5D74F27B896Full)
 R(d, e, f, g, h, a, b, c, 0x80DEB1FE3B1696B1ull)
 R(c, d, e, f, g, h, a, b, 0x9BDC06A725C71235ull)
 R(b, c, d, e, f, g, h, a, 0xC19BF174CF692694ull)
 R(a, b, c, d, e, f, g, h, 0xE49B69C19EF14AD2ull)
 R(h, a, b, c, d, e, f, g, 0xEFBE4786384F25E3ull)
 R(g, h, a, b, c, d, e, f, 0x0FC19DC68B8CD5B5ull)
 R(f, g, h, a, b, c, d, e, 0x240CA1CC77AC9C65ull)
 R(e, f, g, h, a, b, c, d, 0x2DE92C6F592B0275ull)
 R(d, e, f, g, h, a, b, c, 0x4A7484AA6EA6E483ull)
 R(c, d, e, f, g, h, a, b, 0x5CB0A9DCBD41FBD4ull)
 R(b, c, d, e, f, g, h, a, 0x76F988DA831153B5ull)
 R(a, b, c, d, e, f, g, h, 0x983E5152EE66DFABull)
 R(h, a, b, c, d, e, f, g, 0xA831C66D2DB43210ull)
 R(g, h, a, b, c, d, e, f, 0xB00327C898FB213Full)
 R(f, g, h, a, b, c, d, e, 0xBF597FC7BEEF0EE4ull)
 R(e, f, g, h, a, b, c, d, 0xC6E00BF33DA88FC2ull)
 R(d, e, f, g, h, a, b, c, 0xD5A79147930AA725ull)
 R(c, d, e, f, g, h, a, b, 0x06CA6351E003826Full)
 R(b, c, d, e, f, g, h, a, 0x142929670A0E6E70ull)
 R(a, b, c, d, e, f, g, h, 0x27B70A8546D22FFCull)
 R(h, a, b, c, d, e, f, g, 0x2E1B21385C26C926ull)
 R(g, h, a, b, c, d, e, f, 0x4D2C6DFC5AC42AEDull)
 R(f, g, h, a, b, c, d, e, 0x53380D139D95B3DFull)
 R(e, f, g, h, a, b, c, d, 0x650A73548BAF63DEull)
 R(d, e, f, g, h, a, b, c, 0x766A0ABB3C77B2A8ull)
 R(c, d, e, f, g, h, a, b, 0x81C2C92E47EDAEE6ull)
 R(b, c, d, e, f, g, h, a, 0x92722C851482353Bull)
 R(a, b, c, d, e, f, g, h, 0xA2BFE8A14CF10364ull)
 R(h, a, b, c, d, e, f, g, 0xA81A664BBC423001ull)
 R(g, h, a, b, c, d, e, f, 0xC24B8B70D0F89791ull)
 R(f, g, h, a, b, c, d, e, 0xC76C51A30654BE30ull)
 R(e, f, g, h, a, b, c, d, 0xD192E819D6EF5218ull)
 R(d, e, f, g, h, a, b, c, 0xD69906245565A910ull)
 R(c, d, e, f, g, h, a, b, 0xF40E35855771202Aull)
 R(b, c, d, e, f, g, h, a, 0x106AA07032BBD1B8ull)
 R(a, b, c, d, e, f, g, h, 0x19A4C116B8D2D0C8ull)
 R(h, a, b, c, d, e, f, g, 0x1E376C085141AB53ull)
 R(g, h, a, b, c, d, e, f, 0x2748774CDF8EEB99ull)
 R(f, g, h, a, b, c, d, e, 0x34B0BCB5E19B48A8ull)
 R(e, f, g, h, a, b, c, d, 0x391C0CB3C5C95A63ull)
 R(d, e, f, g, h, a, b, c, 0x4ED8AA4AE3418ACBull)
 R(c, d, e, f, g, h, a, b, 0x5B9CCA4F7763E373ull)
 R(b, c, d, e, f, g, h, a, 0x682E6FF3D6B2B8A3ull)
 R(a, b, c, d, e, f, g, h, 0x748F82EE5DEFB2FCull)
 R(h, a, b, c, d, e, f, g, 0x78A5636F43172F60ull)
 R(g, h, a, b, c, d, e, f, 0x84C87814A1F0AB72ull)
 R(f, g, h, a, b, c, d, e, 0x8CC702081A6439ECull)
 R(e, f, g, h, a, b, c, d, 0x90BEFFFA23631E28ull)
 R(d, e, f, g, h, a, b, c, 0xA4506CEBDE82BDE9ull)
 R(c, d, e, f, g, h, a, b, 0xBEF9A3F7B2C67915ull)
 R(b, c, d, e, f, g, h, a, 0xC67178F2E372532Bull)
 R(a, b, c, d, e, f, g, h, 0xCA273ECEEA26619Cull)
 R(h, a, b, c, d, e, f, g, 0xD186B8C721C0C207ull)
 R(g, h, a, b, c, d, e, f, 0xEADA7DD6CDE0EB1Eull)
 R(f, g, h, a, b, c, d, e, 0xF57D4F7FEE6ED178ull)
 R(e, f, g, h, a, b, c, d, 0x06F067AA72176FBAull)
 R(d, e, f, g, h, a, b, c, 0x0A637DC5A2C898A6ull)
 R(c, d, e, f, g, h, a, b, 0x113F9804BEF90DAEull)
 R(b, c, d, e, f, g, h, a, 0x1B710B35131C471Bull)
 R(a, b, c, d, e, f, g, h, 0x28DB77F523047D84ull)
 R(h, a, b, c, d, e, f, g, 0x32CAAB7B40C72493ull)
 R(g, h, a, b, c, d, e, f, 0x3C9EBE0A15C9BEBCull)
 R(f, g, h, a, b, c, d, e, 0x431D67C49C100D4Cull)
 R(e, f, g, h, a, b, c, d, 0x4CC5D4BECB3E42B6ull)
 R(d, e, f, g, h, a, b, c, 0x597F299CFC657E2Aull)
 R(c, d, e, f, g, h, a, b, 0x5FCB6FAB3AD6FAECull)
 R(b, c, d, e, f, g, h, a, 0x6C44198C4A475817ull)

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

#define HASH_FUNC_FINAL  sha384_final
#define HASH_DIGEST_SIZE 48

#include "hash_common.inc"
