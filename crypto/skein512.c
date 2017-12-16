#include "skein512.h"
#include <stdint.h>
#include <string.h>
#include <assert.h>

#define HASH_WORD_SIZE           8
#define HASH_DIGEST_SIZE         64
#define HASH_BLOCK_SIZE          64
#define HASH_CONTEXT             SKEIN512_CTX
#define HASH_FUNC_COMPRESS       skein512_compress
#define HASH_FUNC_FINAL_COMPRESS skein512_final_compress
#define HASH_FUNC_UPDATE         skein512_update
#define HASH_FUNC_FINAL          skein512_512_final
#define HASH_PAD_START           0
#define HASH_BUF_OFFSET

static void skein512_compress(void *pctx, const void *data);
static void skein512_final_compress(void *pctx, const void *data);

#include "hash_common.inc"

#define C240 0x1BD11BDAA9FC1A22ull
#define TYPE(t) ((uint64_t) (t) << 56)
#define FLAG_FIRST (1ull << 62)
#define FLAG_FINAL (1ull << 63)

#define rol(x, r) ((x<<r) | (x>>(64-r)))

#define mix(y0, y1, x0, x1, r) \
 y0 = x0 + x1; y1 = rol(x1, r) ^ y0;

#define add_subkey() \
 do \
 { \
  int l = 0; \
  for (j = js; j < je; j++) w1[l++] += ctx->state[j]; \
  for (j = 0; j < js-1; j++) w1[l++] += ctx->state[j]; \
  if (++js == 9) { js = 0; je = 8; } else je = 9; \
  w1[5] += ctx->t[ti]; \
  if (++ti == 3) ti = 0; \
  w1[6] += ctx->t[ti]; \
  w1[7] += s; \
 } while (0)

#define round(out, in, r1, r2, r3, r4) \
 mix(out[6], out[1], in[0], in[1], r1); \
 mix(out[0], out[7], in[2], in[3], r2); \
 mix(out[2], out[5], in[4], in[5], r3); \
 mix(out[4], out[3], in[6], in[7], r4);
 
static __inline void skein512_ubi(SKEIN512_CTX *ctx, const uint64_t *wdata)
{
 int i, j, ti, js, je;
 unsigned s = 0;
 uint64_t w1[8], w2[8];
 ctx->state[8] = C240;
 for (j = 0; j < 8; j++) ctx->state[8] ^= ctx->state[j];
 ctx->t[2] = ctx->t[0] ^ ctx->t[1];
 for (j = 0; j < 8; j++) w1[j] = HASH_VALUE(wdata[j]) + ctx->state[j];
 w1[5] += ctx->t[0];
 w1[6] += ctx->t[1];
 ti = 1;
 js = 1;
 je = 9;
 for (i = 0; i < 9; i++)
 {
  round(w2, w1, 46, 36, 19, 37);
  round(w1, w2, 33, 27, 14, 42);
  round(w2, w1, 17, 49, 36, 39);
  round(w1, w2, 44,  9, 54, 56);
  ++s;
  add_subkey();
  round(w2, w1, 39, 30, 34, 24);
  round(w1, w2, 13, 50, 10, 17);
  round(w2, w1, 25, 29, 39, 43);
  round(w1, w2,  8, 35, 56, 22);
  ++s;
  add_subkey();
 }
 for (j = 0; j < 8; j++) ctx->state[j] = w1[j] ^ HASH_VALUE(wdata[j]);
}

void skein512_compress(void *pctx, const void *unused)
{
 SKEIN512_CTX *ctx = (SKEIN512_CTX *) pctx;
 if (!ctx->buf_filled)
 {
  ctx->buf_filled = 1;
  ctx->offset ^= HASH_BLOCK_SIZE;
  return;
 }
 ctx->t[0] += HASH_BLOCK_SIZE;
 ctx->offset ^= HASH_BLOCK_SIZE;
 skein512_ubi(ctx, ctx->buf.w + ctx->offset/HASH_WORD_SIZE);
 ctx->t[1] &= ~FLAG_FIRST;
}

void skein512_final_compress(void *pctx, const void *unused)
{
 SKEIN512_CTX *ctx = (SKEIN512_CTX *) pctx;
 if (ctx->buf_filled && !ctx->ptr)
 {
  ctx->t[0] += HASH_BLOCK_SIZE;
  ctx->t[1] |= FLAG_FINAL;
  skein512_ubi(ctx, ctx->buf.w + (ctx->offset ^ HASH_BLOCK_SIZE)/HASH_WORD_SIZE);
 } else
 {
  if (ctx->buf_filled)
  {
   ctx->t[0] += HASH_BLOCK_SIZE;
   skein512_ubi(ctx, ctx->buf.w + (ctx->offset ^ HASH_BLOCK_SIZE)/HASH_WORD_SIZE);
   ctx->t[1] &= ~FLAG_FIRST;
  }
  ctx->t[0] += ctx->ptr;
  ctx->t[1] |= FLAG_FINAL;
  skein512_ubi(ctx, ctx->buf.w + ctx->offset/HASH_WORD_SIZE);
 }
 ctx->t[0] = 8;
 ctx->t[1] = TYPE(63) | FLAG_FIRST | FLAG_FINAL;
 memset(ctx->buf.w, 0, HASH_BLOCK_SIZE);
 skein512_ubi(ctx, ctx->buf.w);
}

void skein512_512_init(void *pctx)
{
 SKEIN512_CTX *ctx = (SKEIN512_CTX *) pctx;
 ctx->state[0] = 0x4903ADFF749C51CEull;
 ctx->state[1] = 0x0D95DE399746DF03ull;
 ctx->state[2] = 0x8FD1934127C79BCEull;
 ctx->state[3] = 0x9A255629FF352CB1ull;
 ctx->state[4] = 0x5DB62599DF6CA7B0ull;
 ctx->state[5] = 0xEABE394CA9D5C3F4ull;
 ctx->state[6] = 0x991112C71A75B523ull;
 ctx->state[7] = 0xAE18A40B660FCC33ull;
 ctx->t[0] = 0;
 ctx->t[1] = TYPE(48) | FLAG_FIRST;
 ctx->ptr = ctx->offset = 0;
 ctx->buf_filled = 0;
}

#undef  HASH_DIGEST_SIZE
#undef  HASH_FUNC_UPDATE
#undef  HASH_FUNC_FINAL

#define HASH_DIGEST_SIZE 48
#define HASH_FUNC_FINAL  skein512_384_final

#include "hash_common.inc"

void skein512_384_init(void *pctx)
{
 SKEIN512_CTX *ctx = (SKEIN512_CTX *) pctx;
 ctx->state[0] = 0xA3F6C6BF3A75EF5Full;
 ctx->state[1] = 0xB0FEF9CCFD84FAA4ull;
 ctx->state[2] = 0x9D77DD663D770CFEull;
 ctx->state[3] = 0xD798CBF3B468FDDAull;
 ctx->state[4] = 0x1BC4A6668A0E4465ull;
 ctx->state[5] = 0x7ED7D434E5807407ull;
 ctx->state[6] = 0x548FC1ACD4EC44D6ull;
 ctx->state[7] = 0x266E17546AA18FF8ull;
 ctx->t[0] = 0;
 ctx->t[1] = TYPE(48) | FLAG_FIRST;
 ctx->ptr = ctx->offset = 0;
 ctx->buf_filled = 0;
}

#undef  HASH_DIGEST_SIZE
#undef  HASH_FUNC_FINAL

#define HASH_DIGEST_SIZE 32
#define HASH_FUNC_FINAL  skein512_256_final

#include "hash_common.inc"

void skein512_256_init(void *pctx)
{
 SKEIN512_CTX *ctx = (SKEIN512_CTX *) pctx;
 ctx->state[0] = 0xCCD044A12FDB3E13ull;
 ctx->state[1] = 0xE83590301A79A9EBull;
 ctx->state[2] = 0x55AEA0614F816E6Full;
 ctx->state[3] = 0x2A2767A4AE9B94DBull;
 ctx->state[4] = 0xEC06025E74DD7683ull;
 ctx->state[5] = 0xE7A436CDC4746251ull;
 ctx->state[6] = 0xC36FBAF9393AD185ull;
 ctx->state[7] = 0x3EEDBA1833EDFC13ull;
 ctx->t[0] = 0;
 ctx->t[1] = TYPE(48) | FLAG_FIRST;
 ctx->ptr = ctx->offset = 0;
 ctx->buf_filled = 0;
}

#undef  HASH_DIGEST_SIZE
#undef  HASH_FUNC_FINAL

#define HASH_DIGEST_SIZE 28
#define HASH_FUNC_FINAL  skein512_224_final

#include "hash_common.inc"

void skein512_224_init(void *pctx)
{
 SKEIN512_CTX *ctx = (SKEIN512_CTX *) pctx;
 ctx->state[0] = 0xCCD0616248677224ull;
 ctx->state[1] = 0xCBA65CF3A92339EFull;
 ctx->state[2] = 0x8CCD69D652FF4B64ull;
 ctx->state[3] = 0x398AED7B3AB890B4ull;
 ctx->state[4] = 0x0F59D1B1457D2BD0ull;
 ctx->state[5] = 0x6776FE6575D4EB3Dull;
 ctx->state[6] = 0x99FBC70E997413E9ull;
 ctx->state[7] = 0x9E2CFCCFE1C41EF7ull;
 ctx->t[0] = 0;
 ctx->t[1] = TYPE(48) | FLAG_FIRST;
 ctx->ptr = ctx->offset = 0;
 ctx->buf_filled = 0;
}

/* MAC */

void *skein512mac_alloc()
{
 return malloc(HASH_BLOCK_SIZE + sizeof(SKEIN512_CTX));
}

void skein512mac_set_key(void *pctx, const void *pkey, size_t key_size, unsigned out_bits)
{
 uint8_t *saved_state = (uint8_t *) pctx;
 SKEIN512_CTX *ctx = (SKEIN512_CTX *) (saved_state + HASH_BLOCK_SIZE);
 const uint8_t *key = (const uint8_t *) pkey;
 union
 {
  uint8_t b[HASH_BLOCK_SIZE];
  uint64_t w[HASH_BLOCK_SIZE/sizeof(uint64_t)];
 } cfg;
 assert(out_bits <= HASH_BLOCK_SIZE*8);
 memset(ctx->state, 0, sizeof(ctx->state));
 /* key block */
 ctx->t[0] = 0;
 ctx->t[1] = FLAG_FIRST;
 for (size_t ptr = 0;;)
 {
  unsigned i;
  size_t nptr = ptr + HASH_BLOCK_SIZE;
  if (nptr >= key_size)
  {
   memset(ctx->buf.b, 0, HASH_BLOCK_SIZE);
   memcpy(ctx->buf.b, key + ptr, key_size - ptr);
   ctx->t[0] = key_size;
   ctx->t[1] |= FLAG_FINAL;
   skein512_ubi(ctx, ctx->buf.w);
   break;
  }
  for (i = 0; i < HASH_BLOCK_SIZE; i += HASH_WORD_SIZE)
  {
   ctx->buf.w[i/HASH_WORD_SIZE] = HASH_GET_WORD(key);
   key += HASH_WORD_SIZE;
  }
  ctx->t[0] += HASH_BLOCK_SIZE;
  skein512_ubi(ctx, ctx->buf.w);
  ctx->t[1] &= ~FLAG_FIRST;
  ptr = nptr;
 }
 /* configuration block */
 memset(cfg.b, 0, sizeof(cfg));
 cfg.b[0] = 'S';
 cfg.b[1] = 'H';
 cfg.b[2] = 'A';
 cfg.b[3] = '3';
 cfg.b[4] = 1;
 *(uint16_t *) (cfg.b + 8) = VALUE_LE16(out_bits);
 ctx->t[0] = 32;
 ctx->t[1] = TYPE(4) | FLAG_FIRST | FLAG_FINAL;
 skein512_ubi(ctx, cfg.w);
 memcpy(saved_state, ctx->state, HASH_BLOCK_SIZE);
 ctx->t[0] = 0;
 ctx->t[1] = TYPE(48) | FLAG_FIRST;
 ctx->ptr = ctx->offset = 0;
 ctx->buf_filled = 0;
}

void skein512mac_update(void *pctx, const void *data, size_t size)
{
 skein512_update((uint8_t *) pctx + HASH_BLOCK_SIZE, data, size); 
}

const void *skein512mac_final(void *pctx)
{
 return skein512_512_final((uint8_t *) pctx + HASH_BLOCK_SIZE); 
}

void skein512mac_reset(void *pctx)
{
 const uint8_t *saved_state = (const uint8_t *) pctx;
 SKEIN512_CTX *ctx = (SKEIN512_CTX *) (saved_state + HASH_BLOCK_SIZE);
 memcpy(ctx->state, saved_state, HASH_BLOCK_SIZE);
 ctx->t[0] = 0;
 ctx->t[1] = TYPE(48) | FLAG_FIRST;
 ctx->ptr = ctx->offset = 0;
 ctx->buf_filled = 0;
}
