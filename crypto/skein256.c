#include "skein256.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#define HASH_WORD_SIZE           8
#define HASH_DIGEST_SIZE         32
#define HASH_BLOCK_SIZE          32
#define HASH_CONTEXT             SKEIN256_CTX
#define HASH_FUNC_COMPRESS       skein256_compress
#define HASH_FUNC_FINAL_COMPRESS skein256_final_compress
#define HASH_FUNC_UPDATE         skein256_update
#define HASH_FUNC_FINAL          skein256_256_final
#define HASH_PAD_START           0
#define HASH_BUF_OFFSET

static void skein256_compress(void *pctx, const void *data);
static void skein256_final_compress(void *pctx, const void *data);

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
  if (++js == 5) { js = 0; je = 4; } else je = 5; \
  w1[1] += ctx->t[ti]; \
  if (++ti == 3) ti = 0; \
  w1[2] += ctx->t[ti]; \
  w1[3] += s; \
 } while (0)

#define round(out, in, r1, r2) \
 mix(out[0], out[3], in[0], in[1], r1); \
 mix(out[2], out[1], in[2], in[3], r2);
 
static __inline void skein256_ubi(SKEIN256_CTX *ctx, const uint64_t *wdata)
{
 int i, j, ti, js, je;
 unsigned s = 0;
 uint64_t w1[4], w2[4];
 ctx->state[4] = C240;
 for (j = 0; j < 4; j++) ctx->state[4] ^= ctx->state[j];
 ctx->t[2] = ctx->t[0] ^ ctx->t[1];
 for (j = 0; j < 4; j++) w1[j] = HASH_VALUE(wdata[j]) + ctx->state[j];
 w1[1] += ctx->t[0];
 w1[2] += ctx->t[1];
 ti = 1;
 js = 1;
 je = 5;
 for (i = 0; i < 9; i++)
 {
  round(w2, w1, 14, 16);
  round(w1, w2, 52, 57);
  round(w2, w1, 23, 40);
  round(w1, w2,  5, 37);
  ++s;
  add_subkey();
  round(w2, w1, 25, 33);
  round(w1, w2, 46, 12);
  round(w2, w1, 58, 22);
  round(w1, w2, 32, 32);
  ++s;
  add_subkey();
 }
 for (j = 0; j < 4; j++) ctx->state[j] = w1[j] ^ HASH_VALUE(wdata[j]);
}

void skein256_compress(void *pctx, const void *unused)
{
 SKEIN256_CTX *ctx = (SKEIN256_CTX *) pctx;
 if (!ctx->buf_filled)
 {
  ctx->buf_filled = 1;
  ctx->offset ^= HASH_BLOCK_SIZE;
  return;
 }
 ctx->t[0] += HASH_BLOCK_SIZE;
 ctx->offset ^= HASH_BLOCK_SIZE;
 skein256_ubi(ctx, ctx->buf.w + ctx->offset/HASH_WORD_SIZE);
 ctx->t[1] &= ~FLAG_FIRST;
}

void skein256_final_compress(void *pctx, const void *unused)
{
 SKEIN256_CTX *ctx = (SKEIN256_CTX *) pctx;
 if (ctx->buf_filled && !ctx->ptr)
 {
  ctx->t[0] += HASH_BLOCK_SIZE;
  ctx->t[1] |= FLAG_FINAL;
  skein256_ubi(ctx, ctx->buf.w + (ctx->offset ^ HASH_BLOCK_SIZE)/HASH_WORD_SIZE);
 } else
 {
  if (ctx->buf_filled)
  {
   ctx->t[0] += HASH_BLOCK_SIZE;
   skein256_ubi(ctx, ctx->buf.w + (ctx->offset ^ HASH_BLOCK_SIZE)/HASH_WORD_SIZE);
   ctx->t[1] &= ~FLAG_FIRST;
  }
  ctx->t[0] += ctx->ptr;
  ctx->t[1] |= FLAG_FINAL;
  skein256_ubi(ctx, ctx->buf.w + ctx->offset/HASH_WORD_SIZE);
 }
 ctx->t[0] = 8;
 ctx->t[1] = TYPE(63) | FLAG_FIRST | FLAG_FINAL;
 memset(ctx->buf.w, 0, HASH_BLOCK_SIZE);
 skein256_ubi(ctx, ctx->buf.w);
}

void skein256_256_init(void *pctx)
{
 SKEIN256_CTX *ctx = (SKEIN256_CTX *) pctx;
 ctx->state[0] = 0xFC9DA860D048B449ull;
 ctx->state[1] = 0x2FCA66479FA7D833ull;
 ctx->state[2] = 0xB33BC3896656840Full;
 ctx->state[3] = 0x6A54E920FDE8DA69ull;
 ctx->t[0] = 0;
 ctx->t[1] = TYPE(48) | FLAG_FIRST;
 ctx->ptr = ctx->offset = 0;
 ctx->buf_filled = 0;
}

#undef  HASH_DIGEST_SIZE
#undef  HASH_FUNC_UPDATE
#undef  HASH_FUNC_FINAL

#define HASH_DIGEST_SIZE 28
#define HASH_FUNC_FINAL  skein256_224_final

#include "hash_common.inc"

void skein256_224_init(void *pctx)
{
 SKEIN256_CTX *ctx = (SKEIN256_CTX *) pctx;
 ctx->state[0] = 0xC6098A8C9AE5EA0Bull;
 ctx->state[1] = 0x876D568608C5191Cull;
 ctx->state[2] = 0x99CB88D7D7F53884ull;
 ctx->state[3] = 0x384BDDB1AEDDB5DEull;
 ctx->t[0] = 0;
 ctx->t[1] = TYPE(48) | FLAG_FIRST;
 ctx->ptr = ctx->offset = 0;
 ctx->buf_filled = 0;
}

#undef  HASH_DIGEST_SIZE
#undef  HASH_FUNC_FINAL

#define HASH_DIGEST_SIZE 20
#define HASH_FUNC_FINAL  skein256_160_final

#include "hash_common.inc"

void skein256_160_init(void *pctx)
{
 SKEIN256_CTX *ctx = (SKEIN256_CTX *) pctx;
 ctx->state[0] = 0x1420231472825E98ull;
 ctx->state[1] = 0x2AC4E9A25A77E590ull;
 ctx->state[2] = 0xD47A58568838D63Eull;
 ctx->state[3] = 0x2DD2E4968586AB7Dull;
 ctx->t[0] = 0;
 ctx->t[1] = TYPE(48) | FLAG_FIRST;
 ctx->ptr = ctx->offset = 0;
 ctx->buf_filled = 0;
}

#undef  HASH_DIGEST_SIZE
#undef  HASH_FUNC_FINAL

#define HASH_DIGEST_SIZE 16
#define HASH_FUNC_FINAL  skein256_128_final

#include "hash_common.inc"

void skein256_128_init(void *pctx)
{
 SKEIN256_CTX *ctx = (SKEIN256_CTX *) pctx;
 ctx->state[0] = 0xE1111906964D7260ull;
 ctx->state[1] = 0x883DAAA77C8D811Cull;
 ctx->state[2] = 0x10080DF491960F7Aull;
 ctx->state[3] = 0xCCF7DDE5B45BC1C2ull;
 ctx->t[0] = 0;
 ctx->t[1] = TYPE(48) | FLAG_FIRST;
 ctx->ptr = ctx->offset = 0;
 ctx->buf_filled = 0;
}

/* MAC */

void *skein256mac_alloc()
{
 return malloc(HASH_BLOCK_SIZE + sizeof(SKEIN256_CTX));
}

void skein256mac_set_key(void *pctx, const void *pkey, size_t key_size, unsigned out_bits)
{
 size_t ptr;
 uint8_t *saved_state = (uint8_t *) pctx;
 SKEIN256_CTX *ctx = (SKEIN256_CTX *) (saved_state + HASH_BLOCK_SIZE);
 const uint8_t *key = (const uint8_t *) pkey;
 union
 {
  uint8_t b[HASH_BLOCK_SIZE];
  uint16_t u[HASH_BLOCK_SIZE/sizeof(uint16_t)];
  uint64_t w[HASH_BLOCK_SIZE/sizeof(uint64_t)];
 } cfg;
 assert(out_bits <= HASH_BLOCK_SIZE*8);
 memset(ctx->state, 0, sizeof(ctx->state));
 /* key block */
 ctx->t[0] = 0;
 ctx->t[1] = FLAG_FIRST;
 for (ptr = 0;;)
 {
  unsigned i;
  size_t nptr = ptr + HASH_BLOCK_SIZE;
  if (nptr >= key_size)
  {
   memset(ctx->buf.b, 0, HASH_BLOCK_SIZE);
   memcpy(ctx->buf.b, key + ptr, key_size - ptr);
   ctx->t[0] = key_size;
   ctx->t[1] |= FLAG_FINAL;
   skein256_ubi(ctx, ctx->buf.w);
   break;
  }
  for (i = 0; i < HASH_BLOCK_SIZE; i += HASH_WORD_SIZE)
  {
   ctx->buf.w[i/HASH_WORD_SIZE] = HASH_GET_WORD(key);
   key += HASH_WORD_SIZE;
  }
  ctx->t[0] += HASH_BLOCK_SIZE;
  skein256_ubi(ctx, ctx->buf.w);
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
 cfg.u[4] = VALUE_LE16(out_bits);
 ctx->t[0] = 32;
 ctx->t[1] = TYPE(4) | FLAG_FIRST | FLAG_FINAL;
 skein256_ubi(ctx, cfg.w);
 memcpy(saved_state, ctx->state, HASH_BLOCK_SIZE);
 ctx->t[0] = 0;
 ctx->t[1] = TYPE(48) | FLAG_FIRST;
 ctx->ptr = ctx->offset = 0;
 ctx->buf_filled = 0;
}

void skein256mac_update(void *pctx, const void *data, size_t size)
{
 skein256_update((uint8_t *) pctx + HASH_BLOCK_SIZE, data, size); 
}

const void *skein256mac_final(void *pctx)
{
 return skein256_256_final((uint8_t *) pctx + HASH_BLOCK_SIZE); 
}

void skein256mac_reset(void *pctx)
{
 const uint8_t *saved_state = (const uint8_t *) pctx;
 SKEIN256_CTX *ctx = (SKEIN256_CTX *) (saved_state + HASH_BLOCK_SIZE);
 memcpy(ctx->state, saved_state, HASH_BLOCK_SIZE);
 ctx->t[0] = 0;
 ctx->t[1] = TYPE(48) | FLAG_FIRST;
 ctx->ptr = ctx->offset = 0;
 ctx->buf_filled = 0;
}
