#include <platform/unaligned.h>
#include <platform/endian_ex.h>

#undef HASH_ENDIAN_MATCH
#undef HASH_WORD_BITS
#undef HASH_GET_WORD
#undef HASH_SWAP_WORD
#undef HASH_VALUE_BE
#undef HASH_VALUE_LE
#undef HASH_VALUE
#undef HASH_VALUE64

#ifdef HASH_NEUTRAL_ENDIAN
#define HASH_ENDIAN_MATCH
#else
#ifdef __BIG_ENDIAN__
#ifdef HASH_BIG_ENDIAN
#define HASH_ENDIAN_MATCH
#endif
#else
#ifndef HASH_BIG_ENDIAN
#define HASH_ENDIAN_MATCH
#endif
#endif
#endif

#ifdef HASH_WORD_SIZE
#if HASH_WORD_SIZE == 4
#define HASH_WORD_BITS 32
typedef uint32_t hash_word_t;
#elif HASH_WORD_SIZE == 8
#define HASH_WORD_BITS 64
typedef uint64_t hash_word_t;
#else
#error HASH_WORD_SIZE must be 4 or 8
#endif
#else
#error HASH_WORD_SIZE must defined
#endif

#undef  CAT
#define CAT(x, y)   x ## y

#undef  EVAL
#define EVAL(x, y)  CAT(x, y)

#define HASH_GET_WORD  EVAL(get_unaligned, HASH_WORD_BITS)
#define HASH_SWAP_WORD EVAL(SWAP, HASH_WORD_BITS)
#define HASH_VALUE_BE  EVAL(VALUE_BE, HASH_WORD_BITS)
#define HASH_VALUE_LE  EVAL(VALUE_LE, HASH_WORD_BITS)

#ifdef HASH_BIG_ENDIAN
#define HASH_VALUE    HASH_VALUE_BE
#define HASH_VALUE64  VALUE_BE64
#else
#define HASH_VALUE    HASH_VALUE_LE
#define HASH_VALUE64  VALUE_LE64
#endif

#ifdef HASH_FUNC_UPDATE
void HASH_FUNC_UPDATE(void *pctx, const void *data, size_t size)
{
 const uint8_t *buf = (const uint8_t *) data;
 HASH_CONTEXT *ctx = (HASH_CONTEXT *) pctx;
 unsigned ptr = ctx->ptr;
 #ifdef HASH_HAS_TOTAL_SIZE
 ctx->hashed_size += size;
 #endif
 if (ptr)
 {
  while (ptr & (HASH_WORD_SIZE-1))
  {
   if (!size) break;
   ctx->buf.b[ptr++] = *buf++;
   size--;
  }
  if (ptr == HASH_BLOCK_SIZE)
  {
   ptr = 0;
   HASH_FUNC_COMPRESS(ctx, ctx->buf.w);
  } else
  {
   unsigned max_ptr;
   unsigned aligned_size = (unsigned) (size & ~(HASH_WORD_SIZE-1));
   unsigned use_size = HASH_BLOCK_SIZE - ptr;
   if (aligned_size < use_size) use_size = aligned_size;
   max_ptr = ptr + use_size;
   while (ptr < max_ptr)
   {
    ctx->buf.w[ptr/HASH_WORD_SIZE] = HASH_GET_WORD(buf);
    ptr += HASH_WORD_SIZE;
    buf += HASH_WORD_SIZE;
   }
   size -= use_size;
   if (ptr == HASH_BLOCK_SIZE)
   {
    ptr = 0;
    HASH_FUNC_COMPRESS(ctx, ctx->buf.w);
   }
  }
 }
 while (size >= HASH_BLOCK_SIZE)
 {
  #ifdef HAVE_UNALIGNED_ACCESS
  HASH_FUNC_COMPRESS(ctx, buf);
  buf += HASH_BLOCK_SIZE;
  #else 
  int i;
  for (i = 0; i < HASH_BLOCK_SIZE/HASH_WORD_SIZE; i++)
  {
   ctx->buf.w[i] = HASH_GET_WORD(buf);
   buf += HASH_WORD_SIZE;
  }
  HASH_FUNC_COMPRESS(ctx, ctx->buf.w);
  #endif
  size -= HASH_BLOCK_SIZE;
 }
 if (size)
 {
  unsigned aligned_size = (unsigned) (size & ~(HASH_WORD_SIZE-1));
  while (ptr < aligned_size)
  {
   ctx->buf.w[ptr/HASH_WORD_SIZE] = HASH_GET_WORD(buf);
   ptr += HASH_WORD_SIZE;
   buf += HASH_WORD_SIZE;
  }
  size -= aligned_size;
  while (size)
  {
   ctx->buf.b[ptr++] = *buf++;
   size--;
  }
 }
 ctx->ptr = ptr;
}
#endif /* HASH_FUNC_UPDATE */

#ifdef HASH_FUNC_FINAL
const void *HASH_FUNC_FINAL(void *pctx)
{
 HASH_CONTEXT *ctx = (HASH_CONTEXT *) pctx;
 #ifdef HASH_DIGEST_OFFSET
 hash_word_t *digest = (hash_word_t *) ((uint8_t *) &ctx->state + HASH_DIGEST_OFFSET);
 #else
 hash_word_t *digest = (hash_word_t *) &ctx->state;
 #endif
 #ifdef HASH_HAS_TOTAL_SIZE
 uint64_t bits = ctx->hashed_size << 3;
 #endif
 unsigned ptr = ctx->ptr;
 #ifndef HASH_ENDIAN_MATCH
 unsigned i;
 #endif
 if (ptr & (HASH_WORD_SIZE-1))
 {
  uint8_t val = HASH_PAD_START;
  while (ptr & (HASH_WORD_SIZE-1))
  {
   ctx->buf.b[ptr++] = val;
   val = 0;
  }
 } else
 {
  ctx->buf.w[ptr/HASH_WORD_SIZE] = HASH_VALUE_BE((hash_word_t) HASH_PAD_START << (HASH_WORD_BITS-8));
  ptr += HASH_WORD_SIZE;
 }
 #ifdef HASH_HAS_TOTAL_SIZE
 if (ptr > HASH_BLOCK_SIZE-2*HASH_WORD_SIZE)
 {
  while (ptr < HASH_BLOCK_SIZE)
  {
   ctx->buf.w[ptr/HASH_WORD_SIZE] = 0;
   ptr += HASH_WORD_SIZE;
  }
  HASH_FUNC_COMPRESS(ctx, ctx->buf.w);
  ptr = 0;
 }
 while (ptr < HASH_BLOCK_SIZE-8)
 {
  ctx->buf.w[ptr/HASH_WORD_SIZE] = 0;
  ptr += HASH_WORD_SIZE;
 }
 put_unaligned64(ctx->buf.b + HASH_BLOCK_SIZE - 8, HASH_VALUE64(bits));
 #else
 while (ptr < HASH_BLOCK_SIZE)
 {
  ctx->buf.w[ptr/HASH_WORD_SIZE] = 0;
  ptr += HASH_WORD_SIZE;
 }
 #endif
 #ifdef HASH_PAD_END
 /* only used by SHA3 */
 ctx->buf.b[HASH_BLOCK_SIZE-1] |= HASH_PAD_END;
 #endif
 #ifdef HASH_FUNC_FINAL_COMPRESS
 HASH_FUNC_FINAL_COMPRESS(ctx, ctx->buf.w);
 #else
 HASH_FUNC_COMPRESS(ctx, ctx->buf.w);
 #endif
 #ifndef HASH_ENDIAN_MATCH
 for (i = 0; i < HASH_DIGEST_SIZE/HASH_WORD_SIZE; i++)
  digest[i] = HASH_SWAP_WORD(digest[i]);
 #endif
 return digest;
}
#endif /* HASH_FUNC_FINAL */
