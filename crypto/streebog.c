#include "streebog.h"
#include "streebog_tables.inc"
#include <platform/endian_ex.h>
#include <platform/word.h>
#include <string.h>

#define HASH_CONTEXT             STREEBOG_CTX
#define HASH_FUNC_COMPRESS       streebog_compress
#define HASH_FUNC_FINAL_COMPRESS streebog_final_compress
#define HASH_FUNC_UPDATE         streebog512_update
#define HASH_FUNC_FINAL          streebog512_final
#define HASH_DIGEST_SIZE         64
#define HASH_BLOCK_SIZE          64
#define HASH_WORD_SIZE           8
#define HASH_PAD_START           1
#define HASH_NEUTRAL_ENDIAN

typedef union
{
 uint64_t w[8];
 uint32_t hw[16];
 uint8_t  b[64];
} streebog_block_t;

#ifdef ENV_64BIT

#ifdef __BIG_ENDIAN__
#define LU_STEP0(i)    out->w[i]  = precomp[0][(in->w[0]>>(56-(8*i))) & 0xFF];
#define LU_STEP1(i, t) out->w[i] ^= precomp[t][(in->w[t]>>(56-(8*i))) & 0xFF];
#else
#define LU_STEP0(i)    out->w[i]  = precomp[0][(in->w[0]>>(8*i)) & 0xFF];
#define LU_STEP1(i, t) out->w[i] ^= precomp[t][(in->w[t]>>(8*i)) & 0xFF];
#endif

#define LOOKUP0        LU_STEP0(0) LU_STEP0(1) LU_STEP0(2) LU_STEP0(3) \
                       LU_STEP0(4) LU_STEP0(5) LU_STEP0(6) LU_STEP0(7)
#define LOOKUP1(t)     LU_STEP1(0, t) LU_STEP1(1, t) LU_STEP1(2, t) LU_STEP1(3, t) \
                       LU_STEP1(4, t) LU_STEP1(5, t) LU_STEP1(6, t) LU_STEP1(7, t)

#else

#ifdef __BIG_ENDIAN__
#define LU_STEP0(i, h)    out->w[4*h+i]  = precomp[0][(in->hw[h]>>(24-(8*i))) & 0xFF];
#define LU_STEP1(i, t, h) out->w[4*h+i] ^= precomp[t][(in->hw[2*t+h]>>(24-(8*i))) & 0xFF];
#else
#define LU_STEP0(i, h)    out->w[4*h+i]  = precomp[0][(in->hw[h]>>(8*i)) & 0xFF];
#define LU_STEP1(i, t, h) out->w[4*h+i] ^= precomp[t][(in->hw[2*t+h]>>(8*i)) & 0xFF];
#endif

#define LOOKUP0        LU_STEP0(0, 0) LU_STEP0(1, 0) LU_STEP0(2, 0) LU_STEP0(3, 0) \
                       LU_STEP0(0, 1) LU_STEP0(1, 1) LU_STEP0(2, 1) LU_STEP0(3, 1)
#define LOOKUP1(t)     LU_STEP1(0, t, 0) LU_STEP1(1, t, 0) LU_STEP1(2, t, 0) LU_STEP1(3, t, 0) \
                       LU_STEP1(0, t, 1) LU_STEP1(1, t, 1) LU_STEP1(2, t, 1) LU_STEP1(3, t, 1)

#endif

static __inline void lps(streebog_block_t *out, const streebog_block_t *in)
{
 LOOKUP0
 LOOKUP1(1)
 LOOKUP1(2)
 LOOKUP1(3)
 LOOKUP1(4)
 LOOKUP1(5)
 LOOKUP1(6)
 LOOKUP1(7)
}

#ifdef __GNUC__
#if defined(__i386__)
#define add_512_inplace(out, in) \
do \
{  \
 uint32_t tmp; \
 asm volatile( \
  "movl (%1), %0\n\t   addl %0, (%2)\n\t   movl 4(%1), %0\n\t  adcl %0, 4(%2)\n\t"  \
  "movl 8(%1), %0\n\t  adcl %0, 8(%2)\n\t  movl 12(%1), %0\n\t adcl %0, 12(%2)\n\t" \
  "movl 16(%1), %0\n\t adcl %0, 16(%2)\n\t movl 20(%1), %0\n\t adcl %0, 20(%2)\n\t" \
  "movl 24(%1), %0\n\t adcl %0, 24(%2)\n\t movl 28(%1), %0\n\t adcl %0, 28(%2)\n\t" \
  "movl 32(%1), %0\n\t adcl %0, 32(%2)\n\t movl 36(%1), %0\n\t adcl %0, 36(%2)\n\t" \
  "movl 40(%1), %0\n\t adcl %0, 40(%2)\n\t movl 44(%1), %0\n\t adcl %0, 44(%2)\n\t" \
  "movl 48(%1), %0\n\t adcl %0, 48(%2)\n\t movl 52(%1), %0\n\t adcl %0, 52(%2)\n\t" \
  "movl 56(%1), %0\n\t adcl %0, 56(%2)\n\t movl 60(%1), %0\n\t adcl %0, 60(%2)\n\t" \
  : "=&r"(tmp) : "r"(in), "r"(out) : "cc", "memory"); \
} while (0)
#elif defined(__amd64__)
#define add_512_inplace(out, in) \
do \
{  \
 uint64_t tmp; \
 asm volatile( \
  "movq (%1), %0\n\t   addq %0, (%2)\n\t   movq 8(%1), %0\n\t  adcq %0, 8(%2)\n\t"  \
  "movq 16(%1), %0\n\t adcq %0, 16(%2)\n\t movq 24(%1), %0\n\t adcq %0, 24(%2)\n\t" \
  "movq 32(%1), %0\n\t adcq %0, 32(%2)\n\t movq 40(%1), %0\n\t adcq %0, 40(%2)\n\t" \
  "movq 48(%1), %0\n\t adcq %0, 48(%2)\n\t movq 56(%1), %0\n\t adcq %0, 56(%2)\n\t" \
  : "=&r"(tmp) : "r"(in), "r"(out) : "cc", "memory"); \
} while (0)
#elif defined(__arm__) && !defined(__thumb__)
#define add_512_inplace(out, in) \
do \
{  \
 uint32_t tmp1, tmp2; \
 asm volatile( \
  "ldr %0, [%2], #4\n\t ldr %1, [%3]\n\t adds %0, %0, %1\n\t str %0, [%3], #4\n\t" \
  "ldr %0, [%2], #4\n\t ldr %1, [%3]\n\t adcs %0, %0, %1\n\t str %0, [%3], #4\n\t" \
  "ldr %0, [%2], #4\n\t ldr %1, [%3]\n\t adcs %0, %0, %1\n\t str %0, [%3], #4\n\t" \
  "ldr %0, [%2], #4\n\t ldr %1, [%3]\n\t adcs %0, %0, %1\n\t str %0, [%3], #4\n\t" \
  "ldr %0, [%2], #4\n\t ldr %1, [%3]\n\t adcs %0, %0, %1\n\t str %0, [%3], #4\n\t" \
  "ldr %0, [%2], #4\n\t ldr %1, [%3]\n\t adcs %0, %0, %1\n\t str %0, [%3], #4\n\t" \
  "ldr %0, [%2], #4\n\t ldr %1, [%3]\n\t adcs %0, %0, %1\n\t str %0, [%3], #4\n\t" \
  "ldr %0, [%2], #4\n\t ldr %1, [%3]\n\t adcs %0, %0, %1\n\t str %0, [%3], #4\n\t" \
  "ldr %0, [%2], #4\n\t ldr %1, [%3]\n\t adcs %0, %0, %1\n\t str %0, [%3], #4\n\t" \
  "ldr %0, [%2], #4\n\t ldr %1, [%3]\n\t adcs %0, %0, %1\n\t str %0, [%3], #4\n\t" \
  "ldr %0, [%2], #4\n\t ldr %1, [%3]\n\t adcs %0, %0, %1\n\t str %0, [%3], #4\n\t" \
  "ldr %0, [%2], #4\n\t ldr %1, [%3]\n\t adcs %0, %0, %1\n\t str %0, [%3], #4\n\t" \
  "ldr %0, [%2], #4\n\t ldr %1, [%3]\n\t adcs %0, %0, %1\n\t str %0, [%3], #4\n\t" \
  "ldr %0, [%2], #4\n\t ldr %1, [%3]\n\t adcs %0, %0, %1\n\t str %0, [%3], #4\n\t" \
  "ldr %0, [%2], #4\n\t ldr %1, [%3]\n\t adcs %0, %0, %1\n\t str %0, [%3], #4\n\t" \
  "ldr %0, [%2]\n\t     ldr %1, [%3]\n\t adcs %0, %0, %1\n\t str %0, [%3]\n\t"     \
  : "=&r"(tmp1), "=&r"(tmp2) : "r"(in), "r"(out) : "cc", "memory"); \
} while (0)
#elif defined(__aarch64__)
#define add_512_inplace(out, in) \
do \
{  \
 uint64_t tmp1, tmp2; \
 asm volatile( \
  "ldr %0, [%2], #8\n\t ldr %1, [%3]\n\t adds %0, %0, %1\n\t str %0, [%3], #8\n\t" \
  "ldr %0, [%2], #8\n\t ldr %1, [%3]\n\t adcs %0, %0, %1\n\t str %0, [%3], #8\n\t" \
  "ldr %0, [%2], #8\n\t ldr %1, [%3]\n\t adcs %0, %0, %1\n\t str %0, [%3], #8\n\t" \
  "ldr %0, [%2], #8\n\t ldr %1, [%3]\n\t adcs %0, %0, %1\n\t str %0, [%3], #8\n\t" \
  "ldr %0, [%2], #8\n\t ldr %1, [%3]\n\t adcs %0, %0, %1\n\t str %0, [%3], #8\n\t" \
  "ldr %0, [%2], #8\n\t ldr %1, [%3]\n\t adcs %0, %0, %1\n\t str %0, [%3], #8\n\t" \
  "ldr %0, [%2], #8\n\t ldr %1, [%3]\n\t adcs %0, %0, %1\n\t str %0, [%3], #8\n\t" \
  "ldr %0, [%2]\n\t     ldr %1, [%3]\n\t adcs %0, %0, %1\n\t str %0, [%3]\n\t"     \
  : "=&r"(tmp1), "=&r"(tmp2) : "r"(in), "r"(out) : "cc", "memory"); \
} while (0)
#endif
#elif defined(_MSC_VER)
#if defined(_M_IX86) || defined(_M_X64)
extern void streebog_add_512_inplace_impl(void *out, const void *in);
#define add_512_inplace streebog_add_512_inplace_impl
#endif
#endif

#ifndef add_512_inplace
/* generic version (slow) */
static __inline void add_512_inplace(uint64_t *out, const uint64_t *in)
{
 int i;
 uint64_t c = 0;
 for (i = 0; i < 8; i++)
 {
  uint64_t x = VALUE_LE64(out[i]);
  uint64_t y = VALUE_LE64(in[i]);
  uint64_t res = x + y + c;
  out[i] = VALUE_LE64(res);
  c = ((x & y) | ((x | y) & ~res)) >> 63;  
 }
}
#endif

static __inline void xor_512(uint64_t *out, const uint64_t *x, const uint64_t *y)
{
 int i;
 for (i = 0; i < 8; i++) out[i] = x[i] ^ y[i];
}

static __inline void xor_512_inplace(uint64_t *out, const uint64_t *in)
{
 int i;
 for (i = 0; i < 8; i++) out[i] ^= in[i];
}

static void process_block(STREEBOG_CTX *ctx, const uint64_t *data)
{
 int i;
 const uint64_t *ck_ptr = ck;
 streebog_block_t ks1, ks2;
 streebog_block_t t1, t2;
 for (i = 0; i < 8; i++) t1.w[i] = ctx->state.w[i];
 t1.w[0] ^= VALUE_LE64(ctx->hashed_size << 3);
 lps(&ks1, &t1);
 xor_512(t1.w, ks1.w, data);
 for (i = 0; i < 6; i++)
 {
  lps(&t2, &t1);
  xor_512_inplace(ks1.w, ck_ptr);
  ck_ptr += 8;
  lps(&ks2, &ks1);
  xor_512_inplace(t2.w, ks2.w);
  lps(&t1, &t2);
  xor_512_inplace(ks2.w, ck_ptr);
  ck_ptr += 8;
  lps(&ks1, &ks2);
  xor_512_inplace(t1.w, ks1.w);
 }
 xor_512_inplace(ctx->state.w, data);
 xor_512_inplace(ctx->state.w, t1.w);
 add_512_inplace(ctx->sigma.w, data);
}

static void streebog_compress(void *pctx, const void *data)
{
 STREEBOG_CTX *ctx = (STREEBOG_CTX *) pctx;
 process_block(ctx, (const uint64_t *) data);
 ctx->hashed_size += 64;
}

static void finalize(STREEBOG_CTX *ctx)
{
 int i;
 const uint64_t *ck_ptr = ck;
 streebog_block_t ks1, ks2;
 streebog_block_t t1, t2;
 uint64_t n = VALUE_LE64(ctx->hashed_size << 3);
 lps(&ks1, (const streebog_block_t *) &ctx->state);
 for (i = 0; i < 8; i++) t1.w[i] = ks1.w[i];
 t1.w[0] ^= n;
 for (i = 0; i < 6; i++)
 {
  lps(&t2, &t1);
  xor_512_inplace(ks1.w, ck_ptr);
  ck_ptr += 8;
  lps(&ks2, &ks1);
  xor_512_inplace(t2.w, ks2.w);
  lps(&t1, &t2);
  xor_512_inplace(ks2.w, ck_ptr);
  ck_ptr += 8;
  lps(&ks1, &ks2);
  xor_512_inplace(t1.w, ks1.w);
 }
 ctx->state.w[0] ^= n;
 xor_512_inplace(ctx->state.w, t1.w);

 ck_ptr = ck;
 lps(&ks1, (const streebog_block_t *) &ctx->state);
 xor_512(t1.w, ks1.w, ctx->sigma.w);
 for (i = 0; i < 6; i++)
 {
  lps(&t2, &t1);
  xor_512_inplace(ks1.w, ck_ptr);
  ck_ptr += 8;
  lps(&ks2, &ks1);
  xor_512_inplace(t2.w, ks2.w);
  lps(&t1, &t2);
  xor_512_inplace(ks2.w, ck_ptr);
  ck_ptr += 8;
  lps(&ks1, &ks2);
  xor_512_inplace(t1.w, ks1.w);
 }
 xor_512_inplace(ctx->state.w, t1.w);
 xor_512_inplace(ctx->state.w, ctx->sigma.w);
}

static void streebog_final_compress(void *pctx, const void *data)
{
 STREEBOG_CTX *ctx = (STREEBOG_CTX *) pctx;
 process_block(ctx, (const uint64_t *) data);
 ctx->hashed_size += ctx->ptr;
 finalize(ctx);
}

#include "hash_common.inc"

void streebog512_init(void *pctx)
{
 memset(pctx, 0, sizeof(STREEBOG_CTX));
}

#undef HASH_FUNC_FINAL
#undef HASH_FUNC_UPDATE
#undef HASH_DIGEST_SIZE

#define HASH_FUNC_FINAL    streebog256_final
#define HASH_DIGEST_SIZE   32
#define HASH_DIGEST_OFFSET 32

#include "hash_common.inc"

void streebog256_init(void *pctx)
{
 STREEBOG_CTX *ctx = (STREEBOG_CTX *) pctx; 
 memset(ctx, 0, sizeof(*ctx));
 memset(ctx->state.b, 1, sizeof(streebog_block_t));
}
