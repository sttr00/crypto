#include "hmac.h"
#include <platform/alloca.h>
#include <platform/word.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#define CTX_ALIGN 16u

#define IPAD_BYTE 0x36
#define XPAD_BYTE 0x6A

#ifdef ENV_64BIT
#define IPAD_WORD 0x3636363636363636ull
#define XPAD_WORD 0x6A6A6A6A6A6A6A6Aull
#else
#define IPAD_WORD 0x36363636ul
#define XPAD_WORD 0x6A6A6A6Aul
#endif

typedef union
{
 const hash_def *hd;
 uint8_t pad[CTX_ALIGN]; 
} hmac_ctx_header;

int hmac_get_context_size(const hash_def *hd)
{
 int hash_ctx_size = (hd->context_size + CTX_ALIGN-1) & ~CTX_ALIGN;
 return sizeof(hmac_ctx_header) + 3*hash_ctx_size + hd->hash_size;
}

void *hmac_alloc(const hash_def *hd)
{
 int size = hmac_get_context_size(hd);
 void *ctx = malloc(size);
 memset(ctx, 0, size);
 ((hmac_ctx_header *) ctx)->hd = hd;
 return ctx;
}

#define XOR_KEY(B, W) \
 pk_len = hd->block_size;             \
 ptr = padded_key;                    \
 while (pk_len >= sizeof(sys_word_t)) \
 {                                    \
  *(sys_word_t *) ptr ^= W;           \
  pk_len -= sizeof(sys_word_t);       \
  ptr += sizeof(sys_word_t);          \
 }                                    \
 while (pk_len)                       \
 {                                    \
  *ptr++ ^= B;                        \
  pk_len--;                           \
 }

void hmac_set_key(void *ctx, const void *key, size_t key_size)
{
 const hash_def *hd = ((const hmac_ctx_header *) ctx)->hd;
 unsigned hash_ctx_size = (hd->context_size + CTX_ALIGN-1) & ~CTX_ALIGN;
 uint8_t *ctx_temp = (uint8_t *) ctx + sizeof(hmac_ctx_header);
 uint8_t *ctx_inner = ctx_temp + hash_ctx_size;
 uint8_t *ctx_outer = ctx_inner + hash_ctx_size;
 uint8_t *padded_key, *ptr;
 size_t pk_len;

 padded_key = (uint8_t *) alloca(hd->block_size);
 memset(padded_key, 0, hd->block_size);
 if (key_size > (size_t) hd->block_size)
 {
  hd->func_init(ctx_inner);
  hd->func_update(ctx_inner, key, key_size);
  assert(hd->hash_size <= hd->block_size);
  memcpy(padded_key, hd->func_final(ctx_inner), hd->hash_size);
 } else memcpy(padded_key, key, key_size);

 XOR_KEY(IPAD_BYTE, IPAD_WORD);
 hd->func_init(ctx_inner);
 hd->func_update(ctx_inner, padded_key, hd->block_size);

 XOR_KEY(XPAD_BYTE, XPAD_WORD);
 hd->func_init(ctx_outer);
 hd->func_update(ctx_outer, padded_key, hd->block_size);

 memcpy(ctx_temp, ctx_inner, hash_ctx_size);
}

void hmac_update(void *ctx, const void *data, size_t size)
{
 const hash_def *hd = ((const hmac_ctx_header *) ctx)->hd;
 uint8_t *ctx_temp = (uint8_t *) ctx + sizeof(hmac_ctx_header);
 hd->func_update(ctx_temp, data, size);
}

const void *hmac_final(void *ctx)
{
 const hash_def *hd = ((const hmac_ctx_header *) ctx)->hd;
 unsigned hash_ctx_size = (hd->context_size + CTX_ALIGN-1) & ~CTX_ALIGN;
 uint8_t *ctx_temp = (uint8_t *) ctx + sizeof(hmac_ctx_header);
 uint8_t *ctx_inner = ctx_temp + hash_ctx_size;
 uint8_t *ctx_outer = ctx_inner + hash_ctx_size;
 uint8_t *hash_buf = ctx_outer + hash_ctx_size;
 memcpy(hash_buf, hd->func_final(ctx_temp), hd->hash_size);
 memcpy(ctx_temp, ctx_outer, hash_ctx_size);
 hd->func_update(ctx_temp, hash_buf, hd->hash_size);
 return hd->func_final(ctx_temp);
}

void hmac_reset(void *ctx)
{
 const hash_def *hd = ((const hmac_ctx_header *) ctx)->hd;
 unsigned hash_ctx_size = (hd->context_size + CTX_ALIGN-1) & ~CTX_ALIGN;
 uint8_t *ctx_temp = (uint8_t *) ctx + sizeof(hmac_ctx_header);
 uint8_t *ctx_inner = ctx_temp + hash_ctx_size;
 memcpy(ctx_temp, ctx_inner, hash_ctx_size);
}
