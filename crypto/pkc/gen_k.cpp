#include <crypto/hmac.h>
#include <crypto/sha256.h>
#include <crypto/oid_const.h>
#include <bigint/bigint.h>
#include <platform/alloca.h>
#include <string.h>
#include <assert.h>

void *gen_k_init(uint8_t *k, uint8_t *v, const hash_def *hd, const bigint_t q, const bigint_t h, const void *x, int xsize)
{
 void *ctx_hmac = hmac_alloc(hd);
 int hash_size = hd->hash_size;
 int qlen = bigint_get_bit_count(q);
 int qbytes = (qlen + 7) >> 3;
 uint8_t *t = (uint8_t *) alloca(qbytes);
 int hbytes = bigint_get_byte_count(h);
 int pad = qbytes - hbytes;
 assert(pad >= 0);
 for (int i = 0; i < pad; i++) t[i] = 0;
 bigint_get_bytes_be(h, t + pad, hbytes);

 memset(v, 1, hash_size);
 memset(k, 0, hash_size);
 hmac_set_key(ctx_hmac, k, hash_size);
 v[hash_size] = 0;
 hmac_update(ctx_hmac, v, hash_size + 1);
 pad = qbytes - xsize;
 assert(pad >= 0);
 uint8_t *xpad = (uint8_t *) alloca(pad);
 for (int i = 0; i < pad; i++) xpad[i] = 0;
 hmac_update(ctx_hmac, xpad, pad);
 hmac_update(ctx_hmac, x, xsize);
 hmac_update(ctx_hmac, t, qbytes);
 memcpy(k, hmac_final(ctx_hmac), hash_size);

 hmac_set_key(ctx_hmac, k, hash_size);
 hmac_update(ctx_hmac, v, hash_size);
 memcpy(v, hmac_final(ctx_hmac), hash_size);
 
 hmac_reset(ctx_hmac);
 v[hash_size] = 1;
 hmac_update(ctx_hmac, v, hash_size + 1);
 hmac_update(ctx_hmac, xpad, pad);
 hmac_update(ctx_hmac, x, xsize);
 hmac_update(ctx_hmac, t, qbytes);
 memcpy(k, hmac_final(ctx_hmac), hash_size);

 hmac_set_key(ctx_hmac, k, hash_size);
 hmac_update(ctx_hmac, v, hash_size);
 memcpy(v, hmac_final(ctx_hmac), hash_size);
 v[hash_size] = 0;
 return ctx_hmac;
}

void gen_k_next_key(uint8_t *k, uint8_t *v, int hash_size, void *ctx_hmac)
{
 hmac_reset(ctx_hmac);
 hmac_update(ctx_hmac, v, hash_size + 1);
 memcpy(k, hmac_final(ctx_hmac), hash_size);
 hmac_set_key(ctx_hmac, k, hash_size);
 hmac_update(ctx_hmac, v, hash_size);
 memcpy(v, hmac_final(ctx_hmac), hash_size);
}

void gen_k_create(bigint_t result, uint8_t *k, uint8_t *v, int hash_size, void *ctx_hmac, const bigint_t q)
{
 int qlen = bigint_get_bit_count(q);
 int qbytes = (qlen + 7) >> 3;
 int shift = qlen & 7;
 uint8_t *t = (uint8_t *) alloca(qbytes);
 for (;;)
 {
  int tbytes = 0;
  while (tbytes < qbytes)
  {
   int frag_size = qbytes - tbytes;
   if (frag_size > hash_size) frag_size = hash_size;
   hmac_reset(ctx_hmac);
   hmac_update(ctx_hmac, v, hash_size);
   memcpy(v, hmac_final(ctx_hmac), hash_size);
   memcpy(t + tbytes, v, frag_size);
   tbytes += frag_size;
  }
  bigint_set_bytes_be(result, t, qbytes);
  if (shift) bigint_rshift(result, result, 8-shift);
  if (bigint_cmp_abs(result, q) < 0 && !bigint_eq_word(result, 0)) break;
  // bad value of k, retry
  gen_k_next_key(k, v, hash_size, ctx_hmac);
 }
}
