#ifndef __gen_k_h__
#define __gen_k_h__

#include <bigint/bigint.h>
#include <crypto/hash_def.h>
#include <stdint.h>

void *gen_k_init(uint8_t *k, uint8_t *v, const hash_def *hd, const bigint_t q, const bigint_t h, const void *x, int xsize);
void gen_k_create(bigint_t result, uint8_t *k, uint8_t *v, int hash_size, void *ctx_hmac, const bigint_t q);
void gen_k_next_key(uint8_t *k, uint8_t *v, int hash_size, void *ctx_hmac);

#endif
