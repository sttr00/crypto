#ifndef __hmac_h__
#define __hmac_h__

#include "hash_def.h"

#ifdef __cplusplus
extern "C"
{
#endif

int hmac_get_context_size(const hash_def *hd);
void *hmac_alloc(const hash_def *hd);
void hmac_set_key(void *ctx, const void *key, size_t key_size);
void hmac_update(void *ctx, const void *data, size_t size);
const void *hmac_final(void *ctx);
void hmac_reset(void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* __hmac_h__ */
