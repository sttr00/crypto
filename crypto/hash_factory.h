#ifndef __hash_factory_h__
#define __hash_factory_h__

#include <stddef.h>

typedef struct
{
 int id;
 int hash_size;
 int block_size;
 int context_size;
 void (*func_init)(void *ctx);
 void (*func_update)(void *ctx, const void *data, size_t size);
 const void* (*func_final)(void *ctx);
} hash_def;

#ifdef __cplusplus
extern "C"
{
#endif

const hash_def *hash_factory(int id);

#ifdef __cplusplus
}
#endif

#endif /* __hash_factory_h__ */
