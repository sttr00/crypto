#ifndef __hash_def_h__
#define __hash_def_h__

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

#endif
