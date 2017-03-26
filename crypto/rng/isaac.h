#ifndef __isaac_h__
#define __isaac_h__

#include <stdint.h>

typedef struct
{
 uint32_t randmem[256]; /* current state, 256 = ISAAC_RANDSIZ */
 uint32_t randa;
 uint32_t randb;
 uint32_t randc;
} ISAAC_CTX;

#ifdef __cplusplus
extern "C"
{
#endif

/* initialize using the contents of r[] as the seed */
void isaac_init(ISAAC_CTX *ctx, const uint32_t *r);

/* generate next 256 numbers in r[] */
void isaac_process(ISAAC_CTX *ctx, uint32_t *r);

#ifdef __cplusplus
}
#endif

#endif
