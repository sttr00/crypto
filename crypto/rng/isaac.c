/*
 ISAAC: a fast cryptographic random number generator
 http://www.burtleburtle.net/bob/rand/isaacafa.html
 */

#include "isaac.h"

#define ISAAC_RANDSIZL 8
#define ISAAC_RANDSIZ  (1<<ISAAC_RANDSIZL)

#define ind(mm,x)  (*(uint32_t *)((uint8_t *)(mm) + ((x) & ((ISAAC_RANDSIZ-1)<<2))))
#define rngstep(mix, a, b, mm, m, m2, r, x) \
{ \
 x = *m;  \
 a = (a^(mix)) + *m2++; \
 *m++ = y = ind(mm, x) + a + b; \
 *r++ = b = ind(mm, y>>ISAAC_RANDSIZL) + x; \
}

void isaac_process(ISAAC_CTX *ctx, uint32_t *r)
{
 uint32_t a, b, x, y, *m, *mm, *m2, *mend;
 ctx->randc++;
 mm = ctx->randmem;
 a = ctx->randa;
 b = ctx->randb + ctx->randc;
 for (m = mm, mend = m2 = m + ISAAC_RANDSIZ/2; m<mend;)
 {
  rngstep(a<<13, a, b, mm, m, m2, r, x);
  rngstep(a>>6,  a, b, mm, m, m2, r, x);
  rngstep(a<<2,  a, b, mm, m, m2, r, x);
  rngstep(a>>16, a, b, mm, m, m2, r, x);
 }
 for (m2 = mm; m2<mend;)
 {
  rngstep(a<<13, a, b, mm, m, m2, r, x);
  rngstep(a>>6,  a, b, mm, m, m2, r, x);
  rngstep(a<<2,  a, b, mm, m, m2, r, x);
  rngstep(a>>16, a, b, mm, m, m2, r, x);
 }
 ctx->randb = b;
 ctx->randa = a;
}


#define mix(a, b, c, d, e, f, g, h) \
{ \
 a ^= b<<11; d += a; b += c; \
 b ^= c>>2;  e += b; c += d; \
 c ^= d<<8;  f += c; d += e; \
 d ^= e>>16; g += d; e += f; \
 e ^= f<<10; h += e; f += g; \
 f ^= g>>4;  a += f; g += h; \
 g ^= h<<8;  b += g; h += a; \
 h ^= a>>9;  c += h; a += b; \
}

void isaac_init(ISAAC_CTX *ctx, const uint32_t *r)
{
 uint32_t a, b, c, d, e, f, g, h;
 uint32_t *m = ctx->randmem;
 int i;

 ctx->randa = ctx->randb = ctx->randc = 0;
 
 #if 0
 a = b = c = d = e = f = g = h = 0x9e3779b9;  /* the golden ratio */
 for (i=0; i<4; ++i) /* scramble it */
  mix(a, b, c, d, e, f, g, h);
 #else
 a = 0x1367DF5A;
 b = 0x95D90059;
 c = 0xC3163E4B;
 d = 0x0F421AD8;
 e = 0xD92A4A78;
 f = 0xA51A3C49;
 g = 0xC4EFEA1B;
 h = 0x30609119;
 #endif

 /* initialize using the contents of r[] as the seed */
 for (i=0; i<ISAAC_RANDSIZ; i+=8)
 {
  a += r[i  ]; b += r[i+1]; c += r[i+2]; d += r[i+3];
  e += r[i+4]; f += r[i+5]; g += r[i+6]; h += r[i+7];
  mix(a, b, c, d, e, f, g, h);
  m[i  ] = a; m[i+1] = b; m[i+2] = c; m[i+3]=d;
  m[i+4] = e; m[i+5] = f; m[i+6] = g; m[i+7]=h;
 }

 /* do a second pass to make all of the seed affect all of m */
 for (i=0; i<ISAAC_RANDSIZ; i+=8)
 {
  a += m[i  ]; b += m[i+1]; c += m[i+2]; d += m[i+3];
  e += m[i+4]; f += m[i+5]; g += m[i+6]; h += m[i+7];
  mix(a, b, c, d, e, f, g, h);
  m[i  ] = a; m[i+1] = b; m[i+2] = c; m[i+3] = d;
  m[i+4] = e; m[i+5] = f; m[i+6] = g; m[i+7] = h;
 }
}

#ifdef ISAAC_TESTSUITE

#include <stdio.h>
#include <string.h>

void isaac_test()
{
 uint32_t r[ISAAC_RANDSIZ];
 ISAAC_CTX ctx;
 int i, j;
 memset(r, 0, sizeof(r));
 isaac_init(&ctx, r);
 isaac_process(&ctx, r);
 for (i=0; i<2; i++)
 {
  isaac_process(&ctx, r);
  for (j=0; j<256; j++)
  {
   printf("%08x", r[j]);
   if ((j & 7) == 7) printf("\n");
  }
 }
}
#endif
