#include "md5.h"

#define HASH_CONTEXT        MD5_CTX
#define HASH_FUNC_COMPRESS  md5_compress
#define HASH_FUNC_UPDATE    md5_update
#define HASH_FUNC_FINAL     md5_final
#define HASH_DIGEST_SIZE    16
#define HASH_BLOCK_SIZE     64
#define HASH_WORD_SIZE      4
#define HASH_PAD_START      0x80
#define HASH_HAS_TOTAL_SIZE

void md5_init(void *pctx)
{
 MD5_CTX *ctx = (MD5_CTX *) pctx;
 ctx->hashed_size = 0;
 ctx->ptr = 0;
 ctx->state[0] = 0x67452301ul;
 ctx->state[1] = 0xEFCDAB89ul;
 ctx->state[2] = 0x98BADCFEul;
 ctx->state[3] = 0x10325476ul;
}

static void md5_compress(void *pctx, const void *data);

#include "hash_common.inc"

#define rol(w, r) ((w)<<(r) | (w)>>(HASH_WORD_BITS-(r)))

#define F(x, y, z) ((z) ^ ((x) & ((y) ^ (z)))) /* selection */
#define G(x, y, z) F(z, x, y)
#define H(x, y, z) ((x) ^ (y) ^ (z)) /* parity */
#define I(x, y, z) ((y) ^ ((x) | ~(z)))  /* majority */

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4 */
/* Rotation is separate from addition to prevent recomputation */
#define FF(a, b, c, d, x, s, ac) \
 (a) += F((b), (c), (d)) + (x) + (ac); \
 (a) = rol((a), (s)); \
 (a) += (b);

#define GG(a, b, c, d, x, s, ac) \
 (a) += G((b), (c), (d)) + (x) + (ac); \
 (a) = rol((a), (s)); \
 (a) += (b);

#define HH(a, b, c, d, x, s, ac) \
 (a) += H((b), (c), (d)) + (x) + (ac); \
 (a) = rol((a), (s)); \
 (a) += (b);

#define II(a, b, c, d, x, s, ac) \
 (a) += I((b), (c), (d)) + (x) + (ac); \
 (a) = rol((a), (s)); \
 (a) += (b);

static void md5_compress(void *pctx, const void *data)
{
 register uint32_t a, b, c, d;

 uint32_t *state = ((MD5_CTX *) pctx)->state;
 #ifdef HASH_ENDIAN_MATCH
 const uint32_t *wdata = (const uint32_t *) data;
 #else
 uint32_t wdata[HASH_BLOCK_SIZE/4];
 const uint32_t *idata = (const uint32_t *) data;
 unsigned i;
 for (i=0; i<HASH_BLOCK_SIZE/4; i++) wdata[i] = HASH_VALUE(idata[i]);
 #endif

 a = state[0];
 b = state[1];
 c = state[2];
 d = state[3];

 /* Round 1 */
 #define S11 7
 #define S12 12
 #define S13 17
 #define S14 22
 FF(a, b, c, d, wdata[ 0], S11, 3614090360UL); /* 1 */
 FF(d, a, b, c, wdata[ 1], S12, 3905402710UL); /* 2 */
 FF(c, d, a, b, wdata[ 2], S13,  606105819UL); /* 3 */
 FF(b, c, d, a, wdata[ 3], S14, 3250441966UL); /* 4 */
 FF(a, b, c, d, wdata[ 4], S11, 4118548399UL); /* 5 */
 FF(d, a, b, c, wdata[ 5], S12, 1200080426UL); /* 6 */
 FF(c, d, a, b, wdata[ 6], S13, 2821735955UL); /* 7 */
 FF(b, c, d, a, wdata[ 7], S14, 4249261313UL); /* 8 */
 FF(a, b, c, d, wdata[ 8], S11, 1770035416UL); /* 9 */
 FF(d, a, b, c, wdata[ 9], S12, 2336552879UL); /* 10 */
 FF(c, d, a, b, wdata[10], S13, 4294925233UL); /* 11 */
 FF(b, c, d, a, wdata[11], S14, 2304563134UL); /* 12 */
 FF(a, b, c, d, wdata[12], S11, 1804603682UL); /* 13 */
 FF(d, a, b, c, wdata[13], S12, 4254626195UL); /* 14 */
 FF(c, d, a, b, wdata[14], S13, 2792965006UL); /* 15 */
 FF(b, c, d, a, wdata[15], S14, 1236535329UL); /* 16 */

 /* Round 2 */
 #define S21 5
 #define S22 9
 #define S23 14
 #define S24 20
 GG(a, b, c, d, wdata[ 1], S21, 4129170786UL); /* 17 */
 GG(d, a, b, c, wdata[ 6], S22, 3225465664UL); /* 18 */
 GG(c, d, a, b, wdata[11], S23,  643717713UL); /* 19 */
 GG(b, c, d, a, wdata[ 0], S24, 3921069994UL); /* 20 */
 GG(a, b, c, d, wdata[ 5], S21, 3593408605UL); /* 21 */
 GG(d, a, b, c, wdata[10], S22,   38016083UL); /* 22 */
 GG(c, d, a, b, wdata[15], S23, 3634488961UL); /* 23 */
 GG(b, c, d, a, wdata[ 4], S24, 3889429448UL); /* 24 */
 GG(a, b, c, d, wdata[ 9], S21,  568446438UL); /* 25 */
 GG(d, a, b, c, wdata[14], S22, 3275163606UL); /* 26 */
 GG(c, d, a, b, wdata[ 3], S23, 4107603335UL); /* 27 */
 GG(b, c, d, a, wdata[ 8], S24, 1163531501UL); /* 28 */
 GG(a, b, c, d, wdata[13], S21, 2850285829UL); /* 29 */
 GG(d, a, b, c, wdata[ 2], S22, 4243563512UL); /* 30 */
 GG(c, d, a, b, wdata[ 7], S23, 1735328473UL); /* 31 */
 GG(b, c, d, a, wdata[12], S24, 2368359562UL); /* 32 */

 /* Round 3 */
 #define S31 4
 #define S32 11
 #define S33 16
 #define S34 23
 HH(a, b, c, d, wdata[ 5], S31, 4294588738UL); /* 33 */
 HH(d, a, b, c, wdata[ 8], S32, 2272392833UL); /* 34 */
 HH(c, d, a, b, wdata[11], S33, 1839030562UL); /* 35 */
 HH(b, c, d, a, wdata[14], S34, 4259657740UL); /* 36 */
 HH(a, b, c, d, wdata[ 1], S31, 2763975236UL); /* 37 */
 HH(d, a, b, c, wdata[ 4], S32, 1272893353UL); /* 38 */
 HH(c, d, a, b, wdata[ 7], S33, 4139469664UL); /* 39 */
 HH(b, c, d, a, wdata[10], S34, 3200236656UL); /* 40 */
 HH(a, b, c, d, wdata[13], S31,  681279174UL); /* 41 */
 HH(d, a, b, c, wdata[ 0], S32, 3936430074UL); /* 42 */
 HH(c, d, a, b, wdata[ 3], S33, 3572445317UL); /* 43 */
 HH(b, c, d, a, wdata[ 6], S34,   76029189UL); /* 44 */
 HH(a, b, c, d, wdata[ 9], S31, 3654602809UL); /* 45 */
 HH(d, a, b, c, wdata[12], S32, 3873151461UL); /* 46 */
 HH(c, d, a, b, wdata[15], S33,  530742520UL); /* 47 */
 HH(b, c, d, a, wdata[ 2], S34, 3299628645UL); /* 48 */

 /* Round 4 */
 #define S41 6
 #define S42 10
 #define S43 15
 #define S44 21
 II(a, b, c, d, wdata[ 0], S41, 4096336452UL); /* 49 */
 II(d, a, b, c, wdata[ 7], S42, 1126891415UL); /* 50 */
 II(c, d, a, b, wdata[14], S43, 2878612391UL); /* 51 */
 II(b, c, d, a, wdata[ 5], S44, 4237533241UL); /* 52 */
 II(a, b, c, d, wdata[12], S41, 1700485571UL); /* 53 */
 II(d, a, b, c, wdata[ 3], S42, 2399980690UL); /* 54 */
 II(c, d, a, b, wdata[10], S43, 4293915773UL); /* 55 */
 II(b, c, d, a, wdata[ 1], S44, 2240044497UL); /* 56 */
 II(a, b, c, d, wdata[ 8], S41, 1873313359UL); /* 57 */
 II(d, a, b, c, wdata[15], S42, 4264355552UL); /* 58 */
 II(c, d, a, b, wdata[ 6], S43, 2734768916UL); /* 59 */
 II(b, c, d, a, wdata[13], S44, 1309151649UL); /* 60 */
 II(a, b, c, d, wdata[ 4], S41, 4149444226UL); /* 61 */
 II(d, a, b, c, wdata[11], S42, 3174756917UL); /* 62 */
 II(c, d, a, b, wdata[ 2], S43,  718787259UL); /* 63 */
 II(b, c, d, a, wdata[ 9], S44, 3951481745UL); /* 64 */

 state[0] += a;
 state[1] += b;
 state[2] += c;
 state[3] += d;
}
