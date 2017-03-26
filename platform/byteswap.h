#ifndef __platform_byteswap_h__
#define __platform_byteswap_h__

#include <stdint.h>

#ifdef _MSC_VER

#if _MSC_VER >= 1500
#include <intrin.h>
#else
#include <stdlib.h>
#endif

#ifndef __INLINE
#define __INLINE __forceinline
#endif

#define SWAP32 _byteswap_ulong
#define SWAP64 _byteswap_uint64

#elif defined(__GNUC__)

#ifndef __INLINE
#define __INLINE __inline
#endif

#if defined(__GNUC_MINOR__) && __GNUC__*256 + __GNUC_MINOR__ >= 0x403
#define SWAP32 __builtin_bswap32
#define SWAP64 __builtin_bswap64
#endif

#endif

#ifndef SWAP16
#define SWAP16 _swap16
static __INLINE uint16_t _swap16(uint16_t x)
{
 return x>>8 | x<<8;
}
#endif

#ifndef SWAP32
#define SWAP32 _swap32
static __INLINE uint32_t _swap32(uint32_t x)
{
 return (x>>24) | ((x>>8) & 0xFF00) | ((x<<8) & 0xFF0000) | (x<<24);
}
#endif

#ifndef SWAP64
#define SWAP64 _swap64
#include "word.h"
#ifdef ENV_32BIT
static __INLINE uint64_t _swap64(uint64_t x)
{
 uint32_t hi = (uint32_t) (x>>32);
 uint32_t lo = (uint32_t) x;
 return (uint64_t) SWAP32(lo)<<32 | SWAP32(hi);
}
#else
static __INLINE uint64_t _swap64(uint64_t x)
{
 return (x>>56) | ((x>>40) & 0xFF00ull) | ((x>>24) & 0xFF0000ull) | ((x>>8) & 0xFF000000ull) |
        ((x<<8) & 0xFF00000000ull) | ((x<<24) & 0xFF0000000000ull) | ((x<<40) & 0xFF000000000000ull) | (x<<56);
}
#endif
#endif

#endif /* __platform_byteswap_h__ */
