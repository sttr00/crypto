#ifndef __platform_bits_h__
#define __platform_bits_h__

#include <stdint.h>
#include "arch.h"
#include "word.h"

/* GCC */
#ifdef __GNUC__

/* arch-independent gcc intrinsics */
#if defined(__GNUC_MINOR__) && (__GNUC__*256 + __GNUC_MINOR__ >= 0x303)
#define clz64 __builtin_clzl
#define ctz64 __builtin_ctzl
#define clz32 __builtin_clz
#define ctz32 __builtin_ctz
#endif

#if defined(ARCH_X86) || defined(ARCH_X86_64)

/* x86 gcc intrinsics */
#if defined(__GNUC_MINOR__) && (__GNUC__*256 + __GNUC_MINOR__ >= 0x404)
#include <x86intrin.h>
#define bsr32 __bsrd
#ifdef ARCH_X86_64
#define bsr64 __bsrq
#endif
#endif

/* clz32 */
#ifndef clz32
#define clz32 _clz32_impl
static __inline int _clz32_impl(uint32_t val) 
{
 uint32_t res;
 asm ("bsrl %1, %0\n\t"
      "xorl $31, %0\n\t" : "=r"(res) : "rm"(val) : "cc");
 return res;
}
#endif

/* clz64 */
#if !defined(clz64) && defined(ARCH_X86_64)
#define clz64 _clz64_impl
static __inline int _clz64_impl(uint64_t val) 
{
 uint64_t res;
 asm ("bsrq %1, %0\n\t"
      "xorq $63, %0\n\t" : "=r"(res) : "rm"(val) : "cc");
 return res;
}
#endif

/* ctz32 */
#ifndef ctz32
#define ctz32 _ctz32_impl
static __inline int _ctz32_impl(uint32_t val) 
{
 uint32_t res;
 asm ("bsfl %1, %0\n\t" : "=r"(res) : "rm"(val) : "cc");
 return res;
}
#endif

/* ctz64 */
#if !defined(ctz64) && defined(ARCH_X86_64)
#define ctz64 _ctz64_impl
static __inline int _ctz64_impl(uint64_t val) 
{
 uint64_t res;
 asm ("bsfq %1, %0\n\t" : "=r"(res) : "rm"(val) : "cc");
 return res;
}
#endif

/* bsr32 */
#ifndef bsr32
#define bsr32 _bsr32_impl
static __inline int _bsr32_impl(uint32_t val) 
{
 uint32_t res;
 asm ("bsrl %1, %0\n\t" : "=r"(res) : "rm"(val) : "cc");
 return res;
}
#endif

/* bsr64 */
#if !defined(bsr64) && defined(ARCH_X86_64)
#define bsr64 _bsr64_impl
static __inline int _bsr64_impl(uint64_t val) 
{
 uint64_t res;
 asm ("bsrq %1, %0\n\t" : "=r"(res) : "rm"(val) : "cc");
 return res;
}
#endif

#endif /* ARCH_X86 || ARCH_X86_64 */

/* MSVC */
#elif defined(_MSC_VER)

#include <intrin.h>

/* clz32 */
#define clz32 _clz32_impl
static __forceinline int _clz32_impl(uint32_t val)
{
 unsigned long pos;
 _BitScanReverse(&pos, val);
 return pos ^ 31;
}

/* clz64 */
#ifdef ENV_64BIT
#define clz64 _clz64_impl
static __forceinline int _clz64_impl(uint64_t val)
{
 unsigned long pos;
 _BitScanReverse64(&pos, val);
 return pos ^ 63;
}
#endif

/* ctz32 */
#define ctz32 _ctz32_impl
static __forceinline int _ctz32_impl(uint32_t val)
{
 unsigned long pos;
 _BitScanForward(&pos, val);
 return pos;
}

/* ctz64 */
#ifdef ENV_64BIT
#define ctz64 _ctz64_impl
static __forceinline int _ctz64_impl(uint64_t val)
{
 unsigned long pos;
 _BitScanForward64(&pos, val);
 return pos;
}
#endif

/* bsr32 */
#define bsr32 _bsr32_impl
static __forceinline int _bsr32_impl(uint32_t val)
{
 unsigned long pos;
 _BitScanReverse(&pos, val);
 return pos;
}

/* bsr64 */
#ifdef ENV_64BIT
#define bsr64 _bsr64_impl
static __forceinline int _bsr64_impl(uint64_t val)
{
 unsigned long pos;
 _BitScanReverse64(&pos, val);
 return pos;
}
#endif

#endif

/* generic clz */
#ifndef clz32
#define clz32 _clz32_impl
static __inline int _clz32_impl(uint32_t val)
{
 int result = 1;
 if (!(val >> 16)) { result += 16; val <<= 16; }
 if (!(val >> 24)) { result += 8;  val <<= 8;  }
 if (!(val >> 28)) { result += 4;  val <<= 4;  }
 if (!(val >> 30)) { result += 2;  val <<= 2;  }
 return result - (val >> 31);
}
#endif

#if !defined(clz64) && defined(ENV_64BIT)
#define clz64 _clz64_impl
static __inline int _clz64_impl(uint64_t val)
{
 int result = 1;
 if (!(val >> 32)) { result += 32; val <<= 32; }
 if (!(val >> 48)) { result += 16; val <<= 16; }
 if (!(val >> 56)) { result += 8;  val <<= 8;  }
 if (!(val >> 60)) { result += 4;  val <<= 4;  }
 if (!(val >> 62)) { result += 2;  val <<= 2;  }
 return result - (val >> 63);
}
#endif

/* generic ctz */
#ifndef ctz32
#define ctz32 _ctz32_impl
static __inline int _ctz32_impl(uint32_t val)
{
 int result = 1;
 if (!(val & 0xFFFF)) { result += 16; val >>= 16; }
 if (!(val & 0x00FF)) { result += 8;  val >>= 8;  }
 if (!(val & 0x000F)) { result += 4;  val >>= 4;  }
 if (!(val & 0x0003)) { result += 2;  val >>= 2;  }
 return result - (val & 1);
}
#endif

#if !defined(ctz64) && defined(ENV_64BIT)
#define ctz64 _ctz64_impl
static __inline int _ctz64_impl(uint64_t val)
{
 int result = 1;
 if (!(val & 0xFFFFFFFF)) { result += 32; val >>= 32; }
 if (!(val & 0x0000FFFF)) { result += 16; val >>= 16; }
 if (!(val & 0x000000FF)) { result += 8;  val >>= 8;  }
 if (!(val & 0x0000000F)) { result += 4;  val >>= 4;  }
 if (!(val & 0x00000003)) { result += 2;  val >>= 2;  }
 return result - (val & 1);
}
#endif

/* clz from bsr */
#if !defined(clz32) && defined(bsr32)
#define clz32 _clz32_impl
static __inline int _clz32_impl(uint32_t val) { return bsr32(val) ^ 31; }
#endif

#if !defined(clz64) && defined(bsr64)
#define clz64 _clz64_impl
static __inline int _clz64_impl(uint64_t val) { return bsr64(val) ^ 63; }
#endif

/* bsr from clz */
#if !defined(bsr32) && defined(clz32)
#define bsr32 _bsr32_impl
static __inline int _bsr32_impl(uint32_t val) { return clz32(val) ^ 31; }
#endif

#if !defined(bsr64) && defined(clz64)
#define bsr64 _bsr64_impl
static __inline int _bsr64_impl(uint64_t val) { return clz64(val) ^ 63; }
#endif

#ifdef ENV_64BIT
#define clzw clz64
#define ctzw ctz64
#define bsrw bsr64
#else
#define clzw clz32
#define ctzw ctz32
#define bsrw bsr32
#endif

#endif /* __platform_bits_h__ */
