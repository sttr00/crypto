#ifndef __tsc_h__
#define __tsc_h__

#include <stdint.h>

#ifdef _WIN32

#include <winnt.h>

#ifdef ReadTimeStampCounter
#define read_tsc ReadTimeStampCounter
#else
#include <intrin.h>
#define read_tsc __rdtsc
#endif

#elif defined(__GNUC__)

#if defined(__GNUC_MINOR__) && (__GNUC__*256 + __GNUC_MINOR__ >= 0x404) && (defined(__i386__) || defined(__amd64__))
#include <x86intrin.h>
#define read_tsc __rdtsc
#elif defined(__i386__)
static __inline uint64_t read_tsc_impl()
{
 uint64_t r;
 asm volatile("rdtsc \n\t" : "=A" (r));
 return r;
}
#define read_tsc read_tsc_impl
#elif defined(__amd64__)
static __inline uint64_t read_tsc_impl()
{
 uint64_t r;
 asm volatile("rdtsc              \n\t"
              "shlq  $32, %%rdx   \n\t"
              "orq   %%rdx, %%rax \n\t" : "=a" (r) :: "cc");
 return r;
}
#define read_tsc read_tsc_impl
#endif

#endif

#ifndef read_tsc
static __inline uint64_t read_tsc_dummy() { return 0; }
#define read_tsc read_tsc_dummy
#ifdef _MSC_VER
#pragma message("Warning: This platform has no timestamp counter")
#else
#warning This platform has no timestamp counter
#endif
#endif

#endif /* __tsc_h__ */
