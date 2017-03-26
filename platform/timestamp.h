#ifndef __platform_timestamp_h__
#define __platform_timestamp_h__

#include <stdint.h>

#ifndef __INLINE
#ifdef _MSC_VER
#define __INLINE __forceinline
#else
#define __INLINE __inline
#endif
#endif

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#ifdef __cplusplus
namespace platform
{
#endif

static __INLINE int64_t get_timestamp()
{
 int64_t result;
 QueryPerformanceCounter((LARGE_INTEGER *) &result);
 return result;
}

static __INLINE int64_t timestamp_frequency()
{
 int64_t result; 
 QueryPerformanceFrequency((LARGE_INTEGER *) &result);
 return result;
}

#ifdef __cplusplus
}
#endif

#else

#include <time.h>

#ifdef __cplusplus
namespace platform
{
#endif

static __INLINE int64_t get_timestamp()
{
 struct timespec t;
 #ifdef CLOCK_BOOTTIME
 clock_gettime(CLOCK_BOOTTIME, &t);
 #else
 clock_gettime(CLOCK_MONOTONIC, &t);
 #endif
 return t.tv_sec*1000000000ll + t.tv_nsec;
}

#if defined(__cplusplus) && __cplusplus > 199711
constexpr int64_t timestamp_frequency()
{
 return 1000000000ll;
}
#else
static __INLINE int64_t timestamp_frequency()
{
 return 1000000000ll;
}
#endif

#ifdef __cplusplus
}
#endif

#endif

#endif /* __platform_timestamp_h__ */
