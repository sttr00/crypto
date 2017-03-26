#ifndef __platform_endian_h__
#define __platform_endian_h__

#if defined(__BIG_ENDIAN__) && defined(__LITTLE_ENDIAN__)
#error Both __BIG_ENDIAN__ and __LITTLE_ENDIAN__ are defined
#endif

#if !defined(__BIG_ENDIAN__) && !defined(__LITTLE_ENDIAN__)

#ifdef _WIN32

#define __LITTLE_ENDIAN__

#else

#include <endian.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define __LITTLE_ENDIAN__
#elif __BYTE_ORDER == __BIG_ENDIAN
#define __BIG_ENDIAN__
#else
#error Unsupported value of __BYTE_ORDER
#endif

#endif
#endif

#endif /* __platform_endian_h__ */
