#ifndef __platform_word_h__
#define __platform_word_h__

#include <stdint.h>

#if !defined(ENV_32BIT) && !defined(ENV_64BIT)
#ifdef _WIN32

#ifdef _WIN64
#define ENV_64BIT
#else
#define ENV_32BIT
#endif

#elif defined(__GNUC__)

#ifdef __LP64__
#define ENV_64BIT
#else
#define ENV_32BIT
#endif

#else

#error Unknown environment

#endif

#endif

#ifdef ENV_64BIT

typedef uint64_t sys_word_t;
typedef int64_t  sys_signed_word_t;
#define SYS_WORD_SIZE  8
#define SYS_WORD_SHIFT 3

#else

typedef uint32_t sys_word_t;
typedef int32_t  sys_signed_word_t;
#define SYS_WORD_SIZE  4
#define SYS_WORD_SHIFT 2

#endif

#endif /* __platform_word_h__ */
