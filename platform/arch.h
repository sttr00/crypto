#ifndef __platform_arch_h__
#define __platform_arch_h__

/* GCC */
#ifdef __GNUC__

#if defined(__i386__)
#define ARCH_X86
#elif defined(__amd64__)
#define ARCH_X86_64
#elif defined(__arm__)
#define ARCH_ARM
#elif defined(__ppc__)
#define ARCH_PPC
#endif

/* MSVC */
#elif defined(_MSC_VER)

#if defined(_M_IX86)
#define ARCH_X86
#elif defined(_M_X64)
#define ARCH_X86_64
#elif defined(_M_ARM)
#define ARCH_ARM
#elif defined(_M_PPC)
#define ARCH_PPC
#endif

#endif

#endif /* __platform_arch_h__ */
