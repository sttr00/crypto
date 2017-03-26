#include "cpu_features.h"

#undef ARCH_INTEL
#undef ARCH_ARM

#ifdef _MSC_VER

#if defined(_M_IX86) || defined(_M_X64)
#define ARCH_INTEL

#if _MSC_VER >= 1500 /* VS2008 */
#include <intrin.h>
#define cpuid(output, eax, ecx) __cpuidex((int *) (output), (eax), (ecx))
#else
extern void cpuid_impl(uint32_t *output, uint32_t eax, uint32_t ecx);
#define cpuid cpuid_impl
#endif

#if defined(_MSC_FULL_VER) && _MSC_FULL_VER >= 160040219 /* VS2010 SP1 */
#include <intrin.h>
#define xgetbv(c) ((uint32_t) _xgetbv(c))
#elif defined(_M_IX86)
static __forceinline uint32_t xgetbv(uint32_t val)
{
 uint32_t res_lo;
 __asm
 {
  mov ecx, val
  _asm _emit 0x0F _asm _emit 0x01 _asm _emit 0xD0
  mov res_lo, eax
 }
 return res_lo;
}
#else
extern uint32_t xgetbv_impl(uint32_t val);
#define xgetbv xgetbv_impl
#endif

#endif /* _M_IX86 || _M_X64 */

#elif defined(__GNUC__)

#if defined(__i386__) || defined(__amd64__)
#define ARCH_INTEL
static __inline uint32_t xgetbv(uint32_t val)
{
 register uint32_t res_lo;
 asm volatile (".byte 0x0F, 0x01, 0xD0\n\t" : "=a"(res_lo) : "c"(val) : "%edx");
 return res_lo;
}

static __inline void cpuid(uint32_t *out, uint32_t eax, uint32_t ecx)
{
#if defined(__PIC__) && !defined(__amd64__)
 asm ("movl %%ebx, %%esi\n\t"
      "cpuid\n\t"
      "xchgl %%ebx, %%esi\n\t" :
      "=a"(out[0]), "=S"(out[1]), "=c"(out[2]), "=d"(out[3]) : "0"(eax), "2"(ecx));
#else
 asm ("cpuid\n\t" :
      "=a"(out[0]), "=b"(out[1]), "=c"(out[2]), "=d"(out[3]) : "0"(eax), "2"(ecx));
#endif
}
#elif defined(__arm__)
#if defined(linux) || defined(__linux__) || defined(ANDROID)
static struct
{
 const char *name;
 uint32_t flag;
} const features_arm[] =
{
 { "edsp",  CPU_FEAT_EDSP },
 { "vfp",   CPU_FEAT_VFP  },
 { "vfpv3", CPU_FEAT_VFP3 },
 { "neon",  CPU_FEAT_NEON },
 { "asimd", CPU_FEAT_NEON },
 { "fp",    CPU_FEAT_VFP | CPU_FEAT_VFP3 }
};
#define FEATURES_DEF features_arm
#endif
#define ARCH_ARM
#endif

#else

#warning Compiler not supported

#endif

#ifdef FEATURES_DEF
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

static uint32_t parse_feature(char *start, char *end)
{
 int i;
 *end = 0;
 for (i=0; i<sizeof(FEATURES_DEF)/sizeof(FEATURES_DEF[0]); i++)
  if (!strcmp(start, FEATURES_DEF[i].name)) return FEATURES_DEF[i].flag;
 return 0;
}
#endif /* FEATURES_DEF */

static uint32_t get_cpu_features_real()
{
 uint32_t feat = 0;
#if defined(ARCH_INTEL)
 uint32_t out[4];
 uint32_t max_eax;
 uint32_t xcr0 = 0;
 cpuid(out, 0, 0);
 max_eax = out[0];
 if (max_eax >= 1)
 {
  cpuid(out, 1, 0);
  /* edx */
  if (out[3] & 1<<25) feat |= CPU_FEAT_SSE;
  if (out[3] & 1<<26) feat |= CPU_FEAT_SSE2;
  /* ecx */
  if (out[2] & 1<<27) xcr0 = xgetbv(0);
  if (out[2] & 1<<0)  feat |= CPU_FEAT_SSE3;
  if (out[2] & 1<<1)  feat |= CPU_FEAT_PCLMULQDQ;
  if (out[2] & 1<<9)  feat |= CPU_FEAT_SSSE3;
  if (out[2] & 1<<12) feat |= CPU_FEAT_FMA;
  if (out[2] & 1<<19) feat |= CPU_FEAT_SSE41;
  if (out[2] & 1<<20) feat |= CPU_FEAT_SSE42;
  if ((out[2] & 1<<28) && (xcr0 & 6) == 6) feat |= CPU_FEAT_AVX;
  if (out[2] & 1<<30) feat |= CPU_FEAT_RDRAND;
  if (max_eax >= 7)
  {
   cpuid(out, 7, 0);
   /* ebx */
   if (out[1] & 1<<3)  feat |= CPU_FEAT_BMI1;
   if ((out[1] & 1<<5) && (xcr0 & 6) == 6) feat |= CPU_FEAT_AVX2;
   if (out[1] & 1<<8)  feat |= CPU_FEAT_BMI2;
   if (out[1] & 1<<18) feat |= CPU_FEAT_RDSEED;
   if (out[1] & 1<<19) feat |= CPU_FEAT_ADX;
   if (out[1] & 1<<29) feat |= CPU_FEAT_SHA;
  }
 }
#elif defined(FEATURES_DEF)
 char buf[2048];
 int fd = open("/proc/cpuinfo", O_RDONLY);
 if (fd >= 0)
 {
  int cpu_arch = 0;
  int data_size = 0, line_len, pos;
  for (;;)
  {
   int rd_size = read(fd, buf + data_size, sizeof(buf) - data_size);
   if (rd_size <= 0) break;
   data_size += rd_size;
   pos = 0;
   while (pos < data_size)
   {
    char *end = memchr(buf + pos, '\n', data_size - pos);
    if (!end) break;
    line_len = end - (buf + pos);
    if (line_len > 8 && !memcmp(buf + pos, "Features", 8))
    {
     char *p = memchr(buf + pos, ':', line_len);
     if (p)
     {
      char *start = NULL;
      for (p++; p != end; p++)
       if (*p == ' ' || *p == '\t')
       {
        if (start)
        {
         feat |= parse_feature(start, p);
         start = NULL;
        }
       } else
       if (!start) start = p;
      if (start) feat |= parse_feature(start, end);
     }
    } else
    if (line_len > 16 && !memcmp(buf + pos, "CPU architecture", 16))
    {
     char *p = memchr(buf + pos, ':', line_len);
     if (p)
     {
      for (p++; p != end; p++)
       if (*p != ' ' && *p != '\t')
       {
        *end = 0;
        cpu_arch = atoi(p);
        break;
       }
     }
    }
    pos += line_len + 1;
   }
   data_size -= pos;
   memmove(buf, buf + pos, data_size);
  }
  close(fd);
  #ifdef ARCH_ARM
  if (!cpu_arch) cpu_arch = 7; /* assume ARMv7 */
  if (cpu_arch >= 6) feat |= CPU_FEAT_UMAAL;
  #endif
 }
#endif

 return feat;
}

static uint32_t cached_features = ~(uint32_t) 0;
static uint32_t user_mask = 0;

uint32_t get_cpu_features()
{
 if (cached_features == ~(uint32_t) 0)
  cached_features = get_cpu_features_real();
 return cached_features & ~user_mask;
}

void mask_cpu_features(uint32_t mask)
{
 user_mask = mask;
}
