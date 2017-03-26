#ifndef __cpu_features_h__
#define __cpu_features_h__

#include <stdint.h>

enum
{
 /* x86, x86_64 */
 CPU_FEAT_SSE       = 0x00000001,
 CPU_FEAT_SSE2      = 0x00000002,
 CPU_FEAT_SSE3      = 0x00000004,
 CPU_FEAT_PCLMULQDQ = 0x00000008,
 CPU_FEAT_SSSE3     = 0x00000010,
 CPU_FEAT_FMA       = 0x00000020,
 CPU_FEAT_SSE41     = 0x00000040,
 CPU_FEAT_SSE42     = 0x00000080,
 CPU_FEAT_AVX       = 0x00000100,
 CPU_FEAT_RDRAND    = 0x00000200,
 CPU_FEAT_BMI1      = 0x00000400,
 CPU_FEAT_AVX2      = 0x00000800,
 CPU_FEAT_BMI2      = 0x00001000,
 CPU_FEAT_RDSEED    = 0x00002000,
 CPU_FEAT_ADX       = 0x00004000,
 CPU_FEAT_SHA       = 0x00008000,
 /* arm */
 CPU_FEAT_UMAAL     = 0x00100000,
 CPU_FEAT_EDSP      = 0x00200000,
 CPU_FEAT_VFP       = 0x00400000,
 CPU_FEAT_VFP3      = 0x00800000,
 CPU_FEAT_NEON      = 0x01000000
};

#ifdef __cplusplus
extern "C"
{
#endif

uint32_t get_cpu_features();
void mask_cpu_features(uint32_t mask);

#ifdef __cplusplus
}
#endif

#endif /* __cpu_features_h__ */
