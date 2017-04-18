#include "std_random.h"
#include <crypto/sha512.h>
#include <platform/arch.h>
#include <platform/unaligned.h>
#include <cpuid/cpu_features.h>
#include <string.h>
#include <assert.h>

#if defined(unix) || defined(__unix__)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#if defined(linux) || defined(__linux__)
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <errno.h>
#endif
#endif

typedef SHA512_CTX HASH_CTX;
static const unsigned HASH_SIZE = 64;

#define hash_init   sha512_init
#define hash_update sha512_update
#define hash_final  sha512_final

#define countof(a) (sizeof(a)/sizeof(a[0]))

#if defined(ARCH_X86) || defined(ARCH_X86_64)
#include <platform/tsc.h>
extern "C" int do_rdrand(sys_word_t *result);
extern "C" int do_rdseed(sys_word_t *result);
#endif

#ifdef _WIN32
typedef NTSTATUS (WINAPI *NtQuerySystemInformation_t)(int SystemInformationClass,
 void *SystemInformation, ULONG SystemInformationLength, ULONG *ReturnLength);
static const int SYS_INFO_SIZE = 0x10000;
enum
{
 SystemPerformanceInformation          = 0x02,
 SystemTimeOfDayInformation            = 0x03,
 SystemProcessInformation              = 0x05,
 SystemProcessorPerformanceInformation = 0x08,
 SystemPageFileInformation             = 0x12,
 SystemFileCacheInformation            = 0x15,
 SystemInterruptInformation            = 0x17,
 SystemExceptionInformation            = 0x21,
 SystemContextSwitchInformation        = 0x24,
 SystemProcessorIdleInformation        = 0x2A,
 SystemLookasideInformation            = 0x2D,
 SystemProcessorPowerInformation       = 0x3D,
 SystemProcessorCycleTimeInformation   = 0x6C
};

struct _SYSTEM_TIMEOFDAY_INFORMATION
{
 LARGE_INTEGER BootTime;
 LARGE_INTEGER CurrentTime;
 LARGE_INTEGER TimeZoneBias;
 ULONG TimeZoneId;
 ULONG Reserved;
 ULONGLONG BootTimeBias;
 ULONGLONG SleepTimeBias;
};
#endif

#if defined(unix) || defined(__unix__)
static bool get_sys_random(void *buf, size_t size)
{
 #if (defined(linux) || defined(__linux__)) && defined(__NR_getrandom)
 long result = syscall(__NR_getrandom, buf, size, 0);
 if (result == size) return true;
 if (result < 0 && errno != ENOSYS) return false;
 #endif
 sys_random rng;
 return rng.get_random(buf, size);
}
#endif

std_random::std_random()
{
 #ifdef _WIN32
 query_sys_info_func = NULL;
 sys_info_buf = NULL;
 #endif
 has_isaac_output = false;
 init();
}

void std_random::hash_entropy(void *ctx, bool first)
{
 #ifdef _WIN32
 if (!query_sys_info_func)
 {
  HMODULE mod = GetModuleHandleW(L"ntdll.dll");
  if (mod) query_sys_info_func = GetProcAddress(mod, "NtQuerySystemInformation");
  if (!query_sys_info_func) query_sys_info_func = (void *) -1;
 }
 #endif

 #if defined(ARCH_X86) || defined(ARCH_X86_64)
 uint32_t cpu_features = get_cpu_features();
 #endif

 if (has_isaac_output)
 {
  hash_update(ctx, buf.b, sizeof(buf));
  has_isaac_output = false;
 }

 #if defined(ARCH_X86) || defined(ARCH_X86_64)
 uint64_t tsc = read_tsc();
 hash_update(ctx, &tsc, sizeof(tsc));
 if (cpu_features & CPU_FEAT_RDRAND)
 {
  sys_word_t rand;
  for (int attempt = 0; attempt < 10; attempt++)
   if (do_rdrand(&rand)) break;
  hash_update(ctx, &rand, sizeof(rand));
 }
 if (cpu_features & CPU_FEAT_RDSEED)
 {
  sys_word_t rand;
  for (int attempt = 0; attempt < 10; attempt++)
   if (do_rdseed(&rand)) break;
  hash_update(ctx, &rand, sizeof(rand));
 }
 #endif

 #ifdef _WIN32
 LARGE_INTEGER perf;
 if (QueryPerformanceCounter(&perf))
  hash_update(ctx, &perf, sizeof(perf));   
 FILETIME ft;
 GetSystemTimeAsFileTime(&ft);
 hash_update(ctx, &ft, sizeof(ft));
 #endif
 #if defined(unix) || defined(__unix__)
 timespec ts;
 if (!clock_gettime(CLOCK_MONOTONIC, &ts))
  hash_update(ctx, &ts, sizeof(ts));
 if (!clock_gettime(CLOCK_REALTIME, &ts))
  hash_update(ctx, &ts, sizeof(ts));
 timeval tv;
 gettimeofday(&tv, NULL);
 hash_update(ctx, &tv, sizeof(tv));
 #endif
 #ifdef _WIN32
 if (first)
 {
  uint32_t val = GetCurrentThreadId();
  hash_update(ctx, &val, sizeof(val));
  val = GetCurrentProcessId();
  hash_update(ctx, &val, sizeof(val));
 }
 FILETIME ftt[4];
 if (GetThreadTimes(GetCurrentThread(),   ftt, ftt+1, ftt+2, ftt+3))
  hash_update(ctx, ftt, sizeof(ftt));
 if (GetProcessTimes(GetCurrentProcess(), ftt, ftt+1, ftt+2, ftt+3))
  hash_update(ctx, ftt, sizeof(ftt));
 if (query_sys_info_func && query_sys_info_func != (void *) -1)
 {
  if (!sys_info_buf) sys_info_buf = ::operator new(SYS_INFO_SIZE);
  static const int types[] =
  {
   SystemPerformanceInformation, SystemTimeOfDayInformation, SystemProcessorPerformanceInformation,
   SystemInterruptInformation,   SystemExceptionInformation, SystemLookasideInformation,
   SystemContextSwitchInformation, SystemProcessorIdleInformation, SystemProcessorCycleTimeInformation,
   // only first time
   SystemPageFileInformation, SystemFileCacheInformation, SystemProcessorPowerInformation,
  };
  int count = countof(types);
  if (!first) count -= 3;
  for (int i=0; i<count; i++)
  {
   ULONG out_size = 0;
   ULONG in_size = types[i] == SystemTimeOfDayInformation? sizeof(_SYSTEM_TIMEOFDAY_INFORMATION) : SYS_INFO_SIZE;
   NTSTATUS status = ((NtQuerySystemInformation_t) query_sys_info_func)(types[i], sys_info_buf, in_size, &out_size);
   if (!status) hash_update(ctx, sys_info_buf, out_size);
  }
 }
 #endif

 #if defined(unix) || defined(__unix__)
 if (first)
 {
  pid_t val = getpid();
  hash_update(ctx, &val, sizeof(val));
  uint8_t buf[32];
  if (get_sys_random(buf, sizeof(buf))) hash_update(ctx, buf, sizeof(buf));
 }
 #if defined(linux) || defined(__linux__)
 struct sysinfo sys;
 sysinfo(&sys);
 hash_update(ctx, &sys, sizeof(sys));
 #endif
 #endif
}

bool std_random::get_random(void *out, size_t size)
{
 while (size)
 {
  unsigned used_size = BUF_BYTES - ptr;
  if (used_size > size)
  {
   memcpy(out, buf.b + ptr, size);
   ptr += (unsigned) size;
   break;
  }
  memcpy(out, buf.b + ptr, used_size);
  out = static_cast<uint8_t*>(out) + used_size;
  ptr += used_size;
  if (ptr == BUF_BYTES)
  {
   isaac_process(&ctx, buf.w);
   ptr = 0;
  }
  size -= used_size;
 }
 return true;
}

void std_random::init()
{
 isaac_buf_t tmp;
 bool result = sys.get_secure_random(tmp.b, sizeof(tmp));
 assert(result);
 (void) result;
 HASH_CTX hctx;
 bool first = true;
 for (unsigned ptr = 0; ptr < BUF_BYTES; ptr += HASH_SIZE)
 {
  hash_init(&hctx);
  hash_entropy(&hctx, first);
  hash_update(&hctx, buf.b, ptr);
  memcpy(buf.b + ptr, hash_final(&hctx), HASH_SIZE);
  first = false;
 }
 #ifdef _WIN32
 ::operator delete(sys_info_buf);
 sys_info_buf = NULL;
 #endif
 for (unsigned i = 0; i < BUF_BYTES/sizeof(sys_word_t); i++) buf.sw[i] ^= tmp.sw[i];
 isaac_init(&ctx, buf.w);
 isaac_process(&ctx, buf.w);
 has_isaac_output = true;
 this->ptr = 0;
}

#ifdef ENV_64BIT
#define put_unaligned_w put_unaligned64
#else
#define put_unaligned_w put_unaligned32
#endif

bool std_random::get_secure_random(void *out, size_t size)
{
 #ifndef HAVE_UNALIGNED_ACCESS
 static const int TEMP_BUF_SIZE = 512;
 union
 {
  sys_word_t sw[TEMP_BUF_SIZE/sizeof(sys_word_t)];
  uint8_t b[TEMP_BUF_SIZE];
 } temp;
 size_t size_rem;
 #endif
 ptr = (ptr + sizeof(sys_word_t) - 1) & ~(sizeof(sys_word_t) - 1);
 if (ptr >= BUF_BYTES)
 {
  isaac_process(&ctx, buf.w);
  ptr = 0;
 }
 #ifdef HAVE_UNALIGNED_ACCESS
 if (!sys.get_secure_random(out, size)) return false;
 while (size >= sizeof(sys_word_t))
 {
  *((sys_word_t *) out) ^= buf.sw[ptr/sizeof(sys_word_t)];
  ptr += sizeof(sys_word_t);
  if (ptr == BUF_BYTES)
  {
   isaac_process(&ctx, buf.w);
   ptr = 0;
  }
  out = (uint8_t *) out + sizeof(sys_word_t);
  size -= sizeof(sys_word_t);
 }
 for (size_t i = 0; i < size; i++)
  ((uint8_t *) out)[i] ^= buf.b[ptr + i];
 ptr += size;
 #else 
 while (size >= TEMP_BUF_SIZE)
 {
  if (!sys.get_secure_random(temp.sw, TEMP_BUF_SIZE)) return false;
  for (size_t i = 0; i < TEMP_BUF_SIZE; i += sizeof(sys_word_t))
  {
   put_unaligned_w(out, temp.sw[i/sizeof(sys_word_t)] ^ buf.sw[ptr/sizeof(sys_word_t)]);
   ptr += sizeof(sys_word_t);
   if (ptr == BUF_BYTES)
   {
    isaac_process(&ctx, buf.w);
    ptr = 0;
   }
   out = (sys_word_t *) out + 1;
  }
  size -= TEMP_BUF_SIZE;
 }
 size_rem = size & (sizeof(sys_word_t) - 1);
 size -= size_rem;
 if (size)
 {
  if (!sys.get_secure_random(temp.sw, size)) return false;
  for (size_t i = 0; i < size; i += sizeof(sys_word_t))
  {
   put_unaligned_w(out, temp.sw[i/sizeof(sys_word_t)] ^ buf.sw[ptr/sizeof(sys_word_t)]);
   ptr += sizeof(sys_word_t);
   if (ptr == BUF_BYTES)
   {
    isaac_process(&ctx, buf.w);
    ptr = 0;
   }
   out = (sys_word_t *) out + 1;
  }
 }
 if (size_rem)
 {
  if (!sys.get_secure_random(temp.b, size_rem)) return false;
  for (size_t i = 0; i < size_rem; i++)
   ((uint8_t *) out)[i] = temp.b[i] ^ buf.b[ptr + i];
  ptr += (unsigned) size_rem;
 }
 #endif
 return true;
}

bool std_random::get_uint32(uint32_t &value)
{
 ptr = (ptr + 3) & ~3;
 if (ptr >= BUF_BYTES)
 {
  isaac_process(&ctx, buf.w);
  value = buf.w[0];
  ptr = 4;
 } else
 {
  value = buf.w[ptr/4];
  ptr += 4;
  if (ptr == BUF_BYTES)
  {
   isaac_process(&ctx, buf.w);
   ptr = 0;
  }
 }
 return true;
}

bool std_random::get_uint64(uint64_t &value)
{
 ptr = (ptr + 7) & ~7;
 if (ptr >= BUF_BYTES)
 {
  isaac_process(&ctx, buf.w);
  value = buf.u64[0];
  ptr = 8;
 } else
 {
  value = buf.u64[ptr/8];
  ptr += 8;
  if (ptr == BUF_BYTES)
  {
   isaac_process(&ctx, buf.w);
   ptr = 0;
  }
 }
 return true;
}
