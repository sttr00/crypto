#ifndef __sys_random_win_h__
#define __sys_random_win_h__

#include "random_gen.h"
#include <winsock2.h>
#include <windows.h>

class sys_random: public random_gen
{
 public:
  sys_random();
  virtual ~sys_random();
  virtual bool get_random(void *buf, size_t size);
  virtual bool get_secure_random(void *buf, size_t size);
  virtual bool get_uint32(uint32_t &value);
  virtual bool get_uint64(uint64_t &value);

 protected:
  typedef BOOL (WINAPI *CryptAcquireContext_t)(ULONG_PTR *phProv, LPCWSTR pszContainer, LPCWSTR pszProvider, DWORD dwProvType, DWORD dwFlags);
  typedef BOOL (WINAPI *CryptGenRandom_t)(ULONG_PTR hProv, DWORD dwLen, BYTE* pbBuffer);
  typedef BOOL (WINAPI *CryptReleaseContext_t)(ULONG_PTR hProv, DWORD dwFlags);
  typedef BOOL (WINAPI *RtlGenRandom_t)(PVOID buf, ULONG size);

  HMODULE lib;
  ULONG_PTR hprov;
  CryptAcquireContext_t pCryptAcquireContext;
  CryptGenRandom_t pCryptGenRandom;
  CryptReleaseContext_t pCryptReleaseContext;
  RtlGenRandom_t pRtlGenRandom;

  sys_random(const sys_random &) = delete;
  sys_random& operator=(const sys_random &) = delete;
};

#endif // __sys_random_win_h__
