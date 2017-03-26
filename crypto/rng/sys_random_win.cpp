#include "sys_random_win.h"
#include <assert.h>

sys_random::sys_random()
{
 pRtlGenRandom = NULL;
 hprov = NULL;
 lib = LoadLibraryW(L"advapi32.dll");
 if (!lib)
 {
  assert(0);
  return;
 }
 
 pRtlGenRandom = (RtlGenRandom_t) GetProcAddress(lib, "SystemFunction036");
 if (pRtlGenRandom) return;

 pCryptAcquireContext = (CryptAcquireContext_t) GetProcAddress(lib, "CryptAcquireContextW");
 if (!pCryptAcquireContext) goto error;
 
 pCryptGenRandom = (CryptGenRandom_t) GetProcAddress(lib, "CryptGenRandom");
 if (!pCryptGenRandom) goto error;
 
 pCryptReleaseContext = (CryptReleaseContext_t) GetProcAddress(lib, "CryptReleaseContext");
 if (!pCryptReleaseContext) goto error;

 if (!pCryptAcquireContext(&hprov, NULL, NULL, PROV_RSA_FULL, CRYPT_SILENT))
 {
  error:
  assert(0);
  FreeLibrary(lib);
  lib = NULL;
 }
}

sys_random::~sys_random()
{
 if (hprov) pCryptReleaseContext(hprov, 0);
 if (lib) FreeLibrary(lib);
}

bool sys_random::get_random(void *buf, size_t size)
{
 if (pRtlGenRandom) return pRtlGenRandom(buf, (ULONG) size) != 0;
 if (hprov) return pCryptGenRandom(hprov, (ULONG) size, static_cast<BYTE*>(buf)) != 0;
 return false;
}

bool sys_random::get_secure_random(void *buf, size_t size)
{
 return get_random(buf, size);
}

bool sys_random::get_uint32(uint32_t &value)
{
 return get_random(&value, sizeof(value));
}

bool sys_random::get_uint64(uint64_t &value)
{
 return get_random(&value, sizeof(value));
}
