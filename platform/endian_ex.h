#ifndef __platform_endian_ex_h__
#define __platform_endian_ex_h__

#include "endian.h"
#include "byteswap.h"

#ifdef __LITTLE_ENDIAN__
#define VALUE_LE16
#define VALUE_LE32
#define VALUE_LE64
#define VALUE_BE16 SWAP16
#define VALUE_BE32 SWAP32
#define VALUE_BE64 SWAP64
#else
#define VALUE_LE16 SWAP16
#define VALUE_LE32 SWAP32
#define VALUE_LE64 SWAP64
#define VALUE_BE16
#define VALUE_BE32
#define VALUE_BE64
#endif

#endif /* __platform_endian_ex_h__ */
