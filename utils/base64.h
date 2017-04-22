#ifndef __utils_base64_h__
#define __utils_base64_h__

#include <stddef.h>

namespace base64
{

 enum
 {
  ENCODE_FLAG_NO_PADDING     = 1,
  DECODE_FLAG_IGNORE_PADDING = 1,
  DECODE_FLAG_IGNORE_ERRORS  = 2
 };

 size_t get_encoded_size(const void *data, size_t size);
 size_t get_decoded_size(const void *data, size_t size);
 bool encode(void *out, size_t &out_size, const void *in, size_t in_size, unsigned flags);
 bool decode(void *out, size_t &out_size, const void *in, size_t in_size, unsigned flags);

}

#endif // __utils_base64_h__
