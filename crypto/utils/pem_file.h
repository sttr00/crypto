#ifndef __pem_file_h__
#define __pem_file_h__

#include <string>
#include <stddef.h>

namespace pem_file
{

 enum
 {
  DECODE_ERROR_BAD_PEM_FILE = 1,
  DECODE_ERROR_WRONG_TYPE,
  DECODE_ERROR_BASE64_ERROR
 };

 bool decode(const void *text_data, size_t text_size, void* &bin_data, size_t &bin_size,
             const std::string *required_type, std::string *type, size_t *ppos, int *error);

}

#endif // __pem_file_h__
