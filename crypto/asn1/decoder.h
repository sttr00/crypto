#ifndef __asn1_decoder_h__
#define __asn1_decoder_h__

#include "element.h"

namespace asn1
{

 enum
 {
  DECODE_ERROR_NO_DATA                   = 1,
  DECODE_ERROR_INDEFINITE_LENGTH         = 2,
  DECODE_ERROR_TAG_TOO_LARGE             = 3,
  DECODE_ERROR_INVALID_TAG               = 4,
  DECODE_ERROR_TOO_MANY_LENGTH_OCTETS    = 5,
  DECODE_ERROR_CONSTRUCTED_FORM_EXPECTED = 6
 };

 enum
 {
  DECODE_FLAG_ALLOW_INDEF_LENGTH = 1
 };
 
 element *decode(const void *data, size_t size, unsigned flags, int *error);

}

#endif // __asn1_decoder_h__
