#ifndef __asn1_encoder_h__
#define __asn1_encoder_h__

#include "element.h"

namespace asn1
{

 size_t calc_encoded_size(element *el);
 size_t get_indef_length_encoded_size(const element *el);
 bool encode_def_length(void *out, size_t &size, const element *el);
 bool encode_indef_length(void *out, size_t &size, const element *el);

}

#endif // __asn1_encoder_h__
