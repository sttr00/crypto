#include "random_range.h"
#include <platform/bits.h>
#include <assert.h>

bool get_random_range(void *output, int size, const void *maxval, random_gen *rng, unsigned flags)
{
 uint8_t *out = static_cast<uint8_t*>(output);
 const uint8_t *in = static_cast<const uint8_t*>(maxval);
 int ptr = 0;
 while (ptr < size && !in[ptr]) out[ptr++] = 0;
 if (ptr == size) return false; 
 bool result;
 if (flags & GRR_FLAG_SECURE)
  result = rng->get_secure_random(out + ptr, size - ptr);
 else
  result = rng->get_random(out + ptr, size - ptr);
 if (!result) return false;
 uint32_t top_word = 0;
 int bytes = 0;
 while (bytes < sizeof(top_word) && ptr + bytes < size)
 {
  top_word = top_word << 8 | in[ptr + bytes];
  bytes++;
 }
 uint32_t top_mask = 0;
 if (flags & GRR_FLAG_SET_MSB)
 {  
  top_mask = 1 << bsr32(top_word);
  top_word ^= top_mask;
  if (!top_word)
  {
   int next_ptr = ptr + bytes;
   while (bytes)
   {
    out[ptr + bytes - 1] = top_mask & 0xFF;
    top_mask >>= 8;
    bytes--;
   }
   assert(top_mask == 0);
   ptr = next_ptr;
   while (ptr < size && !in[ptr]) out[ptr++] = 0;
   if (ptr == size) return false; // number has form 100...0
   while (bytes < sizeof(top_word) && ptr + bytes < size)
   {
    top_word = top_word << 8 | in[ptr + bytes];
    bytes++;
   }
  }
 }
 uint32_t out_word;
 if (flags & GRR_FLAG_SECURE)
  result = rng->get_secure_random(&out_word, sizeof(out_word));
 else
  result = rng->get_uint32(out_word);
 if (!result) return false;
 if (out_word >= top_word) out_word %= top_word;
 out_word |= top_mask;
 while (bytes)
 {
  out[ptr + bytes - 1] = out_word & 0xFF;
  out_word >>= 8;
  bytes--;
 }
 return true;
}
