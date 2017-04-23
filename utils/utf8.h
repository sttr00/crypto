#ifndef __utf8_h__
#define __utf8_h__

#include <stdint.h>
#include <stddef.h>
#include <platform/bits.h>

#ifdef __cplusplus
namespace utf8
{
#endif

typedef uint16_t uchar16_t;
typedef uint32_t uchar32_t;

enum
{
 UTF8_ERROR_UNEXPECTED_END = 1,
 UTF8_ERROR_BAD_ENCODING,
 UTF8_ERROR_INVALID_BYTE_COUNT,
 UTF8_ERROR_OVERLONG_ENCODING,
 UTF8_ERROR_UNASSIGNED_CODE,
 UTF8_ERROR_SURROGATE,
 UTF8_ERROR_BUFFER_TOO_SMALL
};

static __inline int utf8_to_uc32(uchar32_t *out, const void *in, size_t *size, uchar32_t err_char)
{
 size_t in_size = *size;
 size_t count;
 const uint8_t *data = (const uint8_t *) in;
 if (!(data[0] & 0x80))
 {
  *out = data[0];
  *size = 1;
  return 0;
 }
 count = clz32(data[0] ^ 0xFF) - 24;
 if (count > in_size)
 {
  *out = err_char;
  *size = in_size;
  return UTF8_ERROR_UNEXPECTED_END;
 }
 *size = count;
 switch (count)
 {
  case 2:
   *out = (data[0] & 0x1F)<<6 | (data[1] & 0x3F); 
   if (!(data[1] & 0x80)) return UTF8_ERROR_BAD_ENCODING;
   if (*out < 0x80) return UTF8_ERROR_OVERLONG_ENCODING;
   break;
  case 3:
   *out = (data[0] & 0xF)<<12 | (data[1] & 0x3F)<<6 | (data[2] & 0x3F);
   if (!(data[1] & data[2] & 0x80)) return UTF8_ERROR_BAD_ENCODING;
   if (*out < 0x800) return UTF8_ERROR_OVERLONG_ENCODING;
   if ((*out & 0xF800) == 0xD800) return UTF8_ERROR_SURROGATE;
   break;
  case 4:
   *out = (data[0] & 0x7)<<18 | (data[1] & 0x3F)<<12 | (data[2] & 0x3F)<<6 | (data[3] & 0x3F);   
   if (!(data[1] & data[2] & data[3] & 0x80)) return UTF8_ERROR_BAD_ENCODING;
   if (*out < 0x10000) return UTF8_ERROR_OVERLONG_ENCODING;
   if (*out > 0x10FFFF) return UTF8_ERROR_UNASSIGNED_CODE;
   break;
  default:
   *out = err_char;
   return UTF8_ERROR_INVALID_BYTE_COUNT;
 }
 return 0;
}

static __inline size_t utf8_char_count(const void *in, size_t size)
{
 size_t result;
 const uint8_t *data = (const uint8_t *) in;
 if (!size) return 0;
 result = 0;
 for (;;)
 {
  size_t count = clz32(*data ^ 0xFF) - 24;  
  result++;
  if (count >= size) break;
  size -= count;
  data += count;
 }
 return result;
}

static __inline int uc32_to_utf8(void *out, size_t *size, uchar32_t in, char err_char)
{
 size_t out_size = *size;
 uint8_t *data = (uint8_t *) out;
 if (in < 0x80)
 {
  if (!out_size) return UTF8_ERROR_BUFFER_TOO_SMALL;
  data[0] = in;
  *size = 1;
  return 0;
 }
 if (in < 0x800)
 {
  if (out_size < 2) { *size = 0; return UTF8_ERROR_BUFFER_TOO_SMALL; }
  data[0] = 0xC0 | in>>6;
  data[1] = 0x80 | (in & 0x3F);
  *size = 2;
  return 0;
 }
 if (in < 0x10000)
 {
  if (out_size < 3) { *size = 0; return UTF8_ERROR_BUFFER_TOO_SMALL; }
  data[0] = 0xE0 | in>>12;
  data[1] = 0x80 | ((in>>6) & 0x3F);
  data[2] = 0x80 | (in & 0x3F);
  *size = 3;
  return 0;
 }
 if (in < 0x110000)
 {
  if (out_size < 4) { *size = 0; return UTF8_ERROR_BUFFER_TOO_SMALL; }
  data[0] = 0xF0 | in>>18;
  data[1] = 0x80 | ((in>>12) & 0x3F);
  data[2] = 0x80 | ((in>>6) & 0x3F);
  data[3] = 0x80 | (in & 0x3F);
  *size = 4;
  return 0;
 }
 if (!out_size) return UTF8_ERROR_BUFFER_TOO_SMALL;
 data[0] = err_char;
 *size = 1;
 return UTF8_ERROR_UNASSIGNED_CODE;
}

static __inline size_t utf8_byte_count(uchar32_t ch)
{
 if (ch < 0x80) return 1;
 if (ch < 0x800) return 2;
 if (ch < 0x10000) return 3;
 if (ch < 0x110000) return 4;
 return 1;
}

#ifdef __cplusplus
}
#endif

#endif /* __utf8_h__ */
