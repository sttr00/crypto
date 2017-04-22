#include "base64.h"
#include <stdint.h>

static const char to_base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const uint8_t from_base64[] =
{
 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x3E, 0x80, 0x80, 0x80, 0x3F,
 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
 0x80, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x80, 0x80, 0x80, 0x80, 0x80,
 0x80, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x80, 0x80, 0x80, 0x80, 0x80
};

static inline uint8_t decode_char(char ch)
{
 return from_base64[(~(unsigned) (int) (signed char) ch >> ((sizeof(unsigned)-1)*8)) & ch];
}

bool base64::decode(void *out, size_t &out_size, const void *in, size_t in_size, unsigned flags)
{
 if (!in_size)
 {
  out_size = 0;
  return true;
 }
 const char *in_buf = static_cast<const char*>(in);
 uint8_t *out_buf = static_cast<uint8_t*>(out);
 int rem;
 if (in_size & 3)
 {
  if (!(flags & base64::DECODE_FLAG_IGNORE_PADDING)) return false;
  rem = in_size & 3;
  in_size -= rem;
 } else
 {
  rem = 4;
  if (in_buf[in_size-1] == '=')
  {
   rem--;
   if (in_buf[in_size-2] == '=') rem--;
  }
  rem &= 3;
  if (rem) in_size -= 4;
 }
 size_t required_size = 3*(in_size >> 2);
 if (required_size > out_size) return false;
 out_size -= required_size;
 uint8_t result = 0;
 for (size_t i = 0; i < in_size;)
 {
  uint8_t b1 = decode_char(in_buf[i++]);
  uint8_t b2 = decode_char(in_buf[i++]);
  uint8_t b3 = decode_char(in_buf[i++]);
  uint8_t b4 = decode_char(in_buf[i++]);
  result |= b1 | b2 | b3 | b4;
  b2 &= 0x7F;
  b3 &= 0x7F;
  b4 &= 0x7F;
  *out_buf++ = b1<<2 | b2>>4;
  *out_buf++ = b2<<4 | b3>>2;
  *out_buf++ = b3<<6 | b4;
 }
 if (!(flags & base64::DECODE_FLAG_IGNORE_ERRORS) && rem == 1) return false;
 if (rem > 1)
 {
  if (!out_size) return false;
  out_size--;
  uint8_t b1 = decode_char(in_buf[in_size]);
  uint8_t b2 = decode_char(in_buf[in_size + 1]);
  result |= b1 | b2;
  b2 &= 0x7F;
  *out_buf++ = b1<<2 | b2>>4;
  if (rem == 3)
  {
   if (!out_size) return false;
   uint8_t b3 = decode_char(in_buf[in_size + 2]);
   result |= b3;
   b3 &= 0x7F;
   *out_buf++ = b2<<4 | b3>>2;
  }
 }
 out_size = out_buf - static_cast<uint8_t*>(out);
 if (!(flags & base64::DECODE_FLAG_IGNORE_ERRORS) && (result & 0x80)) return false;
 return true;
}

bool base64::encode(void *out, size_t &out_size, const void *in, size_t in_size, unsigned flags)
{
 if (!in_size)
 {
  out_size = 0;
  return true;
 }
 size_t required_size = (in_size/3) << 2;
 if (required_size > out_size) return false;
 const uint8_t *in_buf = static_cast<const uint8_t*>(in);
 char *out_buf = static_cast<char*>(out);
 int rem = in_size % 3;
 in_size -= rem;
 for (size_t i = 0; i < in_size;)
 {
  uint8_t b1 = in_buf[i++];
  uint8_t b2 = in_buf[i++];
  uint8_t b3 = in_buf[i++];
  *out_buf++ = to_base64[b1 >> 2];
  *out_buf++ = to_base64[((b1 << 4) & 63) | b2 >> 4];
  *out_buf++ = to_base64[((b2 << 2) & 63) | b3 >> 6];
  *out_buf++ = to_base64[b3 & 63];
 }
 if (rem)
 {
  size_t pad_len;
  if (out_size < 2) return false;
  out_size -= 2;
  uint8_t b1 = in_buf[in_size];
  *out_buf++ = to_base64[b1 >> 2];
  if (rem == 1)
  {   
   *out_buf++ = to_base64[(b1 << 4) & 63];
   pad_len = 2;
  } else
  {
   if (!out_size) return false;
   out_size--;
   uint8_t b2 = in_buf[in_size + 1];
   *out_buf++ = to_base64[((b1 << 4) & 63) | b2 >> 4];
   *out_buf++ = to_base64[(b2 << 2) & 63];
   pad_len = 1;
  }
  if (!(flags & ENCODE_FLAG_NO_PADDING))
  {
   if (out_size < pad_len) return false;
   *out_buf++ = '=';
   if (pad_len == 2) *out_buf++ = '=';
  }
 }
 out_size = out_buf - static_cast<char*>(out);
 return true;
}

size_t base64::get_encoded_size(const void *data, size_t size)
{
 size_t out_size = (size/3) << 2;
 if (size % 3) out_size += 4;
 return out_size;
}

size_t base64::get_decoded_size(const void *data, size_t size)
{
 const char *str = static_cast<const char*>(data);
 if (size && str[size-1] == '=') size--;
 if (size && str[size-1] == '=') size--;
 size_t out_size = 3*(size >> 2);
 size_t rem = size & 3;
 if (rem >= 2) out_size += rem-1;
 return out_size;
}
