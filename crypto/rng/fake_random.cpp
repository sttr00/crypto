#include "fake_random.h"
#include <string.h>

fake_random::fake_random()
{
 set_seed(0);
}

void fake_random::set_seed(uint32_t seed)
{
 uint32_t r[BUF_WORDS];
 r[0] = seed;
 memset(r + 1, 0, BUF_BYTES - 4);
 isaac_init(&ctx, r);
 isaac_process(&ctx, buf.w);
 ptr = 0;
}

bool fake_random::get_random(void *out, size_t size)
{
 while (size)
 {
  unsigned used_size = BUF_BYTES - ptr;
  if (used_size > size)
  {
   memcpy(out, buf.b + ptr, size);
   ptr += (unsigned) size;
   break;
  }
  memcpy(out, buf.b + ptr, used_size);
  out = static_cast<uint8_t*>(out) + used_size;
  ptr += used_size;
  if (ptr == BUF_BYTES)
  {
   isaac_process(&ctx, buf.w);
   ptr = 0;
  }
  size -= used_size;
 }
 return true;
}

bool fake_random::get_secure_random(void *buf, size_t size)
{
 return get_random(buf, size);
}

bool fake_random::get_uint32(uint32_t &value)
{
 return get_random(&value, sizeof(value));
}

bool fake_random::get_uint64(uint64_t &value)
{
 return get_random(&value, sizeof(value));
}
