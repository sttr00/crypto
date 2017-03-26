#ifndef __fake_random_h__
#define __fake_random_h__

#include "random_gen.h"
#include "isaac.h"

class fake_random: public random_gen
{
 public:
  fake_random();
  void set_seed(uint32_t seed);
  virtual bool get_random(void *buf, size_t size);
  virtual bool get_secure_random(void *buf, size_t size);
  virtual bool get_uint32(uint32_t &value);
  virtual bool get_uint64(uint64_t &value);

 protected:
  static const unsigned BUF_WORDS = 256;
  static const unsigned BUF_BYTES = BUF_WORDS*4;
  union
  {
   uint32_t w[BUF_WORDS];
   uint8_t  b[BUF_BYTES];
  } buf;
  ISAAC_CTX ctx;
  unsigned ptr;
};

#endif // __fake_random_h__
