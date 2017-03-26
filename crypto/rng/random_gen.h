#ifndef __random_gen_h__
#define __random_gen_h__

#include <platform/word.h>
#include <stddef.h>

class random_gen
{
 public:
  virtual ~random_gen() {}
  virtual bool get_random(void *buf, size_t size) = 0;
  virtual bool get_secure_random(void *buf, size_t size) = 0;
  virtual bool get_uint32(uint32_t &value) = 0;
  virtual bool get_uint64(uint64_t &value) = 0;
  bool get_word(sys_word_t &value)
  {
   #ifdef ENV_64BIT
   return get_uint64(value);
   #else
   return get_uint32(value);
   #endif
  }
};

#endif // __random_gen_h__
