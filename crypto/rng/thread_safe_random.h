#ifndef __thread_safe_random_h__
#define __thread_safe_random_h__

#include "random_gen.h"
#include <utils/mutex.h>

template<typename RandType>
class thread_safe_random: public random_gen
{
 public:
  virtual ~thread_safe_random() {}
  virtual bool get_random(void *buf, size_t size)
  {
   mutex_locker ml(m);
   return rng.get_random(buf, size);
  }
  virtual bool get_secure_random(void *buf, size_t size)
  {
   mutex_locker ml(m);
   return rng.get_secure_random(buf, size);
  }
  virtual bool get_uint32(uint32_t &value)
  {
   mutex_locker ml(m);
   return rng.get_uint32(value);
  }
  virtual bool get_uint64(uint64_t &value)
  {
   mutex_locker ml(m);
   return rng.get_uint64(value);
  }
  RandType &get_rng() { return rng; }

 private:
  mutex m;
  RandType rng;
};

#endif // __thread_safe_random_h__
