#ifndef __std_random_h__
#define __std_random_h__

#include "random_gen.h"
#include "sys_random.h"
#include "isaac.h"

class std_random: public random_gen
{
 public:
  std_random();
  virtual bool get_random(void *buf, size_t size);
  virtual bool get_secure_random(void *buf, size_t size);
  virtual bool get_uint32(uint32_t &value);
  virtual bool get_uint64(uint64_t &value);

 protected:
  static const unsigned BUF_WORDS = 256;
  static const unsigned BUF_BYTES = BUF_WORDS*4;
  typedef union
  {
   uint32_t   w[BUF_WORDS];
   uint8_t    b[BUF_BYTES];
   sys_word_t sw[BUF_BYTES/sizeof(sys_word_t)];
   uint64_t   u64[BUF_BYTES/8];
  } isaac_buf_t;
  isaac_buf_t buf;
  ISAAC_CTX ctx;
  bool has_isaac_output;
  unsigned ptr;  
  sys_random sys;
  #ifdef _WIN32
  void *query_sys_info_func;
  void *sys_info_buf;
  #endif

  void init();
  void hash_entropy(void *ctx, bool first);
};

#endif // __std_random_h__
