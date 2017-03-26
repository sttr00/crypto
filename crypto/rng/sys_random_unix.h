#ifndef __sys_random_unix_h__
#define __sys_random_unix_h__

#include "random_gen.h"

class sys_random: public random_gen
{
 public:
  sys_random();
  virtual ~sys_random();
  virtual bool get_random(void *buf, size_t size);
  virtual bool get_secure_random(void *buf, size_t size);
  virtual bool get_uint32(uint32_t &value);
  virtual bool get_uint64(uint64_t &value);
  void set_device_name(const char *file_name) { device_name = file_name; }

 protected:
  int fd;
  const char *device_name;

  sys_random(const sys_random &) = delete;
  sys_random& operator=(const sys_random &) = delete;
  bool open_device();
};


#endif // __sys_random_unix_h__
