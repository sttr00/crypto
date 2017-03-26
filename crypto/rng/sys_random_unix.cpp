#include "sys_random_unix.h"
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#ifndef CRYPTO_DEFAULT_RANDOM_DEVICE
#define CRYPTO_DEFAULT_RANDOM_DEVICE "/dev/urandom"
#endif

sys_random::sys_random()
{
 fd = -1;
 device_name = CRYPTO_DEFAULT_RANDOM_DEVICE;
}

sys_random::~sys_random()
{
 if (fd >= 0) close(fd);
}

bool sys_random::get_random(void *buf, size_t size)
{
 if (fd < 0 && !open_device()) return false;
 while (size)
 {
  ssize_t rv = read(fd, buf, size);
  if (rv < 0) return false;
  size -= rv;
  buf = (uint8_t *) buf + rv;
 }
 return true;
}

bool sys_random::get_secure_random(void *buf, size_t size)
{
 return get_random(buf, size);
}

bool sys_random::get_uint32(uint32_t &value)
{
 return get_random(&value, sizeof(value));
}

bool sys_random::get_uint64(uint64_t &value)
{
 return get_random(&value, sizeof(value));
}

bool sys_random::open_device()
{
 int flags = O_RDONLY;
 #ifdef O_CLOEXEC
 flags |= O_CLOEXEC;
 #endif
 fd = open(device_name, flags);
 if (fd < 0) return false;
 #ifndef O_CLOEXEC
 fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
 #endif
 return true;
}
