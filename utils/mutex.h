#ifndef __utils_mutex_h__
#define __utils_mutex_h__

#include <platform/mutex.h>

class mutex
{
 public:
  mutex() { platform::mutex_init(&m); }
  ~mutex() { platform::mutex_destroy(&m); }
  void lock() { platform::mutex_lock(&m); }
  void unlock() { platform::mutex_unlock(&m); }

 private:
  mutex(const mutex &src) = delete;
  mutex& operator= (const mutex &src) = delete;

  platform::mutex_t m;
};

class mutex_locker
{
 public:
  mutex_locker(mutex &m): m(m) { m.lock(); }
  ~mutex_locker() { m.unlock(); }

 private:
  mutex &m;
};

#endif // __utils_mutex_h__
