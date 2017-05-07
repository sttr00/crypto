#ifndef __oid_def_h__
#define __oid_def_h__

#include <stdint.h>
#include <stddef.h>

namespace oid
{

 struct oid_def
 {
  const uint8_t *data;
  size_t size;
 };

 const oid_def *get(int id);

}

#endif // __oid_def_h__
