#ifndef __ec_common_h__
#define __ec_common_h__

#include <bigint/bigint.h>

typedef struct
{
 bigint_t x;
 bigint_t y;
 bigint_t z;
} ec_point_t;

typedef struct
{
 bigint_t x;
 bigint_t z;
} ec_xz_point_t;

typedef struct
{
 bigint_t x;
 bigint_t y;
 bigint_t z;
 bigint_t t;
} ec_ext_point_t;

typedef struct
{
 bigint_t v[13];
 #ifndef NDEBUG
 int max_alloc;
 #endif
} ec_scratch_t;

#endif
