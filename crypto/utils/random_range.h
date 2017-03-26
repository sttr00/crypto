#ifndef __random_range_h__
#define __random_range_h__

#include <crypto/rng/random_gen.h>

enum
{
 GRR_FLAG_SECURE  = 1,
 GRR_FLAG_SET_MSB = 2
};

bool get_random_range(void *output, int size, const void *maxval, random_gen *rng, unsigned flags);

#endif // __random_range_h__
