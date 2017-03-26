#ifndef __gen_prime_h__
#define __gen_prime_h__

#include <bigint/bigint.h>
#include <crypto/rng/random_gen.h>

enum
{
 PROGRESS_GEN_PRIME = 1,
 PROGRESS_CHECK_PRIME,
 PROGRESS_FAST_CHECK
};

typedef bool (*progress_t)(void *arg, int progress);

bigint_t gen_prime(unsigned nbits, random_gen *rng, progress_t progress_func, void *progress_arg);

#endif // __gen_prime_h__
