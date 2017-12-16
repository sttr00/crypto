#include <crypto/utils/gen_prime.h>
#include <crypto/rng/std_random.h>
#include <crypto/rng/fake_random.h>
#include <platform/alloca.h>
#include <platform/timestamp.h>
#include <stdio.h>
#include <string.h>

static void print_bytes(const bigint_t num)
{
 int size = bigint_get_byte_count(num);
 uint8_t *out = (uint8_t *) alloca(size);
 bigint_get_bytes_be(num, out, size);
 for (int i=0; i<size; i++)
 {
  printf("%02X ", out[i]);
  if ((i & 15) == 15) putchar('\n');
 }
 if ((size & 15) != 15) putchar('\n');
}

static bool verbose_callback(void *arg, int progress)
{
 switch (progress)
 {
  case PROGRESS_GEN_PRIME:
   putchar('+');
   fflush(stdout);
   break;

  case PROGRESS_CHECK_PRIME:
   putchar('?');
   fflush(stdout);
   break;

  case PROGRESS_FAST_CHECK:
   putchar('.');
   fflush(stdout);
   break;
 }
 return true;
}

int main(int argc, char *argv[])
{
 if (argc < 2)
 {
  printf("Usage: %s options\n"
         "Options:\n"
         "         -b <n>       Generate n-bit prime\n"
         "         -s <value>   Use predictable PRNG with seed <value>\n"
         "         -t           Measure time\n"
         "         -v           Verbose mode\n\n", argv[0]);
  return 1;
 }
 static const unsigned min_bits = 32;
 static const unsigned max_bits = 16384;
 unsigned nbits = ~0u;
 unsigned seed; 
 bool use_seed = false;
 bool measure_time = false;
 int64_t ts_start, ts_end;
 progress_t callback = NULL;
 int last_arg = argc-1;
 int rv;
 for (int i=1; i<=last_arg; i++)
  if (!strcmp(argv[i], "-b"))
  {
   if (i == last_arg)
   {
    arg_required:
    fprintf(stderr, "%s: argument required\n", argv[i]);
    return 2;
   }
   nbits = atoi(argv[++i]);
   if (nbits < min_bits || nbits > max_bits)
   {
    fprintf(stderr, "number of bits must be in range %u to %u\n", min_bits, max_bits);
    return 2;
   }
  } else
  if (!strcmp(argv[i], "-s"))
  {
   if (i == last_arg) goto arg_required;
   seed = atoi(argv[++i]);
   use_seed = true;
  } else
  if (!strcmp(argv[i], "-t"))
  {
   measure_time = true;
  } else
  if (!strcmp(argv[i], "-v"))
  {
   callback = verbose_callback;
  } else
  {
   fprintf(stderr, "%s: unknown option\n", argv[i]);
   return 2;
  }

 if (nbits == ~0u)
 {
  fprintf(stderr, "Set the number of bits with -b <bits>\n");
  return 2;
 }
 
 random_gen *rng;
 if (use_seed)
 {
  fake_random *fr = new fake_random;
  fr->set_seed(seed);
  rng = fr;
 } else rng = new std_random;

 printf("Generating %u-bit probable prime...\n", nbits); 
 ts_start = platform::get_timestamp();
 bigint_t prime = gen_prime(nbits, rng, callback, NULL);
 ts_end = platform::get_timestamp();
 if (callback == verbose_callback) putchar('\n');
 if (prime)
 {
  print_bytes(prime);
  if (measure_time)
   printf("Time: %d ms\n", (int) ((ts_end-ts_start)*1000/platform::timestamp_frequency()));
  bigint_destroy(prime);
  rv = 0;
 } else
 {
  fprintf(stderr, "Failed to generate random number\n");
  rv = 255;
 }
 delete rng;
 return rv;
}
