#include <crypto/hash_factory.h>
#include <crypto/oid_const.h>
#include <platform/file.h>
#include <platform/alloca.h>
#include <platform/timestamp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#define countof(a) (sizeof(a)/sizeof(a[0]))

static const struct
{
 const char *name;
 int alg;
} hash_names[] =
{
 { "md5",          ID_HASH_MD5          },
 { "sha1",         ID_HASH_SHA1         },
 { "sha256",       ID_HASH_SHA256       },
 { "sha224",       ID_HASH_SHA224       },
 { "sha512",       ID_HASH_SHA512       },
 { "sha384",       ID_HASH_SHA384       },
 #ifdef CRYPTO_ENABLE_HASH_SHA3
 { "sha3-512",     ID_HASH_SHA3_512     },
 { "sha3-384",     ID_HASH_SHA3_384     },
 { "sha3-256",     ID_HASH_SHA3_256     },
 { "sha3-224",     ID_HASH_SHA3_224     },
 #endif
 #ifdef CRYPTO_ENABLE_HASH_SKEIN256
 { "skein256-128", ID_HASH_SKEIN256_128 },
 { "skein256-160", ID_HASH_SKEIN256_160 },
 { "skein256-224", ID_HASH_SKEIN256_224 },
 { "skein256-256", ID_HASH_SKEIN256_256 },
 #endif
 #ifdef CRYPTO_ENABLE_HASH_SKEIN512
 { "skein512-224", ID_HASH_SKEIN512_224 },
 { "skein512-256", ID_HASH_SKEIN512_256 },
 { "skein512-384", ID_HASH_SKEIN512_384 },
 { "skein512-512", ID_HASH_SKEIN512_512 },
 #endif
 #ifdef CRYPTO_ENABLE_HASH_STREEBOG
 { "streebog512",  ID_HASH_STREEBOG512  },
 { "streebog256",  ID_HASH_STREEBOG256  }
 #endif
};

static const hash_def *get_hash_by_name(const char *name)
{
 int i;
 for (i = 0; i < countof(hash_names); i++)
  if (!strcmp(name, hash_names[i].name))
   return hash_factory(hash_names[i].alg);
 return NULL;
}

static void print_digest(const uint8_t *digest, int len)
{
 int i;
 for (i = 0; i < len; i++) printf("%02X", digest[i]);
}

static int opt_time;
static int opt_brief;

static void print_time(int64_t total_time)
{
 if (opt_time)
  printf("Time: %d ms\n", (int) (total_time*1000/timestamp_frequency()));
}

static int hash_file(const hash_def *hd, const char *filename)
{
 uint8_t buf[0x10000];
 int64_t total_time = 0, ts_start;
 void *context;
 file_t f = open_file(filename);
 if (f == INVALID_FILE)
 {
  fprintf(stderr, "%s: error opening file\n", filename);
  return -1;
 }
 context = alloca(hd->context_size);
 hd->func_init(context);
 for (;;)
 {
  int size = read_file(f, buf, sizeof(buf));
  if (size < 0)
  {
   fprintf(stderr, "%s: read error\n", filename);
   break;
  }
  if (!size) break;
  ts_start = get_timestamp();
  hd->func_update(context, buf, size);
  total_time += get_timestamp() - ts_start;
 }
 close_file(f);
 print_digest(hd->func_final(context), hd->hash_size);
 if (!opt_brief) printf(" *%s\n", filename); else putchar('\n');
 print_time(total_time);
 return 0;
}

static void hash_string(const hash_def *hd, const char *text, unsigned rep)
{
 unsigned i;
 int64_t total_time = 0;
 size_t len = strlen(text);
 void *context = alloca(hd->context_size);
 hd->func_init(context);
 for (i = 0; i < rep; i++)
 {
  int64_t ts_start = get_timestamp();
  hd->func_update(context, text, len);
  total_time += get_timestamp() - ts_start;
 }
 print_digest(hd->func_final(context), hd->hash_size); 
 if (!opt_brief)
 {
  if (rep == 1)
   printf(" \"%s\"\n", text); else
   printf(" \"%s\" x%u\n", text, rep);
 } else putchar('\n');
 print_time(total_time);
}

static void print_algs()
{
 int i;
 printf("Supported hash algorithms: ");
 for (i = 0; i < countof(hash_names); i++)
 {
  if (i) printf(", ");
  printf(hash_names[i].name);
 }
 putchar('\n');
}

int main(int argc, char *argv[])
{
 int i;
 const hash_def *hd;
 unsigned rep = 1;

 if (argc < 2)
 {
  printf("Usage: %s [options...] [files...]\n"
         "Options:\n"
         "          -alg <name>        select hash algorithm\n"
         "          -string <text>     hash string\n"
         "          -file <path>       hash file\n"
         "          -rep <count>       repeat string 'count' times (used before -string)\n"
         "          -brief             print only digest\n"
         "          -time              measure time\n"
         "          -algs              print supported hash algorithms\n\n", argv[0]);
  return 1;
 }

 hd = hash_factory(ID_HASH_MD5);
 assert(hd);

 for (i = 1; i < argc; i++)
  if (argv[i][0] == '-')
  {
   const char *option = argv[i] + 1;
   if (!strcmp(option, "alg"))
   {
    if (++i == argc)
    {
     bad_arg:
     fprintf(stderr, "Option -%s requires an argument\n", option);
     return 2;
    }
    hd = get_hash_by_name(argv[i]);
    if (!hd)
    {
     fprintf(stderr, "Unknown algorithm '%s'\n", argv[i]);
     return 3;
    }
   } else
   if (!strcmp(option, "algs"))
   {
    print_algs();
   } else
   if (!strcmp(option, "string"))
   {
    if (++i == argc) goto bad_arg;
    hash_string(hd, argv[i], rep);
   } else
   if (!strcmp(option, "file"))
   {
    if (++i == argc) goto bad_arg;
    if (hash_file(hd, argv[i])) return 16;
   } else
   if (!strcmp(option, "rep"))
   {
    char *endptr;
    if (++i == argc) goto bad_arg;
    rep = strtoul(argv[i], &endptr, 10);
    if (*endptr)
    {
     fprintf(stderr, "Bad repeat count\n");
     return 4;
    }
   } else
   if (!strcmp(option, "time"))
   {
    opt_time = 1;
   } else
   if (!strcmp(option, "brief"))
   {
    opt_brief = 1;
   } else
   {
    fprintf(stderr, "Option -%s is not supported\n", option);
    return 5;
   }
  } else hash_file(hd, argv[i]);

 return 0;
}
