#include <crypto/md5.h>
#include <crypto/sha1.h>
#include <crypto/sha256.h>
#include <crypto/sha512.h>
#include <crypto/sha3.h>
#include <crypto/streebog.h>
#include <platform/file.h>
#include <platform/alloca.h>
#include <platform/timestamp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#define countof(a) (sizeof(a)/sizeof(a[0]))

enum
{
 HASH_ALG_NONE        = 0,
 HASH_ALG_MD5         = 1,
 HASH_ALG_SHA1        = 2,
 HASH_ALG_SHA256      = 8,
 HASH_ALG_SHA384      = 9,
 HASH_ALG_SHA512      = 10,
 HASH_ALG_SHA224      = 11,
 HASH_ALG_SHA3_512    = 12,
 HASH_ALG_SHA3_384    = 13,
 HASH_ALG_SHA3_256    = 14,
 HASH_ALG_SHA3_224    = 15,
 HASH_ALG_STREEBOG512 = 16,
 HASH_ALG_STREEBOG256 = 17
};

typedef struct
{
 unsigned context_size;
 unsigned hash_size;
 unsigned block_size;

 void (*func_init)(void *ctx);
 void (*func_update)(void *ctx, const void *buf, size_t len);
 const void* (*func_final)(void *ctx); 
} HashInfo;

#define DECLARE_HASH_INFO(name, name_prefix, hash_size, block_size) \
 static const HashInfo HashInfo_ ## name = \
 {                                         \
  sizeof(name ## _CTX),                    \
  hash_size,                               \
  block_size,                              \
  name_prefix ## _init,                    \
  name_prefix ## _update,                  \
  name_prefix ## _final                    \
 };

typedef STREEBOG_CTX STREEBOG512_CTX;
typedef STREEBOG_CTX STREEBOG256_CTX;

DECLARE_HASH_INFO(MD5,         md5,         16, 64)
DECLARE_HASH_INFO(SHA1,        sha1,        20, 64)
DECLARE_HASH_INFO(SHA256,      sha256,      32, 64)
DECLARE_HASH_INFO(SHA224,      sha224,      28, 64)
DECLARE_HASH_INFO(SHA512,      sha512,      64, 128)
DECLARE_HASH_INFO(SHA384,      sha384,      48, 128)
DECLARE_HASH_INFO(SHA3_512,    sha3_512,    64, 72)
DECLARE_HASH_INFO(SHA3_384,    sha3_384,    48, 104)
DECLARE_HASH_INFO(SHA3_256,    sha3_256,    32, 136)
DECLARE_HASH_INFO(SHA3_224,    sha3_224,    28, 144)
DECLARE_HASH_INFO(STREEBOG512, streebog512, 64, 64)
DECLARE_HASH_INFO(STREEBOG256, streebog256, 32, 64)

const HashInfo *get_hash_info(int alg)
{
 switch (alg)
 {
  case HASH_ALG_MD5:         return &HashInfo_MD5;
  case HASH_ALG_SHA1:        return &HashInfo_SHA1;
  case HASH_ALG_SHA256:      return &HashInfo_SHA256;
  case HASH_ALG_SHA224:      return &HashInfo_SHA224;
  case HASH_ALG_SHA512:      return &HashInfo_SHA512;
  case HASH_ALG_SHA384:      return &HashInfo_SHA384;
  case HASH_ALG_SHA3_512:    return &HashInfo_SHA3_512;
  case HASH_ALG_SHA3_384:    return &HashInfo_SHA3_384;
  case HASH_ALG_SHA3_256:    return &HashInfo_SHA3_256;
  case HASH_ALG_SHA3_224:    return &HashInfo_SHA3_224;
  case HASH_ALG_STREEBOG512: return &HashInfo_STREEBOG512;
  case HASH_ALG_STREEBOG256: return &HashInfo_STREEBOG256;
 }
 return NULL;
}

static const struct
{
 const char *name;
 int alg;
} hash_def[] =
{
 { "md5",         HASH_ALG_MD5         },
 { "sha1",        HASH_ALG_SHA1        },
 { "sha256",      HASH_ALG_SHA256      },
 { "sha224",      HASH_ALG_SHA224      },
 { "sha512",      HASH_ALG_SHA512      }, 
 { "sha384",      HASH_ALG_SHA384      },
 { "sha3-512",    HASH_ALG_SHA3_512    },
 { "sha3-384",    HASH_ALG_SHA3_384    },
 { "sha3-256",    HASH_ALG_SHA3_256    },
 { "sha3-224",    HASH_ALG_SHA3_224    },
 { "streebog512", HASH_ALG_STREEBOG512 },
 { "streebog256", HASH_ALG_STREEBOG256 }
};

const HashInfo *get_hash_info(int alg);

static const HashInfo *get_hash_by_name(const char *name)
{
 int i;
 for (i = 0; i < countof(hash_def); i++)
  if (!strcmp(name, hash_def[i].name))
   return get_hash_info(hash_def[i].alg);
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

static int hash_file(const HashInfo *hi, const char *filename)
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
 context = alloca(hi->context_size);
 hi->func_init(context);
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
  hi->func_update(context, buf, size);
  total_time += get_timestamp() - ts_start;
 }
 close_file(f);
 print_digest(hi->func_final(context), hi->hash_size);
 if (!opt_brief) printf(" *%s\n", filename); else putchar('\n');
 print_time(total_time);
 return 0;
}

static void hash_string(const HashInfo *hi, const char *text, unsigned rep)
{
 unsigned i;
 int64_t total_time = 0;
 size_t len = strlen(text);
 void *context = alloca(hi->context_size);
 hi->func_init(context);
 for (i = 0; i < rep; i++)
 {
  int64_t ts_start = get_timestamp();
  hi->func_update(context, text, len);
  total_time += get_timestamp() - ts_start;
 }
 print_digest(hi->func_final(context), hi->hash_size); 
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
 for (i = 0; i < countof(hash_def); i++)
 {
  if (i) printf(", ");
  printf(hash_def[i].name);
 }
 putchar('\n');
}

int main(int argc, char *argv[])
{
 int i;
 const HashInfo *hi;
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

 hi = get_hash_info(HASH_ALG_MD5);
 assert(hi);

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
    hi = get_hash_by_name(argv[i]);
    if (!hi)
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
    hash_string(hi, argv[i], rep);
   } else
   if (!strcmp(option, "file"))
   {
    if (++i == argc) goto bad_arg;
    if (hash_file(hi, argv[i])) return 16;
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
  } else hash_file(hi, argv[i]);

 return 0;
}
