#include "../common/file_utils.h"
#include <crypto/oid_const.h>
#include <crypto/asn1/encoder.h>
#include <crypto/asn1/decoder.h>
#include <crypto/pkc/pkc_rsa.h>
#include <crypto/rng/std_random.h>
#include <utils/str_int_cvt.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#define countof(a) (sizeof(a)/sizeof(a[0]))

enum
{
 ACTION_NONE,
 ACTION_POWER_PUB,
 ACTION_POWER_PRIV,
 ACTION_CERT_VERIFY,
 ACTION_CERT_SIGN
};

static const int MAX_SIGN_PARAMS = 10;

static bool verify_certificate(const void *data, size_t size, const pkc_base &pk, bool &verify_result)
{
 verify_result = false;
 asn1::element *root = asn1::decode(data, size, 0, nullptr);
 if (!root) return false;
 bool result = false;
 if (root->is_sequence())
 {
  const asn1::element *tbs_cert = root->child;
  if (tbs_cert)
  {
   const asn1::element *sig_alg = tbs_cert->sibling;
   if (sig_alg && sig_alg->is_sequence())
   {
    const asn1::element *sig = sig_alg->sibling;
    if (sig && sig->is_aligned_bit_string())
    {
     result = true;
     verify_result = pk.verify_signature(sig->data + 1, sig->size - 1,
      root->data, tbs_cert->size + (tbs_cert->data - root->data), sig_alg);
    }
   }
  }
 }
 asn1::delete_tree(root);
 return result;
}

static void *encode_asn1(asn1::element *el, size_t &size)
{
 size_t buf_size = asn1::calc_encoded_size(el);
 void *out = operator new(buf_size);
 size = buf_size;
 if (!asn1::encode_def_length(out, size, el))
 {
  assert(0);
  return nullptr;
 }
 assert(size == buf_size);
 return out;
}

static bool sign_certificate(void* &out_data, size_t &out_size, const void *data, size_t size,
                             const pkc_rsa &rsa, const pkc_base::param_data params[], int param_count)
{
 out_data = nullptr;
 out_size = 0;
 asn1::element *root = asn1::decode(data, size, 0, nullptr);
 if (!root) return false;
 
 bool parse_result = false;
 asn1::element *old_sign_alg, *old_sign_alg_tbs, *tbs_cert, *signature;
 if (root->is_sequence())
 {
  tbs_cert = root->child;
  if (tbs_cert)
  {
   old_sign_alg = tbs_cert->sibling;
   if (old_sign_alg && old_sign_alg->is_sequence())
   {
    signature = old_sign_alg->sibling;
    if (signature && signature->is_aligned_bit_string())
    {
     asn1::element *child = tbs_cert->child;
     asn1::element *serial = child;
     if (child && child->cls == asn1::CLASS_CONTEXT_SPECIFIC && child->tag == 0) serial = child->sibling;
     if (serial)
     {
      old_sign_alg_tbs = serial->sibling;
      if (old_sign_alg_tbs && old_sign_alg_tbs->is_sequence()) parse_result = true;
     }
    }
   }
  }
 }

 if (!parse_result)
 {
  asn1::delete_tree(root);
  return false;
 }

 asn1::element *el_params = rsa.create_params_struct(params, param_count, pkc_base::WHERE_SIGNATURE);
 if (!el_params)
 {
  asn1::delete_tree(root);
  return true;
 }

 asn1::element *el_params_tbs = el_params->clone_tree();
 root->replace_child(old_sign_alg, el_params);
 tbs_cert->replace_child(old_sign_alg_tbs, el_params_tbs);
 asn1::delete_tree(old_sign_alg);
 asn1::delete_tree(old_sign_alg_tbs);
 asn1::element *prev_sibling = tbs_cert->sibling;
 tbs_cert->sibling = nullptr;

 size_t encoded_size;
 void *encoded_data = encode_asn1(tbs_cert, encoded_size);
 size_t sign_size = rsa.get_modulus_size();
 uint8_t *sign_data = static_cast<uint8_t*>(alloca(sign_size + 1));
 bool result = rsa.create_signature(sign_data + 1, sign_size, encoded_data, encoded_size, params, param_count);
 operator delete(encoded_data);
 if (!result)
 {
  asn1::delete_tree(root);
  return true;
 }
 
 sign_data[0] = 0;
 signature->data = sign_data;
 signature->size = sign_size + 1;
 tbs_cert->sibling = prev_sibling;
 out_data = encode_asn1(root, out_size);
 asn1::delete_tree(root);
 return true;
}

static const struct
{
 const char *name;
 int alg;
} hash_names[] =
{
 { "md5",         oid::ID_HASH_MD5         },
 { "sha1",        oid::ID_HASH_SHA1        },
 { "sha256",      oid::ID_HASH_SHA256      },
 { "sha224",      oid::ID_HASH_SHA224      },
 { "sha512",      oid::ID_HASH_SHA512      }, 
 { "sha384",      oid::ID_HASH_SHA384      },
 #ifdef CRYPTO_ENABLE_HASH_SHA3
 { "sha3-512",    oid::ID_HASH_SHA3_512    },
 { "sha3-384",    oid::ID_HASH_SHA3_384    },
 { "sha3-256",    oid::ID_HASH_SHA3_256    },
 { "sha3-224",    oid::ID_HASH_SHA3_224    },
 #endif
 #ifdef CRYPTO_ENABLE_HASH_STREEBOG
 { "streebog512", oid::ID_HASH_STREEBOG512 },
 { "streebog256", oid::ID_HASH_STREEBOG256 }
 #endif
};

int get_hash_by_name(const std::string &name)
{
 for (unsigned i = 0; i < countof(hash_names); i++)
  if (name == hash_names[i].name) return hash_names[i].alg;
 return 0;
}

bool process_sign_param(pkc_base::param_data params[], int &param_count, const std::string &s)
{
 if (param_count == MAX_SIGN_PARAMS)
 {
  fprintf(stderr, "Too many parameters\n");
  return false;
 }
 int pos = s.find(':');
 if (pos <= 0)
 {
  fprintf(stderr, "Bad format of param string\n");
  return false;
 }
 std::string pname = s.substr(0, pos);
 int param_type, param_value;
 if (pname == "encoding")
 {
  std::string pval = s.substr(pos+1);
  if (pval == "pkcs1v15")
  { 
   param_value = oid::ID_RSA; 
  } else
  if (pval == "pss")
  {
   param_value = oid::ID_RSASSA_PSS;
  } else
  {
   fprintf(stderr, "Unknown encoding algorithm, try pkcs1v15 or pss\n");
   return false;
  }
  param_type = pkc_rsa::PARAM_WRAPPING_ALG;
 } else
 if (pname == "hash")
 {
  param_value = get_hash_by_name(s.substr(pos+1));
  if (!param_value)
  {
   fprintf(stderr, "Unknown hash algorithm\n");
   return false;
  }
  param_type = pkc_rsa::PARAM_HASH_ALG;
 } else
 if (pname == "mgf")
 {
  if (!(s.substr(pos+1, 5) == "mgf1-" && (param_value = get_hash_by_name(s.substr(pos + 6))) != 0))
  {
   fprintf(stderr, "Unknown mask generation function, try something like mgf1-sha1\n");
   return false;
  }
  param_type = pkc_rsa::PARAM_MGF_HASH_ALG;
 } else
 if (pname == "salt-len")
 {
  bool ok;
  pos++;
  uint32_t value = str_to_uint32(s, &pos, &ok);
  if (!ok)
  {
   fprintf(stderr, "Parameter value must be an integer\n");
   return false;
  }
  if (value >= 0x10000)
  {
   fprintf(stderr, "Bad value of salt length\n");
   return false;
  }
  param_value = value;
  param_type = pkc_rsa::PARAM_SALT;
 } else
 {
  fprintf(stderr, "Unknown parameter %s.\nThe supported parameters are: encoding, hash, mgf, salt-len.\n", pname.c_str());
  return false;
 }
 for (int i = 0; i < param_count; i++)
  if (params[i].type == param_type)
  {
   fprintf(stderr, "Duplicate signature parameter: %s\n", pname.c_str());
   return false;
  }
 params[param_count].type = param_type;
 if (param_type == pkc_rsa::PARAM_SALT)
 {
  params[param_count].size = param_value;
  params[param_count].data = nullptr;
 } else
 {
  params[param_count].size = 0;
  params[param_count].ival = param_value;
 }
 param_count++;
 return true;
}

void init_sign_params(pkc_base::param_data params[], int &param_count, random_gen *rng)
{
 bool hash_found = false;
 for (int i = 0; i < param_count; i++)
  if (params[i].type == pkc_rsa::PARAM_SALT && 
      params[i].size &&
      params[i].data == nullptr)
  {
   void *salt = operator new(params[i].size);
   rng->get_secure_random(salt, params[i].size);
   params[i].data = salt;
  } else
  if (params[i].type == pkc_rsa::PARAM_HASH_ALG)
   hash_found = true;
 if (!hash_found && param_count < MAX_SIGN_PARAMS)
 {
  params[param_count].type = pkc_rsa::PARAM_HASH_ALG;
  params[param_count].ival = oid::ID_HASH_SHA1;
  params[param_count].size = 0;
  param_count++;
 }
}

void cleanup_sign_params(pkc_base::param_data params[], int param_count)
{
 for (int i = 0; i < param_count; i++)
  if (params[i].type == pkc_rsa::PARAM_SALT)
  {
   operator delete(const_cast<void*>(params[i].data));
   params[i].data = nullptr;
  }
}

int main(int argc, char *argv[])
{
 if (argc < 2)
 {
  printf("Usage: %s options\n"
         "Options:\n"
         "  -load-pub <pem_file>             Load RSA public key\n"
         "  -load-priv <pem_file>            Load RSA private key\n"
         "  -power-pub                       Do powering with public exponent\n"
         "  -power-priv                      Do powering with private exponent\n"
         "  -cert-verify                     Verify RSA signature on X.509 certificate\n"
         "  -cert-sign                       Sign X.509 certificate\n"
         "  -sign-param <param>:<value>      Set signature parameters\n"
         "  -in-file  { <file> | stdin  }    Read input from file\n"
         "  -out-file { <file> | stdout }    Write output to file (default is stdout)\n"
         "  -in-fmt  { bin | hex | base64 }  Set format of the input\n"
         "  -out-fmt { bin | hex | base64 }  Set format of the output\n"
         "\n", argv[0]);
  return 1;
 }

 std_random rng;
 int in_fmt = FORMAT_DEFAULT;
 int out_fmt = FORMAT_DEFAULT;
 pkc_base::param_data sign_params[MAX_SIGN_PARAMS];
 int sign_param_count = 0;
 const char *pub_file = nullptr;
 const char *priv_file = nullptr;
 const char *in_file = nullptr;
 const char *out_file = nullptr;
 int action = ACTION_NONE;
 int last_arg = argc-1;
 for (int i=1; i<=last_arg; i++)
  if (!strcmp(argv[i], "-load-pub"))
  {
   if (i == last_arg)
   {
    error_arg_required:
    fprintf(stderr, "%s: argument required\n", argv[i]);
    return 2;
   }
   if (pub_file)
   {
    error_duplicate:
    fprintf(stderr, "%s: option can only be used once\n", argv[i]);
    return 2;
   }
   pub_file = argv[++i];
  } else
  if (!strcmp(argv[i], "-load-priv"))
  {
   if (i == last_arg) goto error_arg_required;
   if (priv_file) goto error_duplicate;
   priv_file = argv[++i];
  } else
  if (!strcmp(argv[i], "-power-pub"))
  {
   if (action == ACTION_POWER_PUB) goto error_duplicate;
   if (action != ACTION_NONE)
   {
    error_inconsistent:
    fprintf(stderr, "%s: inconsistent options\n", argv[i]);
    return 2;
   }
   action = ACTION_POWER_PUB;
  } else
  if (!strcmp(argv[i], "-power-priv"))
  {
   if (action == ACTION_POWER_PRIV) goto error_duplicate;
   if (action != ACTION_NONE) goto error_inconsistent;
   action = ACTION_POWER_PRIV;
  } else
  if (!strcmp(argv[i], "-cert-verify"))
  {
   if (action == ACTION_CERT_VERIFY) goto error_duplicate;
   if (action != ACTION_NONE) goto error_inconsistent;
   action = ACTION_CERT_VERIFY;
  } else
  if (!strcmp(argv[i], "-cert-sign"))
  {
   if (action == ACTION_CERT_SIGN) goto error_duplicate;
   if (action != ACTION_NONE) goto error_inconsistent;
   action = ACTION_CERT_SIGN;
  } else
  if (!strcmp(argv[i], "-sign-param"))
  {
   if (i == last_arg) goto error_arg_required;
   if (!process_sign_param(sign_params, sign_param_count, argv[++i])) return 2;
  } else
  if (!strcmp(argv[i], "-in-file"))
  {
   if (i == last_arg) goto error_arg_required;
   if (in_file) goto error_duplicate;
   in_file = argv[++i];
  } else
  if (!strcmp(argv[i], "-out-file"))
  {
   if (i == last_arg) goto error_arg_required;
   if (out_file) goto error_duplicate;
   out_file = argv[++i];
  } else
  if (!strcmp(argv[i], "-in-fmt"))
  {
   if (i == last_arg) goto error_arg_required;
   if (in_fmt != FORMAT_DEFAULT) goto error_duplicate;
   in_fmt = get_format(argv[i+1]);
   if (in_fmt < 0)
   {
    error_bad_format:
    fprintf(stderr, "%s: format not supported\n", argv[i]);
    return 2;
   }
   i++;
  } else
  if (!strcmp(argv[i], "-out-fmt"))
  {
   if (i == last_arg) goto error_arg_required;
   if (out_fmt != FORMAT_DEFAULT) goto error_duplicate;
   out_fmt = get_format(argv[i+1]);
   if (out_fmt < 0) goto error_bad_format;
   i++;
  } else
  {
   fprintf(stderr, "%s: unknown option\n", argv[i]);
   return 2;
  }

 if (action == ACTION_NONE)
 {
  fprintf(stderr, "Use -power-pub, -power-priv, -cert-verify or -cert-sign\n");
  return 2;
 }
 if (!in_file)
 {
  fprintf(stderr, "Use -in-file option to set input file\n");
  return 2;
 }
 bool use_stdin = strcmp(in_file, "stdin") == 0;
 bool use_stdout = !out_file || strcmp(out_file, "stdout") == 0;
 if (action == ACTION_POWER_PRIV || action == ACTION_POWER_PUB)
 {
  if (use_stdin && in_fmt == FORMAT_DEFAULT) in_fmt = FORMAT_HEX;
  if (use_stdout && out_fmt == FORMAT_DEFAULT) out_fmt = FORMAT_HEX;
  if (in_fmt == FORMAT_DEFAULT) in_fmt = FORMAT_BIN;
  if (out_fmt == FORMAT_DEFAULT) out_fmt = FORMAT_BIN;
 } else
 {
  if (in_fmt == FORMAT_DEFAULT) in_fmt = FORMAT_BASE64;
  if (out_fmt == FORMAT_DEFAULT) out_fmt = FORMAT_BASE64;
 }
 if ((action == ACTION_POWER_PRIV || action == ACTION_CERT_SIGN) && !priv_file)
 {
  fprintf(stderr, "Use -priv-file option to set private key file\n");
  return 2;
 }
 if ((action == ACTION_POWER_PUB || action == ACTION_CERT_VERIFY) && !pub_file && !priv_file)
 {
  fprintf(stderr, "Use -pub-file, -priv-file or both to set key files\n");
  return 2;
 }

 pkc_rsa rsa;
 void *pub_data, *priv_data;
 int size;
 if (pub_file)
 {
  printf("Loading public key from %s\n", pub_file);
  pub_data = load_pem_file(pub_file, size, "RSA PUBLIC KEY");
  if (!pub_data) return 3;
  if (!rsa.set_public_key(pub_data, size, nullptr))
  {
   fprintf(stderr, "Failed to load public key\n");
   return 5;
  }
 }
 if (priv_file)
 {
  printf("Loading private key from %s\n", priv_file);
  std::string found_type;
  priv_data = load_pem_file(priv_file, size, std::string(), &found_type);
  if (!priv_data) return 3;
  if (found_type == "PRIVATE KEY")
  {
   size_t out_size;
   const void *out_data = decode_pkcs8(priv_file, priv_data, size, oid::ID_RSA, out_size);
   if (!out_data) return 3;
   memcpy(priv_data, out_data, out_size);
   size = out_size;
  } else
  if (found_type != "RSA PRIVATE KEY")
  {
   fprintf(stderr, "Invalid private key format: %s\n", found_type.c_str());
   return 3;
  }
  if (!rsa.set_private_key(priv_data, size))
  {
   fprintf(stderr, "Failed to load private key\n");
   return 6;
  }
 }
 printf("Using %d-bit RSA key\n", rsa.get_modulus_bits());
 std::string pem_type;
 void *in_data = load_input_file(in_file, size, use_stdin, in_fmt, &pem_type);
 if (!in_data) return 3;
 if (action == ACTION_POWER_PRIV || action == ACTION_POWER_PUB)
 {
  size_t out_size = rsa.get_modulus_size();
  void *out_data = operator new(out_size);
  bool result = action == ACTION_POWER_PRIV?
   rsa.power_private(out_data, out_size, in_data, size) : rsa.power_public(out_data, out_size, in_data, size);
  if (!result)
  {
   fprintf(stderr, "RSA operation failed\n");
   return 7;
  }
  if (!save_output_file(out_file, out_data, out_size, use_stdout, out_fmt, "DATA")) return 4;
 } else
 {
  if (!pem_type.empty() && pem_type != "CERTIFICATE")
  {
   fprintf(stderr, "Input file must be an X.509 certificate\n");
   return 3;
  }
  if (action == ACTION_CERT_VERIFY)
  {
   bool verify_result;
   if (!verify_certificate(in_data, size, rsa, verify_result))
   {
    fprintf(stderr, "Failed to parse X.509 certificate\n");
    return 3;
   }
   printf("Verification result: %s\n", verify_result? "Success" : "Failure");
  } else
  {
   void *out_data;
   size_t out_size;
   init_sign_params(sign_params, sign_param_count, &rng);
   bool result = sign_certificate(out_data, out_size, in_data, size, rsa, sign_params, sign_param_count);
   cleanup_sign_params(sign_params, sign_param_count);
   if (!result)
   {
    fprintf(stderr, "Failed to parse X.509 certificate\n");
    return 3;
   }
   if (!out_data)
   {
    fprintf(stderr, "Failed to create RSA signature\n");
    return 7;
   }
   if (!save_output_file(out_file, out_data, out_size, use_stdout, out_fmt, "CERTIFICATE")) return 4;
  }
 }
 puts("Done");
 return 0;
}
