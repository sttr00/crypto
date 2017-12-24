#include "../common/file_utils.h"
#include <crypto/oid_const.h>
#include <crypto/oid_search.h>
#include <crypto/asn1/encoder.h>
#include <crypto/asn1/decoder.h>
#include <crypto/pkc/pkc_dsa.h>
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
 ACTION_VERIFY_CERT,
 ACTION_SIGN_CERT,
 ACTION_VERIFY_DATA,
 ACTION_SIGN_DATA
};

enum
{
 ERR_BAD_X509_CERTIFICATE = 1,
 ERR_BAD_SIGNATURE_PARAMS,
 ERR_BAD_SIGNATURE_FORMAT,
 ERR_SIGNING_FAILED,
 ERR_VERIFICATION_FAILED
};

static const int MAX_SIGN_PARAMS = 10;

static bool verify_certificate(const void *data, size_t size, const pkc_base &pk, int *error)
{
 if (error) *error = ERR_BAD_X509_CERTIFICATE;
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
     result = pk.verify_signature(sig->data + 1, sig->size - 1,
      root->data, tbs_cert->size + (tbs_cert->data - root->data), sig_alg);
     if (error) *error = result? 0 : ERR_VERIFICATION_FAILED;
    }
   }
  }
 }
 asn1::delete_tree(root);
 return result;
}

static bool verify_data(const void *data, size_t size, const void *sig_data, size_t sig_size, const pkc_base &pk, int *error)
{
 if (error) *error = ERR_BAD_SIGNATURE_FORMAT;
 asn1::element *root = asn1::decode(sig_data, sig_size, 0, nullptr);
 if (!root) return false;
 bool result = false;
 if (root->is_sequence())
 {
  const asn1::element *sig_alg = root->child;
  if (sig_alg && sig_alg->is_sequence())
  {
   const asn1::element *sig = sig_alg->sibling;
   if (sig && sig->is_aligned_bit_string())
   {
    result = pk.verify_signature(sig->data + 1, sig->size - 1, data, size, sig_alg);
    if (error) *error = result? 0 : ERR_VERIFICATION_FAILED;
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
                             const pkc_base &pk, const pkc_base::param_data params[], int param_count, int *error)
{
 out_data = nullptr;
 out_size = 0;
 asn1::element *root = asn1::decode(data, size, 0, nullptr);
 if (!root)
 {
  if (error) *error = ERR_BAD_X509_CERTIFICATE;
  return false;
 }
 
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
  if (error) *error = ERR_BAD_X509_CERTIFICATE;
  return false;
 }

 asn1::element *el_params = pk.create_params_struct(params, param_count, pkc_base::WHERE_SIGNATURE);
 if (!el_params)
 {
  asn1::delete_tree(root);
  if (error) *error = ERR_BAD_SIGNATURE_PARAMS;
  return false;
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
 size_t sign_size = pk.get_max_signature_size();
 uint8_t *sign_data = static_cast<uint8_t*>(alloca(sign_size + 1));
 bool result = pk.create_signature(sign_data + 1, sign_size, encoded_data, encoded_size, params, param_count);
 operator delete(encoded_data);
 if (!result)
 {
  asn1::delete_tree(root);
  if (error) *error = ERR_SIGNING_FAILED;
  return false;
 }
 
 sign_data[0] = 0;
 signature->data = sign_data;
 signature->size = sign_size + 1;
 tbs_cert->sibling = prev_sibling;
 out_data = encode_asn1(root, out_size);
 asn1::delete_tree(root);
 if (error) *error = 0;
 return true;
}

static bool sign_data(void* &out_data, size_t &out_size, const void *data, size_t size,
                      const pkc_base &pk, const pkc_base::param_data params[], int param_count, int *error)
{
 asn1::element *el_params = pk.create_params_struct(params, param_count, pkc_base::WHERE_SIGNATURE);
 if (!el_params)
 {
  if (error) *error = ERR_BAD_SIGNATURE_PARAMS;
  return false;
 }

 size_t sign_size = pk.get_max_signature_size();
 uint8_t *sign_data = static_cast<uint8_t*>(alloca(sign_size + 1));
 if (!pk.create_signature(sign_data + 1, sign_size, data, size, params, param_count))
 {
  asn1::delete_tree(el_params);
  if (error) *error = ERR_SIGNING_FAILED;
  return false;
 }

 asn1::element *root = asn1::element::create(asn1::TYPE_SEQUENCE);
 root->child = el_params;
 asn1::element *signature = asn1::element::create(asn1::TYPE_BIT_STRING);
 el_params->sibling = signature;
 sign_data[0] = 0;
 signature->data = sign_data;
 signature->size = sign_size + 1;
 out_data = encode_asn1(root, out_size);
 asn1::delete_tree(root); 
 if (error) *error = 0;
 return true;
}

static const struct
{
 const char *name;
 int alg;
} hash_names[] =
{
 { "md5",      oid::ID_HASH_MD5      },
 { "sha1",     oid::ID_HASH_SHA1     },
 { "sha256",   oid::ID_HASH_SHA256   },
 { "sha224",   oid::ID_HASH_SHA224   },
 { "sha512",   oid::ID_HASH_SHA512   }, 
 { "sha384",   oid::ID_HASH_SHA384   },
 #ifdef CRYPTO_ENABLE_HASH_SHA3
 { "sha3-512", oid::ID_HASH_SHA3_512 },
 { "sha3-384", oid::ID_HASH_SHA3_384 },
 { "sha3-256", oid::ID_HASH_SHA3_256 },
 { "sha3-224", oid::ID_HASH_SHA3_224 }
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
  fprintf(stderr, "Unknown parameter %s.\n"
          "The supported parameters are: encoding, hash, mgf, salt-len.\n", pname.c_str());
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

static bool parse_alg_id(int &alg, const asn1::element* &params, const asn1::element *el, const asn1::element* &unknown_oid)
{
 unknown_oid = nullptr;
 if (!(el && el->is_sequence())) return false;
 el = el->child;
 if (!(el && el->is_obj_id())) return false;
 alg = oid::find(el->data, el->size); 
 if (!alg)
 {
  unknown_oid = el;
  return false;
 }
 params = el->sibling;
 return true;
}

static const asn1::element *get_subject_public_key_from_x509(const asn1::element *root)
{
 if (!(root && root->is_sequence())) return nullptr;
 const asn1::element *tbs_cert = root->child;
 if (!(tbs_cert && tbs_cert->is_sequence())) return nullptr;
 const asn1::element *version = tbs_cert->child;
 if (!version) return nullptr;
 const asn1::element *serial_num;
 if (version->cls == asn1::CLASS_CONTEXT_SPECIFIC && version->tag == 0)
 {
  serial_num = version->sibling;
  if (!serial_num) return nullptr;
 } else serial_num = version;
 const asn1::element *signature = serial_num->sibling;
 if (!signature) return nullptr;
 const asn1::element *issuer = signature->sibling;
 if (!issuer) return nullptr;
 const asn1::element *validity = issuer->sibling;
 if (!validity) return nullptr;
 const asn1::element *subject = validity->sibling;
 if (!subject) return nullptr;
 return subject->sibling;
}

static pkc_base *create_pkc(int alg)
{
 switch (alg)
 {
  case oid::ID_RSA: return new pkc_rsa;
  case oid::ID_DSA: return new pkc_dsa;
 }
 return nullptr;
}

bool load_public_key(pkc_base* &pk, void* &data, const char *filename)
{
 int size;
 std::string type;
 data = load_pem_file(filename, size, std::string(), &type);
 if (!data) return false;
 asn1::element *root = nullptr;
 const asn1::element *alg_id = nullptr;
 const char *error = "Failed to load public key";
 if (type == "PUBLIC KEY")
 {
  root = asn1::decode(data, size, 0, nullptr);
  if (root)
  {
   if (root->is_sequence())
    alg_id = root->child;
   else
    error = "Failed to parse public key";
  } else error = "Failed to decode public key";
 } else
 if (type == "CERTIFICATE")
 {
  root = asn1::decode(data, size, 0, nullptr);
  if (root)
  {
   const asn1::element *pub_key_info = get_subject_public_key_from_x509(root);
   if (pub_key_info && pub_key_info->is_sequence())
    alg_id = pub_key_info->child;
   else
    error = "Failed to parse X.509 certificate";
  } else error = "Failed to decode X.509 certificate";
 } else 
 {
  fprintf(stderr, "%s: Can't load public key from a file of type %s\n", filename, type.c_str());
  error = nullptr;
 }
 if (alg_id)
 {
  const asn1::element *unknown_oid, *params;
  int alg;
  if (parse_alg_id(alg, params, alg_id, unknown_oid))
  {
   const asn1::element *key_data = alg_id->sibling;
   if (key_data && key_data->is_aligned_bit_string())
   {
    if (!pk) pk = create_pkc(alg);
    if (pk)
    {
     if (pk->set_public_key(key_data->data + 1, key_data->size - 1, params))
     {
      printf("%s: Public key loaded\n", filename);
      asn1::delete_tree(root);
      return true;
     } else error = "Failed to set public key";
    } else error = "Unsupported public key algorithm";
   }
  } else
  if (unknown_oid)
  {
   fprintf(stderr, "%s: Algorithm %s not supported\n", filename, print_oid(unknown_oid->data, unknown_oid->size).c_str());
   error = nullptr;
  }
 }
 asn1::delete_tree(root);
 operator delete(data);
 data = nullptr;
 if (error) fprintf(stderr, "%s: %s\n", filename, error);
 return false;
}

static bool load_raw_private_key(pkc_base* &pk, int alg, const void *data, int size, const char* &error)
{
 pk = create_pkc(alg);
 if (!pk)
 {
  error = "Unsupported public key algorithm";
  return false;
 }
 if (!pk->set_private_key(data, size, nullptr))
 {
  error = "Failed to set private key";
  return false;
 }
 return true;
}

bool load_private_key(pkc_base* &pk, void* &data, const char *filename)
{
 int size;
 std::string type;
 data = load_pem_file(filename, size, std::string(), &type);
 if (!data) return false;
 bool result = false;
 const char *error = nullptr;
 if (type == "PRIVATE KEY")
 {
  static const int req_alg_id[] = { oid::ID_RSA, oid::ID_DSA, 0 };
  pkcs8_result pk_res;
  if (decode_pkcs8(pk_res, filename, data, size, req_alg_id))
  {
   if (!pk) pk = create_pkc(pk_res.alg_id);
   if (pk)
   {
    if (pk->set_private_key(pk_res.data, pk_res.size, pk_res.params))
     result = true;
    else
     error = "Failed to set private key";
   } else error = "Unsupported public key algorithm";
   asn1::delete_tree(pk_res.params);
  }
 } else 
 if (type == "RSA PRIVATE KEY")
 {
  result = load_raw_private_key(pk, oid::ID_RSA, data, size, error);
 } else
 if (type == "DSA PRIVATE KEY")
 {
  result = load_raw_private_key(pk, oid::ID_DSA, data, size, error);
 } else fprintf(stderr, "%s: Can't load private key from a file of type %s\n", filename, type.c_str());
 if (!result)
 {
  if (error) fprintf(stderr, "%s: %s\n", filename, error);
  operator delete(data);
  data = nullptr;
  return false;
 }
 printf("%s: Private key loaded\n", filename);
 return true;
}

static int print_error(int error)
{
 switch (error)
 {
  case ERR_BAD_X509_CERTIFICATE:
   fprintf(stderr, "Failed to parse X.509 certificate\n");
   return 3;
  case ERR_BAD_SIGNATURE_FORMAT:
   fprintf(stderr, "Invalid signature file format\n");
   return 3;
  case ERR_BAD_SIGNATURE_PARAMS:
   fprintf(stderr, "Invalid signature parameters\n");
   return 5;    
  case ERR_SIGNING_FAILED:
   fprintf(stderr, "Failed to create signature\n");
   return 7;
  case ERR_VERIFICATION_FAILED:
   puts("Verification Failed");
   return 10;
 }
 return 255;
}

int main(int argc, char *argv[])
{
 if (argc < 2)
 {
  printf("Usage: %s options\n"
         "Options:\n"
         "  -load-pub <pem_file>    Load public key\n"
         "  -load-priv <pem_file>   Load private key\n"
         "  -verify-cert            Verify signature on X.509 certificate\n"
         "  -sign-cert              Sign X.509 certificate\n"
         "  -verify-data            Verify signature on raw file\n"
         "  -sign-data              Sign raw file\n"
         "  -in-sign <file>         Signature file to use with -data-verify\n"
         "  -param <param>:<value>  Set signature parameters\n"
         "  -in-file  <file>        Read input from file\n"
         "  -out-file <file>        Write output to file (default is stdout)\n"
         "\n", argv[0]);
  return 1;
 }

 std_random rng;
 pkc_base::param_data sign_params[MAX_SIGN_PARAMS];
 int sign_param_count = 0;
 const char *pub_file = nullptr;
 const char *priv_file = nullptr;
 const char *in_file = nullptr;
 const char *out_file = nullptr;
 const char *sign_file = nullptr;
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
  if (!strcmp(argv[i], "-verify-cert"))
  {
   if (action == ACTION_VERIFY_CERT) goto error_duplicate;
   if (action != ACTION_NONE)
   {
    error_inconsistent:
    fprintf(stderr, "%s: inconsistent options\n", argv[i]);
    return 2;
   }
   action = ACTION_VERIFY_CERT;
  } else
  if (!strcmp(argv[i], "-sign-cert"))
  {
   if (action == ACTION_SIGN_CERT) goto error_duplicate;
   if (action != ACTION_NONE) goto error_inconsistent;
   action = ACTION_SIGN_CERT;
  } else
  if (!strcmp(argv[i], "-sign-data"))
  {
   if (action == ACTION_SIGN_DATA) goto error_duplicate;
   if (action != ACTION_NONE) goto error_inconsistent;
   action = ACTION_SIGN_DATA;
  } else
  if (!strcmp(argv[i], "-verify-data"))
  {
   if (action == ACTION_VERIFY_DATA) goto error_duplicate;
   if (action != ACTION_NONE) goto error_inconsistent;
   action = ACTION_VERIFY_DATA;
  } else
  if (!strcmp(argv[i], "-param"))
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
  if (!strcmp(argv[i], "-in-sign"))
  {
   if (i == last_arg) goto error_arg_required;
   if (sign_file) goto error_duplicate;
   sign_file = argv[++i];
  } else
  {
   fprintf(stderr, "%s: unknown option\n", argv[i]);
   return 2;
  }

 if (action == ACTION_NONE)
 {
  fprintf(stderr, "Use -cert-verify, -cert-sign, -data-verify or -data-sign\n");
  return 2;
 }
 if (!in_file)
 {
  fprintf(stderr, "Use -in-file option to set input file\n");
  return 2;
 }

 bool have_private_key = false;
 pkc_base *pk = nullptr;
 void *data;
 if (pub_file && priv_file)
 {
  fprintf(stderr, "Options -load-pub and -load-priv are mutually exclusive\n");
  return 2;
 }
 if (pub_file)
 {
  if (!load_public_key(pk, data, pub_file)) return 5;
 }
 if (priv_file)
 {
  if (!load_private_key(pk, data, priv_file)) return 6;
  have_private_key = true;
 }
 if (!pk)
 {
  fprintf(stderr, "Use -load-pub or -load-priv\n");
  return 2;
 }

 if (!have_private_key && (action == ACTION_SIGN_CERT || action == ACTION_SIGN_DATA))
 {
  fprintf(stderr, "Private key must be loaded\n");
  return 2;
 }

 pk->set_rng(&rng);
 if (action == ACTION_SIGN_CERT)
 {
  int error, cert_size;
  void *cert_data = load_pem_file(in_file, cert_size, "CERTIFICATE", nullptr);
  if (!cert_data) return 3;
  void *out_data;
  size_t out_size;
  init_sign_params(sign_params, sign_param_count, &rng);
  sign_certificate(out_data, out_size, cert_data, cert_size, *pk, sign_params, sign_param_count, &error);
  cleanup_sign_params(sign_params, sign_param_count);
  if (error) return print_error(error);
  puts("Signature Created");
  if (!save_output_file(out_file, out_data, out_size,
   out_file == nullptr, FORMAT_BASE64, "CERTIFICATE")) return 4;
 } else
 if (action == ACTION_SIGN_DATA)
 {
  int error, raw_size;
  void *raw_data = load_file(in_file, raw_size, false);
  if (!raw_data) return 3;
  void *out_data;
  size_t out_size;
  init_sign_params(sign_params, sign_param_count, &rng);
  sign_data(out_data, out_size, raw_data, raw_size, *pk, sign_params, sign_param_count, &error);
  if (error) return print_error(error);
  puts("Signature Created");
  if (!save_output_file(out_file, out_data, out_size,
   out_file == nullptr, out_file == nullptr? FORMAT_HEX : FORMAT_BIN, nullptr)) return 4;
 } else
 if (action == ACTION_VERIFY_DATA)
 {
  if (!sign_file)
  {
   fprintf(stderr, "Use -in-sign to load signature\n");
   return 2;
  }
  int error, raw_size, sign_size;
  void *raw_data = load_file(in_file, raw_size, false);
  if (!raw_data) return 3;
  void *sign_data = load_file(sign_file, sign_size, false);
  if (!sign_data) return 3;
  verify_data(raw_data, raw_size, sign_data, sign_size, *pk, &error);
  if (error) return print_error(error);
  puts("Verification Succeeded");
 } else
 {
  int error, cert_size;
  void *cert_data = load_pem_file(in_file, cert_size, "CERTIFICATE", nullptr);
  if (!cert_data) return 3;
  verify_certificate(cert_data, cert_size, *pk, &error);
  if (error) return print_error(error);
  puts("Verification Succeeded");
 }
 return 0;
}
