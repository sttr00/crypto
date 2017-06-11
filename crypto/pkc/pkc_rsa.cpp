#include "pkc_rsa.h"
#include "utils.h"
#include <crypto/asn1/decoder.h>
#include <crypto/asn1/encoder.h>
#include <crypto/oid_const.h>
#include <crypto/hash_factory.h>
#include <bigint/bigint.h>
#include <platform/endian_ex.h>
#include <platform/alloca.h>
#include <cstring>
#include <cassert>

using namespace oid;

#define countof(a) (sizeof(a)/sizeof(a[0]))

static const size_t MIN_BITS = 512;
static const size_t MAX_BITS = 16384;

static const size_t MIN_BYTES = MIN_BITS/8;
static const size_t MAX_BYTES = MAX_BITS/8 + 2;

static const size_t MIN_PRIV_EXP_BYTES = 16;

static const int MAX_DIGEST_SIZE = 64;

static const uint16_t v15_oid_pairs[] =
{
 ID_SIGN_RSA_MD2,        ID_HASH_MD2,
 ID_SIGN_RSA_MD5,        ID_HASH_MD5,
 ID_SIGN_RSA_SHA1,       ID_HASH_SHA1,
 ID_SIGN_RSA_SHA224,     ID_HASH_SHA224,
 ID_SIGN_RSA_SHA256,     ID_HASH_SHA256,
 ID_SIGN_RSA_SHA384,     ID_HASH_SHA384,
 ID_SIGN_RSA_SHA512,     ID_HASH_SHA512,
 ID_SIGN_RSA_SHA512_224, ID_HASH_SHA512,
 ID_SIGN_RSA_SHA512_256, ID_HASH_SHA512_256,
 ID_SIGN_RSA_SHA3_224,   ID_HASH_SHA3_224,
 ID_SIGN_RSA_SHA3_256,   ID_HASH_SHA3_256,
 ID_SIGN_RSA_SHA3_384,   ID_HASH_SHA3_384,
 ID_SIGN_RSA_SHA3_512,   ID_HASH_SHA3_512
};

pkc_rsa::pkc_rsa()
{
 modulus.clear();
 pub_exp_large.clear();
 pub_exp_small = 0;
 priv_exp.clear();
}

int pkc_rsa::get_id() const
{
 return ID_RSA;
}

int pkc_rsa::sign_oid_to_hash_oid(int id)
{
 for (unsigned i = 0; i < countof(v15_oid_pairs); i += 2)
  if (v15_oid_pairs[i] == id) return v15_oid_pairs[i + 1];
 return 0;
}

int pkc_rsa::hash_oid_to_sign_oid(int id)
{
 for (unsigned i = 0; i < countof(v15_oid_pairs); i += 2)
  if (v15_oid_pairs[i + 1] == id) return v15_oid_pairs[i];
 return 0;
}

static bool get_modulus(pkc_base::data_buffer &out, const asn1::element *el)
{
 if (!el->is_valid_positive_int()) return false;
 if (el->size < MIN_BYTES || el->size > MAX_BYTES) return false;
 get_integer(out, el);
 return true;
}

static bool get_pub_exponent(pkc_base::data_buffer &pub_exp_large, unsigned &pub_exp_small,
                             const pkc_base::data_buffer &modulus, const asn1::element *el)
{
 if (!el->is_valid_positive_int()) return false;
 if (el->get_small_uint(pub_exp_small))
 {
  if (pub_exp_small < 3) return false;
  pub_exp_large.clear();
  return true;
 }
 get_integer(pub_exp_large, el);
 if (!is_less(pub_exp_large, modulus)) return false;
 pub_exp_small = 0;
 return true;
}

static bool get_priv_exponent(pkc_base::data_buffer &priv_exp,
                              const pkc_base::data_buffer &modulus, const asn1::element *el)
{
 if (!el->is_valid_positive_int()) return false;
 if (el->size < MIN_PRIV_EXP_BYTES) return false;
 get_integer(priv_exp, el);
 return is_less(priv_exp, modulus);
}

static inline bool compare_exponent(pkc_base::data_buffer x_large, unsigned x_small,
                                    pkc_base::data_buffer y_large, unsigned y_small)
{
 if (x_small) return x_small == y_small;
 return is_equal(x_large, y_large);
}

bool pkc_rsa::set_public_key(const void *data, size_t size, const asn1::element *param)
{
 if (param)
 {
  int alg_id;
  const asn1::element *alg_param;
  if (!parse_alg_id(alg_id, alg_param, param)) return false;
  if (alg_id != ID_RSA || (alg_param && alg_param->tag != asn1::TYPE_NULL)) return false;
 }
 asn1::element *root = asn1::decode(data, size, 0, nullptr);
 if (!root) return false;
 bool result = false;
 if (root->is_sequence())
 {
  data_buffer res_modulus, res_pub_exp_large;
  unsigned res_pub_exp_small;
  const asn1::element *el = root->child;
  if (el && get_modulus(res_modulus, el))
  {
   el = el->sibling;
   if (el && get_pub_exponent(res_pub_exp_large, res_pub_exp_small, res_modulus, el))
   {
    result = true;
    modulus = res_modulus;
    pub_exp_large = res_pub_exp_large;
    pub_exp_small = res_pub_exp_small;
    // new public key is set, clear private key
    priv_exp.clear();
   }
  }
 }
 asn1::delete_tree(root);
 return result;
}

bool pkc_rsa::set_private_key(const void *data, size_t size)
{
 asn1::element *root = asn1::decode(data, size, 0, nullptr);
 if (!root) return false;
 bool result = false;
 if (root->is_sequence())
 {
  const asn1::element *el = root->child;
  unsigned version;
  if (el && el->get_small_uint(version) && version == 0)
  {
   data_buffer res_modulus, res_pub_exp_large, res_priv_exp;
   unsigned res_pub_exp_small;
   el = el->sibling;
   if (el && get_modulus(res_modulus, el) &&
       (!modulus.data || is_equal(modulus, res_modulus)))
   {
    el = el->sibling;
    if (el && get_pub_exponent(res_pub_exp_large, res_pub_exp_small, res_modulus, el) &&
        (!modulus.data || compare_exponent(res_pub_exp_large, res_pub_exp_small, pub_exp_large, pub_exp_small)))
    {
     el = el->sibling;
     if (el && get_priv_exponent(res_priv_exp, res_modulus, el))
     {
      result = true;
      modulus = res_modulus;
      pub_exp_large = res_pub_exp_large;
      pub_exp_small = res_pub_exp_small;
      priv_exp = res_priv_exp;
     }
    }
   }  
  }
 }
 asn1::delete_tree(root);
 return result;
}

bool pkc_rsa::power_public(void *out, size_t &out_size, const void *in, size_t in_size) const
{
 if (!modulus.data || in_size > modulus.size) return false;
 assert(pub_exp_large.data || pub_exp_small);
 bigint_t val_modulus = bigint_create_bytes_be(modulus.data, modulus.size);
 bigint_t val_public = pub_exp_small?
  bigint_create_word(pub_exp_small) : bigint_create_bytes_be(pub_exp_large.data, pub_exp_large.size);
 bigint_t val_input = bigint_create_bytes_be(in, in_size);
 bigint_t val_result = bigint_create(0);
 bigint_mpow(val_result, val_input, val_public, val_modulus);
 size_t pad_size = 0;
 size_t result_size = bigint_get_byte_count(val_result);
 if (result_size < modulus.size)
 {
  pad_size = modulus.size-result_size;
  memset(out, 0, pad_size);
 }
 int result = bigint_get_bytes_be(val_result, static_cast<uint8_t*>(out) + pad_size, out_size - pad_size);
 bigint_destroy(val_result);
 bigint_destroy(val_input);
 bigint_destroy(val_public);
 bigint_destroy(val_modulus);
 if (result < 0) return false;
 out_size = result + pad_size;
 return true;
}

bool pkc_rsa::power_private(void *out, size_t &out_size, const void *in, size_t in_size) const
{
 if (!priv_exp.data) return false;
 assert(modulus.data);
 bigint_t val_modulus = bigint_create_bytes_be(modulus.data, modulus.size);
 bigint_t val_private = bigint_create_bytes_be(priv_exp.data, priv_exp.size);
 bigint_t val_input = bigint_create_bytes_be(in, in_size);
 bigint_t val_result = bigint_create(0);
 bigint_mpow(val_result, val_input, val_private, val_modulus);
 size_t pad_size = 0;
 size_t result_size = bigint_get_byte_count(val_result);
 if (result_size < modulus.size)
 {
  pad_size = modulus.size-result_size;
  memset(out, 0, pad_size);
 }
 int result = bigint_get_bytes_be(val_result, static_cast<uint8_t*>(out) + pad_size, out_size - pad_size);
 bigint_destroy(val_result);
 bigint_destroy(val_input);
 bigint_destroy(val_private);
 bigint_destroy(val_modulus);
 if (result < 0) return false;
 out_size = result + pad_size;
 return true;
}

static void mgf1(uint8_t *out, size_t out_size, const void *seed, size_t seed_len, const hash_def *hd)
{
 uint32_t counter = 0;
 void *ctx = alloca(hd->context_size);
 while (out_size)
 {
  size_t result_size = hd->hash_size;
  if (result_size > out_size) result_size = out_size;
  hd->func_init(ctx);
  hd->func_update(ctx, seed, seed_len);
  uint32_t be_counter = VALUE_BE32(counter);
  hd->func_update(ctx, &be_counter, 4);
  memcpy(out, hd->func_final(ctx), result_size);
  counter++;
  out += result_size;
  out_size -= result_size;
 }
}

#define GET_INT_PARAM(result) \
 if (params[i].size) return 0; \
 result = params[i].ival;

#define GET_BOOL_PARAM(result) \
 if (params[i].size) return 0; \
 result = params[i].bval;

#define GET_DATA_PARAM(result) \
 result.data = params[i].data; \
 result.size = params[i].size;

bool pkc_rsa::create_signature(void *out, size_t &out_size,
                               const void *data, size_t data_size,
                               const param_data *params, int param_count) const
{
 if (!priv_exp.data || out_size < modulus.size) return false;
 uint8_t digest[MAX_DIGEST_SIZE];
 bool data_is_hash = false;
 int wrap_alg = ID_RSA;
 int hash_alg = 0;
 int mg_hash_alg = 0;
 data_buffer salt;
 size_t in_size;
 salt.clear();
 for (int i = 0; i < param_count; i++)
  switch (params[i].type)
  {
   case PARAM_DATA_IS_HASH:
    GET_BOOL_PARAM(data_is_hash);
    break;

   case PARAM_WRAPPING_ALG:
    GET_INT_PARAM(wrap_alg);
    if (!(wrap_alg == ID_RSA || wrap_alg == ID_RSASSA_PSS)) return false;
    break;

   case PARAM_HASH_ALG:
    GET_INT_PARAM(hash_alg);
    break;

   case PARAM_MGF_HASH_ALG:
    GET_INT_PARAM(mg_hash_alg);
    break;

   case PARAM_SALT:
    GET_DATA_PARAM(salt);
    if (salt.size >= 0x10000) return false;
    break;

   default:
    return false;
  }

 if (!hash_alg) return false;
 if (wrap_alg == ID_RSASSA_PSS)
 {
  // encoded PSS signature can have modulus.size or modulus.size-1 bytes,
  // depending on the MSB position
  in_size = modulus.size;
  int top_bit = bsr32(static_cast<const uint8_t*>(modulus.data)[0]);
  uint8_t top_mask = 0xFF >> (8-top_bit);
  if (!top_mask)
  {
   in_size--;
   top_mask = 0xFF;
  }
  uint8_t *masked = static_cast<uint8_t*>(out);
  const hash_def *hd_hash = hash_factory(hash_alg);
  if (!hd_hash) return false;
  if (hd_hash->hash_size + salt.size + 2 > in_size) return false;
  if (!mg_hash_alg) mg_hash_alg = hash_alg;
  const hash_def *hd_mgf = hash_factory(mg_hash_alg);
  if (!hd_mgf) return false;
  void *ctx = alloca(hd_hash->context_size);
  const void *msg;
  size_t msg_size;
  if (data_is_hash)
  {
   msg = data;
   msg_size = data_size;
  } else
  {
   msg_size = hd_hash->hash_size;
   assert(msg_size <= MAX_DIGEST_SIZE); 
   hd_hash->func_init(ctx);
   hd_hash->func_update(ctx, data, data_size);
   memcpy(digest, hd_hash->func_final(ctx), msg_size);
   msg = digest;
  }
  hd_hash->func_init(ctx);
  uint64_t ps1 = 0;
  hd_hash->func_update(ctx, &ps1, sizeof(ps1));
  hd_hash->func_update(ctx, msg, msg_size);
  hd_hash->func_update(ctx, salt.data, salt.size);
  size_t mask_size = in_size - 1 - hd_hash->hash_size;
  uint8_t *hash_out = masked + mask_size;
  memcpy(hash_out, hd_hash->func_final(ctx), hd_hash->hash_size);
  hash_out[hd_hash->hash_size] = 0xBC;
  mgf1(masked, mask_size, hash_out, hd_hash->hash_size, hd_mgf);
  xor_data(masked + mask_size - salt.size, static_cast<const uint8_t*>(salt.data), salt.size);
  masked[mask_size - salt.size - 1] ^= 1;
  masked[0] &= top_mask;
 } else
 {
  const oid_def *hash_oid_def = get(hash_alg);
  if (!hash_oid_def) return false;
  const hash_def *hd_hash = nullptr;
  const void *msg;
  size_t msg_size;
  if (data_is_hash)
  {
   if (data_size + 11 > modulus.size) return false;  
   msg = data;
   msg_size = data_size;
  } else
  {
   hd_hash = hash_factory(hash_alg);
   if (!hd_hash) return false;
   msg_size = hd_hash->hash_size;
   if (msg_size + 11 > modulus.size) return false;
   assert(msg_size <= MAX_DIGEST_SIZE);
   void *ctx = alloca(hd_hash->context_size);
   hd_hash->func_init(ctx);
   hd_hash->func_update(ctx, data, data_size);
   memcpy(digest, hd_hash->func_final(ctx), msg_size);
   msg = digest;
  }

  asn1::element el_root(asn1::TYPE_SEQUENCE);
  asn1::element el_alg(asn1::TYPE_SEQUENCE);
  asn1::element el_oid(asn1::TYPE_OID, hash_oid_def->data, hash_oid_def->size);
  asn1::element el_params(asn1::TYPE_NULL);
  asn1::element el_hash(asn1::TYPE_OCTET_STRING, msg, msg_size);
  el_alg.child = &el_oid;
  el_oid.sibling = &el_params;
  el_alg.sibling = &el_hash;
  el_root.child = &el_alg;
  size_t asn_size = asn1::calc_encoded_size(&el_root);
  if (asn_size + 11 > modulus.size) return false;

  uint8_t *pad = static_cast<uint8_t*>(out);
  size_t pad_len = modulus.size - asn_size - 3;
  // leading zero is removed, it's not needed for power_private
  pad[0] = 1;
  memset(pad + 1, 0xFF, pad_len);
  pad[pad_len + 1] = 0;
  size_t encoded_size;
  if (!asn1::encode_def_length(pad + pad_len + 2, encoded_size, &el_root))
  {
   assert(0);
   return false;
  }
  assert(asn_size == encoded_size);  
  in_size = modulus.size - 1;
 }
 return power_private(out, out_size, out, in_size);
}

asn1::element *pkc_rsa::create_params_struct(const param_data *params, int param_count, int where) const
{
 int wrap_alg = ID_RSA;
 int hash_alg = 0, mg_hash_alg = 0;
 data_buffer salt;
 salt.clear();
 for (int i = 0; i < param_count; i++)
  switch (params[i].type)
  {
   case PARAM_DATA_IS_HASH:
    break;

   case PARAM_WRAPPING_ALG:
    GET_INT_PARAM(wrap_alg);
    if (!(wrap_alg == ID_RSA || wrap_alg == ID_RSASSA_PSS)) return nullptr;
    break;

   case PARAM_HASH_ALG:
    GET_INT_PARAM(hash_alg);
    break;

   case PARAM_MGF_HASH_ALG:
    GET_INT_PARAM(mg_hash_alg);
    break;

   case PARAM_SALT:
    GET_DATA_PARAM(salt);
    if (salt.size >= 0x10000) return nullptr;
    break;

   default:
    return nullptr;
  }

 if (!hash_alg) return nullptr;
 int sign_id;
 const oid_def *hash_oid_def = nullptr;
 const oid_def *mg_hash_oid_def = nullptr;
 if (wrap_alg == ID_RSASSA_PSS)
 {
  sign_id = ID_RSASSA_PSS;
  if (hash_alg != ID_HASH_SHA1)
  {
   hash_oid_def = get(hash_alg);
   if (!hash_oid_def) return nullptr;
  }
  if (!mg_hash_alg) mg_hash_alg = hash_alg;
  if (mg_hash_alg != ID_HASH_SHA1)
  {
   mg_hash_oid_def = get(mg_hash_alg);
   if (!mg_hash_oid_def) return nullptr;
  }
 } else
 {
  sign_id = hash_oid_to_sign_oid(hash_alg);
  if (!sign_id) return nullptr;
 } 
 const oid_def *sign_oid_def = get(sign_id);
 if (!sign_oid_def) return nullptr;
 asn1::element *el_oid = asn1::element::create(asn1::TYPE_OID, sign_oid_def->data, sign_oid_def->size);
 if (wrap_alg == ID_RSASSA_PSS)
 {
  asn1::element *params = asn1::element::create(asn1::TYPE_SEQUENCE);
  asn1::element *prev = nullptr;
  if (hash_oid_def)
  {
   asn1::element *el = create_tagged_element(0, create_alg_id(hash_oid_def));
   append_child(params, el, prev);
  }
  if (mg_hash_oid_def)
  {
   const oid_def *mgf1_def = get(ID_MGF1);
   assert(mgf1_def);
   asn1::element *el = create_alg_id(mgf1_def);
   el->child->sibling = create_alg_id(mg_hash_oid_def);
   el = create_tagged_element(1, el);
   append_child(params, el, prev);
  }
  if (mg_hash_alg != ID_HASH_SHA1 || salt.size != 20)
  {
   void *uint_buf = operator new(8);
   size_t uint_size = pack_small_uint(static_cast<uint8_t*>(uint_buf), salt.size);
   asn1::element *el_int = asn1::element::create(asn1::TYPE_INTEGER, uint_buf, uint_size);
   el_int->flags |= asn1::element::FLAG_OWN_BUFFER;
   append_child(params, create_tagged_element(2, el_int), prev);
  }
  if (params->child) el_oid->sibling = params; else delete params;
 } else
 {
  el_oid->sibling = asn1::element::create(asn1::TYPE_NULL);
 }
 asn1::element *el_root = asn1::element::create(asn1::TYPE_SEQUENCE);
 el_root->child = el_oid;
 return el_root;
}

static bool parse_hash_alg(int &hash_alg, const asn1::element *el)
{
 const asn1::element *params;
 if (!parse_alg_id(hash_alg, params, el->child) || params) return false;
 return true;
}

static bool parse_mg_alg(int &mg_hash_alg, const asn1::element *el)
{
 const asn1::element *params;
 int mg_alg;
 if (!parse_alg_id(mg_alg, params, el->child) || !params) return false;
 if (mg_alg != ID_MGF1) return false;
 if (!parse_alg_id(mg_hash_alg, params, params) || params) return false;
 return true;
}

static bool parse_salt_len(int &salt_len, const asn1::element *el)
{
 el = el->child;
 unsigned value;
 if (!(el && el->get_small_uint(value))) return false;
 if (value >= 0x10000) return false;
 salt_len = value;
 return true;
}

static bool parse_trailer(const asn1::element *el)
{
 el = el->child;
 unsigned value;
 if (!(el && el->get_small_uint(value))) return false;
 return value == 1;
}

static bool check_zero(const uint8_t *data, size_t size)
{
 for (size_t i = 0; i < size; i++)
  if (data[i]) return false;
 return true;
}

static size_t decode_v15_padding(const uint8_t *data, size_t size)
{
 if (data[0] || data[1] != 1) return 0;
 size_t pos = 2;
 for (;;)
 {
  if (data[pos] != 0xFF) break;
  if (++pos == size) return 0;
 }
 if (pos < 10 || data[pos]) return 0;
 if (++pos == size) return 0;
 return pos;
}

static const uint8_t *decode_v15_wrapping(const uint8_t *data, size_t size, int hash_id, size_t &hash_size)
{
 asn1::element *root = asn1::decode(data, size, 0, nullptr);
 if (!root) return nullptr;
 const uint8_t *result = nullptr;
 if (root->is_sequence())
 {
  const asn1::element *el = root->child;
  const asn1::element *params;
  int alg_id;
  if (parse_alg_id(alg_id, params, el) && alg_id == hash_id)
  {
   el = el->sibling;
   if (el && el->is_octet_string())
   {
    result = el->data;
    hash_size = el->size;
   }
  }
 }
 asn1::delete_tree(root);
 return result;
}

bool pkc_rsa::verify_signature(const void *sig, size_t sig_size,
                               const void *data, size_t data_size,
                               const asn1::element *param) const
{
 if (!modulus.data) return false;
 const hash_def *hd_hash = nullptr;
 const hash_def *hd_mgf = nullptr;
 int salt_len = -1;
 uint8_t top_mask;
 bool result;
 int enc_alg;
 const asn1::element *alg_param;
 if (!parse_alg_id(enc_alg, alg_param, param)) return false;
 if (enc_alg == ID_RSASSA_PSS)
 {
  int hash_alg = ID_HASH_SHA1;
  int mg_hash_alg = ID_HASH_SHA1;
  if (alg_param)
  {
   if (!alg_param->is_sequence()) return false;
   int prev_tag = -1;
   for (const asn1::element *el = alg_param->child; el; el = el->sibling)
   {
    if (el->cls != asn1::CLASS_CONTEXT_SPECIFIC || el->tag >= 0x10000) return false;
    int tag = static_cast<int>(el->tag);
    if (tag <= prev_tag) return false;
    switch (tag)
    {
     case 0:
      if (!parse_hash_alg(hash_alg, el)) return false;
      break;
     case 1:
      if (!parse_mg_alg(mg_hash_alg, el)) return false;
      break;
     case 2:
      if (!parse_salt_len(salt_len, el)) return false;
      break;
     case 3:
      if (!parse_trailer(el)) return false;
      break;
    }
    prev_tag = tag;
   }
  }
  hd_hash = hash_factory(hash_alg);
  if (!hd_hash) return false;
  hd_mgf = hash_factory(mg_hash_alg);
  if (!hd_mgf) return false;
  if (salt_len < 0) salt_len = hd_hash->hash_size;
  if (static_cast<size_t>(hd_hash->hash_size) > sig_size - 2) return false;
  if (static_cast<size_t>(salt_len) > sig_size - (hd_hash->hash_size + 2)) return false;
  int top_bit = bsr32(static_cast<const uint8_t*>(modulus.data)[0]);
  top_mask = 0xFF >> (8-top_bit);
 } else
 {
  int hash_alg = sign_oid_to_hash_oid(enc_alg);
  if (!hash_alg) return false;
  hd_hash = hash_factory(hash_alg);
  if (!hd_hash) return false;
 }

 assert(hd_hash->hash_size <= MAX_DIGEST_SIZE); 
 size_t out_size = modulus.size;
 uint8_t *out = static_cast<uint8_t*>(alloca(out_size));
 if (!power_public(out, out_size, sig, sig_size)) return false;
 assert(out_size == modulus.size);

 if (enc_alg == ID_RSASSA_PSS)
 {
  if (!top_mask)
  {
   out++;
   out_size--;
   top_mask = 0xFF;
  }
  if (static_cast<size_t>(hd_hash->hash_size + salt_len + 2) > out_size) return false;
  if (out[out_size-1] != 0xBC) return false;
  if (out[0] & ~top_mask) return false;
  size_t mask_len = out_size - (hd_hash->hash_size + 1);
  const uint8_t *hash = out + mask_len;
  uint8_t *mask = static_cast<uint8_t*>(alloca(mask_len));
  mgf1(mask, mask_len, hash, hd_hash->hash_size, hd_mgf);
  xor_data(out, mask, mask_len);
  out[0] &= top_mask;
  size_t pad_len = mask_len - salt_len - 1;
  if (!check_zero(out, pad_len) || out[pad_len] != 1) return false;

  uint8_t digest[MAX_DIGEST_SIZE];  
  void *ctx = alloca(hd_hash->context_size);
  hd_hash->func_init(ctx);
  hd_hash->func_update(ctx, data, data_size);
  memcpy(digest, hd_hash->func_final(ctx), hd_hash->hash_size);
  hd_hash->func_init(ctx);
  uint64_t ps1 = 0;
  hd_hash->func_update(ctx, &ps1, sizeof(ps1));
  hd_hash->func_update(ctx, digest, hd_hash->hash_size);
  hd_hash->func_update(ctx, out + pad_len + 1, salt_len);
  result = memcmp(hd_hash->func_final(ctx), hash, hd_hash->hash_size) == 0;
 } else
 {
  size_t pad_len = decode_v15_padding(out, out_size);
  if (!pad_len) return false;
  size_t hash_size;
  const void *hash = decode_v15_wrapping(out + pad_len, out_size - pad_len, hd_hash->id, hash_size);
  if (!hash || static_cast<int>(hash_size) != hd_hash->hash_size) return false;
  void *ctx = alloca(hd_hash->context_size);
  hd_hash->func_init(ctx);
  hd_hash->func_update(ctx, data, data_size);
  result = memcmp(hd_hash->func_final(ctx), hash, hash_size) == 0;
 }

 return result;
}

int pkc_rsa::get_modulus_bits() const
{
 return get_bits(modulus);
}
