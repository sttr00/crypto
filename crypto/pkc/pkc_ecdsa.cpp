#include "pkc_ecdsa.h"
#include "utils.h"
#include "gen_k.h"
#include <crypto/asn1/decoder.h>
#include <crypto/asn1/encoder.h>
#include <crypto/ec/curves_wei.h>
#include <crypto/oid_const.h>
#include <crypto/oid_search.h>
#include <crypto/utils/random_range.h>
#include <crypto/hash_factory.h>
#include <string.h>

#ifdef CRYPTO_EC_PROJECTIVE
#include <crypto/ec/ec_weip.h>
#define ec_point_mul       ec_weip_point_mul
#define ec_point_add       ec_weip_point_add
#define ec_point_dbl       ec_weip_point_dbl
#define ec_point_affine_xy ec_weip_point_affine_xy
#define ec_point_affine_x  ec_weip_point_affine_x
#define ec_point_normalize ec_weip_point_normalize
#else
#include <crypto/ec/ec_weij.h>
#define ec_point_mul       ec_weij_point_mul
#define ec_point_add       ec_weij_point_add
#define ec_point_dbl       ec_weij_point_dbl
#define ec_point_affine_xy ec_weij_point_affine_xy
#define ec_point_affine_x  ec_weij_point_affine_x
#define ec_point_normalize ec_weij_point_normalize
#endif

using namespace oid;

#define countof(a) (sizeof(a)/sizeof(a[0]))

static const uint16_t ecdsa_oid_pairs[] =
{
 ID_SIGN_ECDSA_SHA1,     ID_HASH_SHA1,
 ID_SIGN_ECDSA_SHA224,   ID_HASH_SHA224,
 ID_SIGN_ECDSA_SHA256,   ID_HASH_SHA256,
 ID_SIGN_ECDSA_SHA384,   ID_HASH_SHA384,
 ID_SIGN_ECDSA_SHA512,   ID_HASH_SHA512,
 ID_SIGN_ECDSA_SHA3_224, ID_HASH_SHA3_224,
 ID_SIGN_ECDSA_SHA3_256, ID_HASH_SHA3_256,
 ID_SIGN_ECDSA_SHA3_384, ID_HASH_SHA3_384,
 ID_SIGN_ECDSA_SHA3_512, ID_HASH_SHA3_512
};

static inline void init_point(ec_point_t &pt)
{
 pt.x = pt.y = pt.z = nullptr;
}

static bool get_point(ec_point_t &pt, const uint8_t *data, size_t size, const ec_wei_def_t *def)
{
 if (!size) return false;
 size_t coord_size = bigint_get_byte_count(def->p);
 if (data[0] == 4)
 {
  if (size != 2*coord_size + 1) return false;
  pt.x = bigint_create_bytes_be(data + 1, coord_size);
  pt.y = bigint_create_bytes_be(data + 1 + coord_size, coord_size);
  pt.z = bigint_create_word(1);
  return true;
 }
 if (data[0] == 2 || data[0] == 3)
 {
  if (size != coord_size + 1) return false;
  if ((bigint_get_ls_word(def->p) & 3) != 3) return false;
  pt.x = bigint_create_bytes_be(data + 1, coord_size);
  pt.y = bigint_create(0);
  pt.z = bigint_create_word(1);
  bigint_t t1 = bigint_create(0);
  bigint_t t2 = bigint_create(0);
  bigint_mmul(t1, pt.x, pt.x, def->p);
  bigint_mmul(t2, t1, pt.x, def->p);
  bigint_mmul(t1, pt.x, def->a, def->p);
  bigint_add(t2, t2, t1);
  bigint_madd(t2, t2, def->b, def->p);
  bigint_addw(t1, def->p, 1);
  bigint_rshift(t1, t1, 2);
  bigint_mpow(pt.y, t2, t1, def->p);
  if ((bigint_get_ls_word(pt.y) & 1) ^ (data[0]-2))
   bigint_sub(pt.y, def->p, pt.y);
  bigint_destroy(t2);
  bigint_destroy(t1);
  return true;
 } 
 return false;
}

pkc_ecdsa::pkc_ecdsa()
{
 ec_wei_def_init(&def, nullptr, nullptr, nullptr);
 init_point(gen);
 init_point(pub);
 order = priv = nullptr;
 rng = nullptr;
 curve_id = 0;
 key_bits = 0;
}

pkc_ecdsa::~pkc_ecdsa()
{
 clear();
}

int pkc_ecdsa::get_id() const
{
 return ID_ECDSA;
}

int pkc_ecdsa::sign_oid_to_hash_oid(int id)
{
 for (unsigned i = 0; i < countof(ecdsa_oid_pairs); i += 2)
  if (ecdsa_oid_pairs[i] == id) return ecdsa_oid_pairs[i + 1];
 return 0;
}

int pkc_ecdsa::hash_oid_to_sign_oid(int id)
{
 for (unsigned i = 0; i < countof(ecdsa_oid_pairs); i += 2)
  if (ecdsa_oid_pairs[i + 1] == id) return ecdsa_oid_pairs[i];
 return 0;
}

void pkc_ecdsa::clear()
{
 ec_wei_def_destroy(&def);
 ec_wei_point_destroy(&gen);
 ec_wei_point_destroy(&pub);
 bigint_destroy(order);
 bigint_destroy(priv);
}

static const curve_wei *get_curve(const asn1::element *el)
{
 if (!(el && el->is_obj_id())) return nullptr;
 int curve_id = oid::find(el->data, el->size); 
 if (!curve_id) return nullptr;
 return get_wei_curve_by_id(curve_id);
}

bool pkc_ecdsa::set_public_key(const void *data, size_t size, const asn1::element *param)
{
 const curve_wei *curve = get_curve(param);
 if (!curve) return false;
 ec_wei_def_t new_def;
 ec_point_t new_gen, new_pub;
 bigint_t new_order;
 init_curve(&new_def, &new_gen, &new_order, curve);
 if (!get_point(new_pub, static_cast<const uint8_t*>(data), size, &new_def))
 {
  ec_wei_def_destroy(&new_def);
  ec_wei_point_destroy(&new_gen);
  bigint_destroy(new_order);
  return false;
 }
 clear();
 def = new_def;
 gen = new_gen;
 pub = new_pub;
 order = new_order;
 priv = nullptr;
 curve_id = curve->id;
 key_bits = curve->bits;
 return true;
} 

bool pkc_ecdsa::set_private_key(const void *data, size_t size, const asn1::element *param)
{
 asn1::element *root = asn1::decode(data, size, 0, nullptr); 
 if (!root) return false;
 int curve_id = 0;
 bool result = false;
 ec_wei_def_t new_def;
 ec_point_t new_gen, new_pub;
 bigint_t new_order = nullptr;
 bigint_t new_priv = nullptr;
 ec_wei_def_init(&new_def, nullptr, nullptr, nullptr);
 init_point(new_gen);
 init_point(new_pub);
 const asn1::element *el, *el_priv;
 if (!root->is_sequence()) goto fin; // ECPrivateKey, rfc5919
 el = root->child;
 unsigned version;
 if (!(el && el->get_small_uint(version) && version == 1)) goto fin;
 el_priv = el->sibling;
 if (!(el_priv && el_priv->is_octet_string())) goto fin;
 el = el_priv->sibling;
 if (el && el->cls == asn1::CLASS_CONTEXT_SPECIFIC && el->tag == 0)
 {
  const asn1::element *el_curve = el->child;
  const curve_wei *curve = get_curve(el_curve);
  if (!curve) goto fin;
  if (param &&
      (!param->is_obj_id() || param->size != el_curve->size ||
        memcmp(param->data, el_curve->data, param->size))) goto fin;
  el = el->sibling;
  init_curve(&new_def, &new_gen, &new_order, curve);
  curve_id = curve->id;
  key_bits = curve->bits;
 } else
 {
  // PKCS #8: get curve from params
  const curve_wei *curve = get_curve(param);
  if (!curve) goto fin;
  init_curve(&new_def, &new_gen, &new_order, curve);
  curve_id = curve->id;
  key_bits = curve->bits;
 }
 if (el_priv->size != (size_t) bigint_get_byte_count(new_order)) goto fin;
 new_priv = bigint_create_bytes_be(el_priv->data, el_priv->size);
 if (el && el->cls == asn1::CLASS_CONTEXT_SPECIFIC && el->tag == 1)
 {
  const asn1::element *el_pub = el->child;
  if (!(el_pub && el_pub->is_aligned_bit_string())) goto fin;
  if (!get_point(new_pub, el_pub->data + 1, el_pub->size - 1, &new_def)) goto fin;
 } else
 {
  // calculate public key
  ec_scratch_t s;
  ec_wei_scratch_init(&s, &new_def);
  ec_wei_point_init(&new_pub, &new_def);
  ec_point_mul(&new_pub, &new_gen, &new_def, new_priv, &s);
  int res = ec_point_normalize(&new_pub, &new_def, &s);
  ec_wei_scratch_destroy(&s);
  if (!res) goto fin;
 }

 result = true;
 clear();
 def = new_def;
 gen = new_gen;
 pub = new_pub;
 order = new_order;
 priv = new_priv;
 this->curve_id = curve_id;

 fin:
 asn1::delete_tree(root);
 if (!result)
 {
  ec_wei_def_destroy(&new_def);
  ec_wei_point_destroy(&new_gen);
  ec_wei_point_destroy(&new_pub);
  bigint_destroy(new_order);
  bigint_destroy(new_priv);
 }
 return result;
}

#define GET_INT_PARAM(result) \
 if (params[i].size) return 0; \
 result = params[i].ival;

#define GET_BOOL_PARAM(result) \
 if (params[i].size) return 0; \
 result = params[i].bval;

bool pkc_ecdsa::create_signature(void *out, size_t &out_size,
                                 const void *data, size_t data_size,
                                 const param_data *params, int param_count,
                                 random_gen *rng) const
{
 if (!priv) return false;
 bool data_is_hash = false;
 bool deterministic = true;
 int hash_alg = 0;
 for (int i = 0; i < param_count; i++)
  switch (params[i].type)
  {
   case PARAM_DATA_IS_HASH:
    GET_BOOL_PARAM(data_is_hash);
    break;

   case PARAM_HASH_ALG:
    GET_INT_PARAM(hash_alg);
    break;

   case PARAM_DETERMINISTIC:
    GET_BOOL_PARAM(deterministic);
    break;

   default:
    return false;
  }

 if (!deterministic && !rng) return false;
 if (!hash_alg) return false;
 const hash_def *hd = hash_factory(hash_alg);
 if (!hd) return false;
 bigint_t h;
 if (!data_is_hash)
 {
  void *ctx = alloca(hd->context_size);
  hd->func_init(ctx);
  hd->func_update(ctx, data, data_size);
  h = bigint_create_bytes_be(hd->func_final(ctx), hd->hash_size);
 } else h = bigint_create_bytes_be(data, data_size);
 
 int shift = (hd->hash_size<<3) - bigint_get_bit_count(order);
 if (shift > 0) bigint_rshift(h, h, shift);
 if (bigint_cmp(h, order) > 0) bigint_sub(h, h, order);

 uint8_t *kbuf, *vbuf, *qdata;
 size_t qsize;
 void *ctx_hmac = nullptr;
 bigint_t r = bigint_create(0);
 bigint_t s = bigint_create(0);
 bigint_t k = bigint_create(0);
 bigint_t t1 = bigint_create(0);
 bigint_t t2 = bigint_create(0);
 if (deterministic)
 {
  kbuf = static_cast<uint8_t*>(alloca((hd->hash_size<<1) + 1));
  vbuf = kbuf + hd->hash_size;
  size_t xsize = bigint_get_byte_count(priv);
  uint8_t *xbuf = static_cast<uint8_t*>(alloca(xsize));
  bigint_get_bytes_be(priv, xbuf, xsize);
  ctx_hmac = gen_k_init(kbuf, vbuf, hd, order, h, xbuf, xsize);
 } else
 {
  qsize = bigint_get_byte_count(order);
  qdata = static_cast<uint8_t*>(alloca(qsize<<1));
  kbuf = qdata + qsize;
  bigint_get_bytes_be(order, qdata, qsize);
 }
 bool result = false;
 ec_scratch_t scratch;
 ec_point_t pt;
 ec_wei_scratch_init(&scratch, &def);
 ec_wei_point_init(&pt, &def);
 for (;;)
 {
  if (deterministic)
  {
   gen_k_create(k, kbuf, vbuf, hd->hash_size, ctx_hmac, order);
  } else
  {
   if (!get_random_range(kbuf, qsize, qdata, rng, GRR_FLAG_SECURE)) continue;
   bigint_set_bytes_be(k, kbuf, qsize);
   if (bigint_eq_word(k, 0)) continue;
  }
  ec_point_mul(&pt, &gen, &def, k, &scratch);
  if (!ec_point_affine_x(r, &pt, &def, &scratch))
  {
   if (deterministic) gen_k_next_key(kbuf, vbuf, hd->hash_size, ctx_hmac);
   continue;
  }
  bigint_mod(r, r, order);
  if (bigint_eq_word(r, 0))
  {
   if (deterministic) gen_k_next_key(kbuf, vbuf, hd->hash_size, ctx_hmac);
   continue;
  }
  if (!bigint_minv(t1, k, order)) break;
  bigint_mmul(t2, priv, r, order);
  bigint_add(t2, t2, h);
  bigint_mmul(s, t1, t2, order);
  if (!bigint_eq_word(s, 0))
  {
   result = true;
   break;
  }
  if (deterministic) gen_k_next_key(kbuf, vbuf, hd->hash_size, ctx_hmac);
 }

 free(ctx_hmac);
 bigint_destroy(t2);
 bigint_destroy(t1);
 bigint_destroy(k);
 ec_wei_point_destroy(&pt);
 ec_wei_scratch_destroy(&scratch);

 if (!result)
 {
  bigint_destroy(s);
  bigint_destroy(r);
  return false;
 }

 size_t rsize, ssize;
 uint8_t *rdata = pack_bigint(r, rsize);
 uint8_t *sdata = pack_bigint(s, ssize);
 bigint_destroy(s);
 bigint_destroy(r);

 asn1::element el_seq(asn1::TYPE_SEQUENCE);
 asn1::element el_r(asn1::TYPE_INTEGER, rdata, rsize);
 el_r.flags |= asn1::element::FLAG_OWN_BUFFER;
 el_seq.child = &el_r; 
 asn1::element el_s(asn1::TYPE_INTEGER, sdata, ssize);
 el_s.flags |= asn1::element::FLAG_OWN_BUFFER;
 el_r.sibling = &el_s;

 size_t enc_size = asn1::calc_encoded_size(&el_seq);
 if (enc_size > out_size) return false;
 return asn1::encode_def_length(out, out_size, &el_seq);
}

asn1::element *pkc_ecdsa::create_params_struct(const param_data *params, int param_count, int where) const
{
 int hash_alg = 0;
 for (int i = 0; i < param_count; i++)
  switch (params[i].type)
  {
   case PARAM_DATA_IS_HASH:
   case PARAM_DETERMINISTIC:   
    break;

   case PARAM_HASH_ALG:
    GET_INT_PARAM(hash_alg);
    break;

   default:
    return nullptr;
  }

 int alg_id;
 if (where == WHERE_SIGNATURE)
 {
  if (!hash_alg) return nullptr;
  alg_id = hash_oid_to_sign_oid(hash_alg);
  if (!alg_id) return nullptr;
 } else alg_id = ID_ECDSA;

 const oid_def *oid_alg = get(alg_id);
 if (!oid_alg) return nullptr;
 asn1::element *root = nullptr;
 if (where != WHERE_SIGNATURE)
 {
  const oid_def *oid_curve = get(curve_id);
  if (!oid_curve) return nullptr;
  root = create_alg_id(oid_alg);
  root->child->sibling = asn1::element::create(asn1::TYPE_OID, oid_curve->data, oid_curve->size);
 } else root = create_alg_id(oid_alg);
 return root;
}

bool pkc_ecdsa::verify_signature(const void *sig, size_t sig_size,
                                 const void *data, size_t data_size,
                                 const param_data *params, int param_count) const
{
 if (!pub.x) return false;

 int hash_alg = 0;
 const asn1::element *alg_info = nullptr;
 bool data_is_hash = false;

 for (int i = 0; i < param_count; i++)
  switch (params[i].type)
  {
   case PARAM_DATA_IS_HASH:
    GET_BOOL_PARAM(data_is_hash);
    break;

   case PARAM_HASH_ALG:
    GET_INT_PARAM(hash_alg);
    break;

   case PARAM_ALG_INFO:
    if (params[i].size) return false;
    alg_info = static_cast<const asn1::element*>(params[i].data);
    break;
   
   default:
    return false;
  }

 if (alg_info)
 { 
  int enc_alg;
  const asn1::element *alg_param;
  if (!parse_alg_id(enc_alg, alg_param, alg_info)) return false;
  hash_alg = sign_oid_to_hash_oid(enc_alg);
 }

 if (!hash_alg) return false;
 const hash_def *hd = hash_factory(hash_alg);
 if (!hd) return false;
 if (data_is_hash && hd->hash_size != data_size) return false;

 asn1::element *el_sig = asn1::decode(sig, sig_size, 0, nullptr);
 if (!el_sig) return false;
 bool result = false;
 if (el_sig->is_sequence())
 {
  const asn1::element *el = el_sig->child;
  if (el && el->is_valid_positive_int())
  {
   bigint_t r = bigint_create_bytes_be(el->data, el->size);
   if (!bigint_eq_word(r, 0) && bigint_cmp(r, order) < 0)
   {
    el = el->sibling;
    if (el && el->is_valid_positive_int())
    {
     bigint_t s = bigint_create_bytes_be(el->data, el->size);
     if (!bigint_eq_word(s, 0) && bigint_cmp(s, order) < 0)
     {
      bigint_t h;
      if (data_is_hash)
      {
       h = bigint_create_bytes_be(data, hd->hash_size);
      } else
      {
       void *ctx = alloca(hd->context_size);
       hd->func_init(ctx);
       hd->func_update(ctx, data, data_size);
       h = bigint_create_bytes_be(hd->func_final(ctx), hd->hash_size);
      }
      
      int qbits = bigint_get_bit_count(order);
      int shift = (hd->hash_size<<3) - qbits;
      if (shift > 0) bigint_rshift(h, h, shift);
      if (bigint_cmp(h, order) > 0) bigint_sub(h, h, order);
      bigint_t w = bigint_create(0);
      bigint_t t = bigint_create(0);
      if (bigint_minv(w, s, order))
      {
       ec_scratch_t s;
       ec_point_t p1, p2;
       bigint_mmul(t, h, w, order);
       ec_wei_point_init(&p1, &def);
       ec_wei_scratch_init(&s, &def);
       ec_point_mul(&p1, &gen, &def, t, &s);
       bigint_mmul(t, r, w, order);
       ec_wei_point_init(&p2, &def);
       ec_point_mul(&p2, &pub, &def, t, &s);
       ec_point_add(&p1, &p1, &p2, &def, &s);
       if (ec_point_affine_x(t, &p1, &def, &s))
       {
        bigint_mod(t, t, order);
        result = bigint_cmp(t, r) == 0;
       }
       ec_wei_point_destroy(&p2);
       ec_wei_point_destroy(&p1);
       ec_wei_scratch_destroy(&s);
      }
      bigint_destroy(t);
      bigint_destroy(w);
      bigint_destroy(h);
     }
     bigint_destroy(s);
    } 
   }
   bigint_destroy(r);
  }
 }
 asn1::delete_tree(el_sig);
 return result;
}

size_t pkc_ecdsa::get_max_signature_size() const
{
 // sequence: 2 header bytes
 // integers: 2 header bytes, 1 zero pad byte
 if (!order) return 0;
 return (bigint_get_byte_count(order) << 1) + 8;
}

size_t pkc_ecdsa::get_min_signature_size() const
{
 return 8;
}
