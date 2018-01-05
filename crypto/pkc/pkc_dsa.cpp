#include "pkc_dsa.h"
#include "utils.h"
#include <crypto/asn1/decoder.h>
#include <crypto/asn1/encoder.h>
#include <crypto/oid_const.h>
#include <crypto/utils/random_range.h>
#include <crypto/hash_factory.h>
#include <bigint/bigint.h>
#include <platform/alloca.h>

using namespace oid;

#define countof(a) (sizeof(a)/sizeof(a[0]))

static const size_t MIN_BITS = 512;
static const size_t MAX_BITS = 16384;

void *gen_k_init(uint8_t *k, uint8_t *v, const hash_def *hd, const bigint_t q, const bigint_t h, const void *x, int xsize);
void gen_k_create(bigint_t result, uint8_t *k, uint8_t *v, int hash_size, void *ctx_hmac, const bigint_t q);
void gen_k_next_key(uint8_t *k, uint8_t *v, int hash_size, void *ctx_hmac);

static const uint16_t dsa_oid_pairs[] =
{
 ID_SIGN_DSA_SHA1,     ID_HASH_SHA1,
 ID_SIGN_DSA_SHA224,   ID_HASH_SHA224,
 ID_SIGN_DSA_SHA256,   ID_HASH_SHA256,
 ID_SIGN_DSA_SHA384,   ID_HASH_SHA384,
 ID_SIGN_DSA_SHA512,   ID_HASH_SHA512,
 ID_SIGN_DSA_SHA3_224, ID_HASH_SHA3_224,
 ID_SIGN_DSA_SHA3_256, ID_HASH_SHA3_256,
 ID_SIGN_DSA_SHA3_384, ID_HASH_SHA3_384,
 ID_SIGN_DSA_SHA3_512, ID_HASH_SHA3_512
};

static const uint16_t bit_len_pairs[] =
{
 1024, 160,
 2048, 224,
 2048, 256,
 3072, 256
};

static const bool check_bit_len(int pbits, int qbits)
{
 for (unsigned i = 0; i < countof(bit_len_pairs); i += 2)
  if (pbits >= bit_len_pairs[i]-7 && pbits <= bit_len_pairs[i]+8 &&
      qbits >= bit_len_pairs[i+1] && qbits <= bit_len_pairs[i+1]+8) return true;
 return false;
}

pkc_dsa::pkc_dsa()
{
 p.clear();
 g.clear();
 q.clear();
 y.clear();
 x.clear();
 rng = nullptr;
 ytemp = nullptr;
}

int pkc_dsa::get_id() const
{
 return ID_DSA;
}

int pkc_dsa::sign_oid_to_hash_oid(int id)
{
 for (unsigned i = 0; i < countof(dsa_oid_pairs); i += 2)
  if (dsa_oid_pairs[i] == id) return dsa_oid_pairs[i + 1];
 return 0;
}

int pkc_dsa::hash_oid_to_sign_oid(int id)
{
 for (unsigned i = 0; i < countof(dsa_oid_pairs); i += 2)
  if (dsa_oid_pairs[i + 1] == id) return dsa_oid_pairs[i];
 return 0;
}

bool pkc_dsa::get_params(const asn1::element* &el, pkc_base::data_buffer &res_p, pkc_base::data_buffer &res_q, pkc_base::data_buffer &res_g)
{
 if (!(el && el->is_valid_positive_int())) return false; 
 get_integer(res_p, el);
 el = el->sibling;
 if (!(el && el->is_valid_positive_int())) return false; 
 get_integer(res_q, el);
 int pbits = get_bits(res_p);
 int qbits = get_bits(res_q);
 if (!check_bit_len(pbits, qbits)) return false;
 el = el->sibling;
 if (!(el && el->is_valid_positive_int())) return false; 
 get_integer(res_g, el);
 if (!is_less(res_g, res_p)) return false;
 el = el->sibling;
 return true;
}

bool pkc_dsa::set_public_key(const void *data, size_t size, const asn1::element *param)
{
 if (!(param && param->is_sequence())) return false;
 data_buffer res_p, res_q, res_g, res_y;
 const asn1::element *el = param->child;
 if (!get_params(el, res_p, res_q, res_g)) return false;
 bool result = false;
 asn1::element *el_pub = asn1::decode(data, size, 0, nullptr); 
 if (el_pub && !el_pub->sibling && el_pub->is_valid_positive_int())
 {
  get_integer(res_y, el_pub);
  if (is_less(res_y, res_p))
  {
   result = true;
   p = res_p;
   g = res_g;
   q = res_q;
   y = res_y;
   // new public key is set, clear private key
   x.clear();
   operator delete(ytemp);
   ytemp = nullptr;
  }  
  asn1::delete_tree(el_pub);
 }
 return result;
}

bool pkc_dsa::set_private_key(const void *data, size_t size, const asn1::element *param)
{
 asn1::element *root = asn1::decode(data, size, 0, nullptr); 
 if (!root) return false;
 bool result = false;
 data_buffer res_p, res_q, res_g, res_y, res_x;
 if (root->is_sequence())
 {
  const asn1::element *el = root->child;
  unsigned version;
  if (!(el && el->get_small_uint(version) && version == 0)) goto fin;
  el = el->sibling;
  if (!get_params(el, res_p, res_q, res_g)) goto fin;
  if (!(el && el->is_valid_positive_int())) goto fin;
  get_integer(res_y, el);
  if (!is_less(res_y, res_p)) goto fin;
  el = el->sibling;
  if (!(el && el->is_valid_positive_int())) goto fin;
  get_integer(res_x, el);
  if (!is_less(res_x, res_q)) goto fin;
  result = true;
  p = res_p;
  g = res_g;
  q = res_q;
  y = res_y;
  x = res_x;
  operator delete(ytemp);
  ytemp = nullptr;
 } else
 if (root->is_valid_positive_int() && param && param->is_sequence())
 {
  const asn1::element *el = param->child;
  if (!get_params(el, res_p, res_q, res_g)) goto fin;
  get_integer(res_x, root);
  if (!is_less(res_x, res_q)) goto fin;
  result = true;
  p = res_p;
  g = res_g;
  q = res_q;
  x = res_x; 
  // calculate public key
  bigint_t pv = bigint_create_bytes_be(res_p.data, res_p.size);
  bigint_t xv = bigint_create_bytes_be(res_x.data, res_x.size);
  bigint_t gv = bigint_create_bytes_be(res_g.data, res_g.size);
  bigint_t yv = bigint_create(0);
  bigint_mpow(yv, gv, xv, pv);
  operator delete(ytemp);
  size_t out_size = bigint_get_byte_count(yv);
  ytemp = static_cast<uint8_t*>(operator new(out_size));
  bigint_get_bytes_be(yv, ytemp, out_size);
  bigint_destroy(yv);
  bigint_destroy(gv);
  bigint_destroy(xv);
  bigint_destroy(pv);
  y.data = ytemp;
  y.size = out_size;
 }
 fin:
 asn1::delete_tree(root);
 return result;
}

#define GET_INT_PARAM(result) \
 if (params[i].size) return 0; \
 result = params[i].ival;

#define GET_BOOL_PARAM(result) \
 if (params[i].size) return 0; \
 result = params[i].bval;

bool pkc_dsa::create_signature(void *out, size_t &out_size,
                               const void *data, size_t data_size,
                               const param_data *params, int param_count) const
{
 if (!x.data) return false;
 bool data_is_hash = false;
 #ifdef BROKEN_HASH_TRUNCATION
 bool deterministic = false;
 #else
 bool deterministic = true;
 #endif
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

   #ifndef BROKEN_HASH_TRUNCATION
   case PARAM_DETERMINISTIC:
    GET_BOOL_PARAM(deterministic);
    break;
   #endif

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
 
 uint8_t *kbuf, *vbuf;
 void *ctx_hmac = nullptr;
 bigint_t r = bigint_create(0);
 bigint_t s = bigint_create(0);
 bigint_t k = bigint_create(0);
 bigint_t t1 = bigint_create(0);
 bigint_t t2 = bigint_create(0);
 bigint_t xv = bigint_create_bytes_be(x.data, x.size);
 bigint_t pv = bigint_create_bytes_be(p.data, p.size);
 bigint_t qv = bigint_create_bytes_be(q.data, q.size);
 bigint_t gv = bigint_create_bytes_be(g.data, g.size);
 #ifdef BROKEN_HASH_TRUNCATION
 int shift = hd->hash_size - static_cast<int>(q.size);
 if (shift > 0) bigint_rshift(h, h, shift<<3);
 #else
 int shift = (hd->hash_size<<3) - bigint_get_bit_count(qv);
 if (shift > 0) bigint_rshift(h, h, shift);
 if (bigint_cmp(h, qv) > 0) bigint_sub(h, h, qv);
 #endif
 if (deterministic)
 {
  kbuf = static_cast<uint8_t*>(alloca((hd->hash_size<<1) + 1));
  vbuf = kbuf + hd->hash_size;
  ctx_hmac = gen_k_init(kbuf, vbuf, hd, qv, h, x.data, x.size);
 } else kbuf = static_cast<uint8_t*>(alloca(q.size));
 bool result = false;
 for (;;)
 {
  if (deterministic)
  {
   gen_k_create(k, kbuf, vbuf, hd->hash_size, ctx_hmac, qv);
  } else
  {
   if (!get_random_range(kbuf, q.size, q.data, rng, GRR_FLAG_SECURE)) continue;
   bigint_set_bytes_be(k, kbuf, q.size);
   if (bigint_eq_word(k, 0)) continue;
  }
  bigint_mpow(t1, gv, k, pv);
  bigint_mod(r, t1, qv);
  if (bigint_eq_word(r, 0))
  {
   if (deterministic) gen_k_next_key(kbuf, vbuf, hd->hash_size, ctx_hmac);
   continue;
  }
  if (!bigint_minv(t1, k, qv)) break;
  bigint_mmul(t2, xv, r, qv);
  bigint_add(t2, t2, h);
  bigint_mmul(s, t1, t2, qv);
  if (!bigint_eq_word(s, 0))
  {
   result = true;
   break;
  }
  if (deterministic) gen_k_next_key(kbuf, vbuf, hd->hash_size, ctx_hmac);
 }

 free(ctx_hmac);
 bigint_destroy(gv);
 bigint_destroy(qv);
 bigint_destroy(pv);
 bigint_destroy(xv);
 bigint_destroy(t2);
 bigint_destroy(t1);
 bigint_destroy(k);

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

static void fill_element_from_data_buffer(asn1::element *el, const pkc_base::data_buffer buf)
{
 el->data = static_cast<const uint8_t*>(buf.data);
 el->size = buf.size;
 // DSA parameter buffers are only set from ASN.1, therefore the leading zero must be there
 if (el->data[0] & 0x80)
 {
  el->data--;
  el->size++;
 }
}

asn1::element *pkc_dsa::create_params_struct(const param_data *params, int param_count, int where) const
{
 int hash_alg = 0;
 for (int i = 0; i < param_count; i++)
  switch (params[i].type)
  {
   case PARAM_DATA_IS_HASH:
   #ifndef BROKEN_HASH_TRUNCATION
   case PARAM_DETERMINISTIC:
   #endif
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
 } else
 {
  if (!p.data) return nullptr;
  alg_id = ID_DSA;
 }

 const oid_def *def = get(alg_id);
 if (!def) return nullptr;
 asn1::element *root = create_alg_id(def);
 if (where != WHERE_SIGNATURE)
 {
  asn1::element *seq = asn1::element::create(asn1::TYPE_SEQUENCE);
  asn1::element *el_p = asn1::element::create(asn1::TYPE_INTEGER);
  fill_element_from_data_buffer(el_p, p);
  asn1::element *el_q = asn1::element::create(asn1::TYPE_INTEGER);
  fill_element_from_data_buffer(el_q, q);
  asn1::element *el_g = asn1::element::create(asn1::TYPE_INTEGER);
  fill_element_from_data_buffer(el_g, g);
  seq->child = el_p;
  el_p->sibling = el_q;
  el_q->sibling = el_g;
  root->child->sibling = seq;
 }
 return root;
}

bool pkc_dsa::verify_signature(const void *sig, size_t sig_size,
                               const void *data, size_t data_size,
                               const asn1::element *alg_info) const
{
 if (!y.data) return false;
 int alg;
 const asn1::element *alg_param;
 if (!parse_alg_id(alg, alg_param, alg_info)) return false;
 int hash_alg = sign_oid_to_hash_oid(alg);
 if (!hash_alg) return false;
 const hash_def *hd = hash_factory(hash_alg);
 if (!hd) return false;
 asn1::element *el_sig = asn1::decode(sig, sig_size, 0, nullptr);
 if (!el_sig) return false;
 bool result = false;
 if (el_sig->is_sequence())
 {
  const asn1::element *el = el_sig->child;
  if (el && el->is_valid_positive_int())
  {
   data_buffer r_buf, s_buf;
   get_integer(r_buf, el);
   el = el->sibling;
   if (el && el->is_valid_positive_int())
   {
    get_integer(s_buf, el);
    if (is_less(r_buf, q) && is_less(s_buf, q))
    {
     void *ctx = alloca(hd->context_size);
     hd->func_init(ctx);
     hd->func_update(ctx, data, data_size);
     bigint_t h = bigint_create_bytes_be(hd->func_final(ctx), hd->hash_size);
     bigint_t r = bigint_create_bytes_be(r_buf.data, r_buf.size);
     bigint_t s = bigint_create_bytes_be(s_buf.data, s_buf.size);
     bigint_t pv = bigint_create_bytes_be(p.data, p.size);
     bigint_t qv = bigint_create_bytes_be(q.data, q.size);
     bigint_t gv = bigint_create_bytes_be(g.data, g.size);
     bigint_t yv = bigint_create_bytes_be(y.data, y.size);
     bigint_t w = bigint_create(0);
     bigint_t t1 = bigint_create(0);
     bigint_t t2 = bigint_create(0);
     #ifdef BROKEN_HASH_TRUNCATION
     int shift = hd->hash_size - static_cast<int>(q.size);
     if (shift > 0) bigint_rshift(h, h, shift<<3);
     #else
     int qbits = bigint_get_bit_count(qv);
     int shift = (hd->hash_size<<3) - qbits;
     if (shift > 0) bigint_rshift(h, h, shift);
     if (bigint_cmp(h, qv) > 0) bigint_sub(h, h, qv);
     #endif
     if (bigint_minv(w, s, qv))
     {
      bigint_mmul(t1, h, w, qv);
      bigint_mmul(t2, r, w, qv);
      bigint_mpow(t1, gv, t1, pv);
      bigint_mpow(t2, yv, t2, pv);
      bigint_mmul(t1, t1, t2, pv);
      bigint_mod(t1, t1, qv);
      result = bigint_cmp(t1, r) == 0;
     }
     bigint_destroy(t2);
     bigint_destroy(t1);
     bigint_destroy(w);
     bigint_destroy(yv);
     bigint_destroy(gv);
     bigint_destroy(qv);
     bigint_destroy(pv);
     bigint_destroy(s);
     bigint_destroy(r);
     bigint_destroy(h);
    }
   }
  }
 }
 asn1::delete_tree(el_sig);
 return result;
}

size_t pkc_dsa::get_max_signature_size() const
{
 // sequence: 2 header bytes
 // integers: 2 header bytes, 1 zero pad byte
 return (q.size << 1) + 8;
}
