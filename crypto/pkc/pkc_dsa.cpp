#include "pkc_dsa.h"
#include "utils.h"
#include <crypto/asn1/decoder.h>
#include <crypto/asn1/encoder.h>
#include <crypto/oid_const.h>
#include <crypto/utils/random_range.h>
#include <crypto/hash_factory.h>
#include <bigint/bigint.h>
#include <cassert>

using namespace oid;

#define countof(a) (sizeof(a)/sizeof(a[0]))

static const size_t MIN_BITS = 512;
static const size_t MAX_BITS = 16384;

static const uint16_t dsa_oid_pairs[] =
{
 ID_SIGN_DSA_SHA1,   ID_HASH_SHA1,
 ID_SIGN_DSA_SHA224, ID_HASH_SHA224,
 ID_SIGN_DSA_SHA256, ID_HASH_SHA256
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
      bit_len_pairs[i+1] == qbits) return true;
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

bool pkc_dsa::set_public_key(const void *data, size_t size, const asn1::element *param)
{
 if (!param) return false;
 int alg_id;
 const asn1::element *alg_param;
 if (!parse_alg_id(alg_id, alg_param, param) || alg_id != ID_DSA) return false;
 if (!(alg_param && alg_param->is_sequence())) return false;
 data_buffer res_p, res_q, res_g, res_y;
 const asn1::element *el = alg_param->child;
 if (!(el && el->is_valid_positive_int())) return false; 
 get_integer(res_p, el);
 el = el->sibling;
 if (!(el && el->is_valid_positive_int())) return false; 
 get_integer(res_q, el);
 el = el->sibling;
 if (!(el && el->is_valid_positive_int())) return false; 
 get_integer(res_g, el);
 if (!is_less(res_g, res_p)) return false;
 int pbits = get_bits(res_p);
 int qbits = get_bits(res_q);
 if (!check_bit_len(pbits, qbits)) return false;
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
  }  
  asn1::delete_tree(el_pub);
 }
 return result;
}

bool pkc_dsa::set_private_key(const void *data, size_t size)
{
 asn1::element *root = asn1::decode(data, size, 0, nullptr); 
 if (!root) return false;
 bool result = false;
 if (root->is_sequence())
 {
  data_buffer res_p, res_q, res_g, res_y, res_x;
  const asn1::element *el = root->child;
  unsigned version;
  if (!(el && el->get_small_uint(version) && version == 0)) goto fin;
  el = el->sibling;
  if (!(el && el->is_valid_positive_int())) goto fin;
  get_integer(res_p, el);
  if (p.data && !is_equal(res_p, p)) goto fin;
  el = el->sibling;
  if (!(el && el->is_valid_positive_int())) goto fin;
  get_integer(res_q, el);
  if (q.data)
  {
   if (!is_equal(res_q, q)) goto fin;
  } else
  {
   int pbits = get_bits(res_p);
   int qbits = get_bits(res_q);
   if (!check_bit_len(pbits, qbits)) goto fin;
  }
  el = el->sibling;
  if (!(el && el->is_valid_positive_int())) goto fin;
  get_integer(res_g, el);
  if (g.data)
  {
   if (!is_equal(res_g, g)) goto fin;
  } else
  {
   if (!is_less(res_g, res_p)) goto fin;
  }
  el = el->sibling;
  if (!(el && el->is_valid_positive_int())) goto fin;
  get_integer(res_y, el);
  if (y.data)
  {
   if (!is_equal(res_y, y)) goto fin;
  } else
  {
   if (!is_less(res_y, res_p)) goto fin;
  }
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
 }
 fin:
 asn1::delete_tree(root);
 return result;
}

static uint8_t *pack_bigint(const bigint_t num, size_t &out_size)
{
 int bits = bigint_get_bit_count(num);
 size_t pad = (bits & 7)? 0 : 1;
 size_t bytes = (bits + 7) >> 3;
 uint8_t *out = static_cast<uint8_t*>(operator new(bytes + pad));
 if (pad) *out = 0;
 int size = bigint_get_bytes_be(num, out + pad, bytes);
 assert(size > 0);
 out_size = size + pad;
 return out;
}

#define GET_INT_PARAM(result) \
 if (params[i].size) return false; \
 result = params[i].ival;

#define GET_BOOL_PARAM(result) \
 if (params[i].size) return false; \
 result = params[i].bval;

bool pkc_dsa::create_signature(void *out, size_t &out_size,
                               const void *data, size_t data_size,
                               const param_data *params, int param_count) const
{
 if (!x.data || !rng) return false;
 bool data_is_hash = false;
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
  
   default:
    return false;
  }

 if (!hash_alg) return false;
 const hash_def *hd = hash_factory(hash_alg);
 if (!hd) return false;
 if (hd->hash_size > static_cast<int>(q.size)) return false;
 bigint_t h;
 if (!data_is_hash)
 {
  void *ctx = alloca(hd->context_size);
  hd->func_init(ctx);
  hd->func_update(ctx, data, data_size);
  h = bigint_create_bytes_be(hd->func_final(ctx), hd->hash_size);
 } else h = bigint_create_bytes_be(data, data_size);
 
 void *kbuf = alloca(q.size);
 bigint_t r = bigint_create(0);
 bigint_t s = bigint_create(0);
 bigint_t k = bigint_create(0);
 bigint_t t1 = bigint_create(0);
 bigint_t t2 = bigint_create(0);
 bigint_t xv = bigint_create_bytes_be(x.data, x.size);
 bigint_t pv = bigint_create_bytes_be(p.data, p.size);
 bigint_t qv = bigint_create_bytes_be(q.data, q.size);
 bigint_t gv = bigint_create_bytes_be(g.data, g.size);
 bool result = false;
 while (!result)
 {
  if (!get_random_range(kbuf, q.size, q.data, rng, GRR_FLAG_SECURE)) continue;
  bigint_set_bytes_be(k, kbuf, q.size);
  if (bigint_eq_word(k, 0)) continue;
  bigint_mpow(t1, gv, k, pv);
  bigint_mod(r, t1, qv);
  if (bigint_eq_word(r, 0)) continue;
  if (!bigint_minv(t1, k, qv)) break;
  bigint_mmul(t2, xv, r, qv);
  bigint_add(t2, t2, h);
  bigint_mmul(s, t1, t2, qv);
  if (!bigint_eq_word(s, 0)) result = true;
 }
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
                               const asn1::element *param) const
{
 if (!y.data) return false;
 int alg;
 const asn1::element *alg_param;
 if (!parse_alg_id(alg, alg_param, param)) return false;
 int hash_alg = sign_oid_to_hash_oid(alg);
 if (!hash_alg) return false;
 const hash_def *hd = hash_factory(hash_alg);
 if (!hd || static_cast<size_t>(hd->hash_size) > q.size) return false;
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
