#ifndef __pkc_utils_h__
#define __pkc_utils_h__

#include "pkc_base.h"
#include <crypto/oid_def.h>
#include <crypto/oid_search.h>
#include <platform/bits.h>
#include <cstring>

static inline int get_bits(pkc_base::data_buffer x)
{
 if (!x.size) return 0;
 return ((x.size-1)<<3) + bsr32(*static_cast<const uint8_t*>(x.data)) + 1;
}

static inline bool is_less(pkc_base::data_buffer x, pkc_base::data_buffer y)
{
 if (x.size < y.size) return true;
 if (x.size > y.size) return false;
 return memcmp(x.data, y.data, x.size) < 0;
}

static inline bool is_equal(pkc_base::data_buffer x, pkc_base::data_buffer y)
{
 if (x.size != y.size) return false;
 return memcmp(x.data, y.data, x.size) == 0;
}

static inline void get_integer(pkc_base::data_buffer &out, const asn1::element *el)
{
 if (el->data[0]) out.data = el->data, out.size = el->size;
  else out.data = el->data + 1, out.size = el->size - 1;
}

static void xor_data(uint8_t *out, const uint8_t *in, size_t size)
{
 for (size_t i = 0; i < size; i++) out[i] ^= in[i];
}

static bool parse_alg_id(int &alg, const asn1::element* &params, const asn1::element *el)
{
 if (!(el && el->is_sequence())) return false;
 el = el->child;
 if (!(el && el->is_obj_id())) return false;
 alg = oid::find(el->data, el->size); 
 if (!alg) return false;
 params = el->sibling;
 return true;
}

static asn1::element *create_alg_id(const oid::oid_def *def)
{
 asn1::element *el = asn1::element::create(asn1::TYPE_SEQUENCE);
 el->child = asn1::element::create(asn1::TYPE_OID, def->data, def->size);
 return el;
}

static asn1::element *create_tagged_element(unsigned tag, asn1::element *inner)
{
 asn1::element *outer = asn1::element::create();
 outer->cls = asn1::CLASS_CONTEXT_SPECIFIC;
 outer->tag = tag;
 outer->child = inner;
 return outer;
}

static void append_child(asn1::element *parent, asn1::element *child, asn1::element* &prev)
{
 if (!prev) parent->child = child; else prev->sibling = child;
 prev = child;
}

static size_t pack_small_uint(uint8_t out[], unsigned val)
{
 if (!val)
 {
  out[0] = 0;
  return 1;
 }
 size_t out_size = 0;
 int shift = (bsr32(val) >> 3) << 3;
 if ((val >> shift) & 0x80) out[out_size++] = 0;
 while (shift >= 0)
 {
  out[out_size++] = (val >> shift) & 0xFF;
  shift -= 8;
 }
 return out_size;
}

#endif // __pkc_utils_h__
