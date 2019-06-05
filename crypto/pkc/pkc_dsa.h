#ifndef __pkc_dsa_h__
#define __pkc_dsa_h__

#include "pkc_base.h"

class pkc_dsa : public pkc_base
{
 public:
  enum
  {
   PARAM_DETERMINISTIC = 64,
   PARAM_RAW_SIGNATURE
  };
  
  pkc_dsa();
  virtual ~pkc_dsa() { operator delete(ytemp); }
  virtual int  get_id() const;
  virtual bool set_public_key(const void *data, size_t size, const asn1::element *param);
  virtual bool set_private_key(const void *data, size_t size, const asn1::element *param);
  virtual bool create_signature(void *out, size_t &out_size,
                                const void *data, size_t data_size,
                                const param_data *params, int param_count,
                                random_gen *rng) const;
  virtual asn1::element *create_params_struct(const param_data *params, int param_count, int where) const;
  virtual bool verify_signature(const void *sig, size_t sig_size,
                                const void *data, size_t data_size,
                                const param_data *params, int param_count) const;
  virtual size_t get_max_signature_size() const;
  virtual size_t get_min_signature_size() const;
  virtual int get_key_bits() const { return p.size << 3; }

  int get_pbits() const;
  int get_qbits() const;
  static int sign_oid_to_hash_oid(int id);
  static int hash_oid_to_sign_oid(int id);
  static bool check_bit_len(int pbits, int qbits);
 
 private:
  data_buffer p, g, q, y, x;
  uint8_t *ytemp;

  bool get_params(const asn1::element* &el, data_buffer &res_p, data_buffer &res_q, data_buffer &res_g);
  bool verify_signature(data_buffer r_buf, data_buffer s_buf, const void *digest, size_t digest_size) const;
};

#endif // __pkc_dsa_h__
