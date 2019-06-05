#ifndef __pkc_rsa_h__
#define __pkc_rsa_h__

#include "pkc_base.h"

class pkc_rsa : public pkc_base
{
 public:
  enum
  {
   PARAM_WRAPPING_ALG = 256,
   PARAM_MGF_HASH_ALG,
   PARAM_SALT,
   PARAM_RAW_SIGNATURE
  };
  
  pkc_rsa();
  virtual ~pkc_rsa() {}
  virtual int  get_id() const;
  virtual bool set_public_key(const void *data, size_t size, const asn1::element *param);
  virtual bool set_private_key(const void *data, size_t size, const asn1::element *param);
  virtual void set_rng(random_gen *rng) {}
  virtual bool create_signature(void *out, size_t &out_size,
                                const void *data, size_t data_size,
                                const param_data *params, int param_count,
                                random_gen *rng) const;
  virtual asn1::element *create_params_struct(const param_data *params, int param_count, int where) const;
  virtual bool verify_signature(const void *sig, size_t sig_size,
                                const void *data, size_t data_size,
                                const param_data *params, int param_count) const;
  virtual size_t get_max_signature_size() const { return modulus.size; }
  virtual size_t get_min_signature_size() const { return modulus.size; }
  virtual int get_key_bits() const;

  // in == out is allowed
  bool power_public(void *out, size_t &out_size, const void *in, size_t in_size) const;
  bool power_private(void *out, size_t &out_size, const void *in, size_t in_size) const;
  size_t get_modulus_size() const { return modulus.size; }
  static int sign_oid_to_hash_oid(int id);
  static int hash_oid_to_sign_oid(int id);
 
 private:
  data_buffer modulus;
  data_buffer pub_exp_large;
  unsigned pub_exp_small;
  data_buffer priv_exp;  
};

#endif // __pkc_rsa_h__
