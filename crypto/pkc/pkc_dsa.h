#ifndef __pkc_dsa_h__
#define __pkc_dsa_h__

#include "pkc_base.h"

class pkc_dsa : public pkc_base
{
 public:
  enum
  {
   PARAM_HASH_ALG = 64,
   PARAM_DETERMINISTIC = 65
  };
  
  pkc_dsa();
  virtual ~pkc_dsa() {}
  virtual int  get_id() const;
  virtual bool set_public_key(const void *data, size_t size, const asn1::element *param);
  virtual bool set_private_key(const void *data, size_t size);
  virtual void set_rng(random_gen *rng) { this->rng = rng; }
  virtual bool create_signature(void *out, size_t &out_size,
                                const void *data, size_t data_size,
                                const param_data *params, int param_count) const;
  virtual asn1::element *create_params_struct(const param_data *params, int param_count, int where) const;
  virtual bool verify_signature(const void *sig, size_t sig_size,
                                const void *data, size_t data_size,
                                const asn1::element *param) const;
  virtual size_t get_max_signature_size() const;

  int get_pbits() const;
  int get_qbits() const;
  static int sign_oid_to_hash_oid(int id);
  static int hash_oid_to_sign_oid(int id);
 
 private:
  data_buffer p, g, q, y, x;
  random_gen *rng;
};

#endif // __pkc_dsa_h__
