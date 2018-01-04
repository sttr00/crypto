#ifndef __pkc_ecdsa_h__
#define __pkc_ecdsa_h__

#include "pkc_base.h"
#include <crypto/ec/ec_wei.h>

class pkc_ecdsa : public pkc_base
{
 public:
  enum
  {
   PARAM_HASH_ALG = 64,
   PARAM_DETERMINISTIC = 65
  };
  
  pkc_ecdsa();
  virtual ~pkc_ecdsa();
  virtual int  get_id() const;
  virtual bool set_public_key(const void *data, size_t size, const asn1::element *param);
  virtual bool set_private_key(const void *data, size_t size, const asn1::element *param);
  virtual void set_rng(random_gen *rng) { this->rng = rng; }
  virtual bool create_signature(void *out, size_t &out_size,
                                const void *data, size_t data_size,
                                const param_data *params, int param_count) const;
  virtual asn1::element *create_params_struct(const param_data *params, int param_count, int where) const;
  virtual bool verify_signature(const void *sig, size_t sig_size,
                                const void *data, size_t data_size,
                                const asn1::element *param) const;
  virtual size_t get_max_signature_size() const;

  static int sign_oid_to_hash_oid(int id);
  static int hash_oid_to_sign_oid(int id);
 
 private:  
  random_gen *rng;
  ec_wei_def_t def;
  ec_point_t gen;
  ec_point_t pub;
  bigint_t order;
  bigint_t priv;
  int curve_id;

  void clear();
};

#endif // __pkc_ecdsa_h__
