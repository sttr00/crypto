#ifndef __pkc_base_h__
#define __pkc_base_h__

#include <crypto/rng/random_gen.h>
#include <crypto/asn1/element.h>

class pkc_base
{
 public:
  struct data_buffer
  {
   const void *data;
   size_t size;
 
   void clear() { data = nullptr; size = 0; }
  };
  
  struct param_data
  {
   int type;
   union
   {
    const void *data;
    int ival;
    bool bval;
   };
   size_t size;
  };

  enum
  {
   PARAM_DATA_IS_HASH,
  };

  enum
  {
   WHERE_SIGNATURE = 1,
   WHERE_PUBLIC_KEY_INFO
  };
  
  pkc_base() {}
  virtual ~pkc_base() {}
  virtual int  get_id() const = 0;
  virtual bool set_public_key(const void *data, size_t size, const asn1::element *param) = 0;
  virtual bool set_private_key(const void *data, size_t size, const asn1::element *param) = 0;
  virtual void set_rng(random_gen *rng) = 0;
  virtual bool create_signature(void *out, size_t &out_size,
                                const void *hash, size_t hash_size,
                                const param_data *params, int param_count) const = 0;
  virtual asn1::element *create_params_struct(const param_data *params, int param_count, int where) const = 0;
  virtual bool verify_signature(const void *sig, size_t sig_size,
                                const void *data, size_t data_size,
                                const asn1::element *alg_info) const = 0;
  virtual size_t get_max_signature_size() const = 0;

 private:
  pkc_base(const pkc_base &);
  pkc_base& operator= (const pkc_base &);
};

#endif // __pkc_base_h__
