#ifndef __asn1_element_h__
#define __asn1_element_h__

#include <stdint.h>
#include <stddef.h>

namespace asn1
{

 enum
 {
  CLASS_UNIVERSAL,
  CLASS_APPLICATION,
  CLASS_CONTEXT_SPECIFIC,
  CLASS_PRIVATE
 };

 enum
 {
  TYPE_BOOLEAN          = 1,
  TYPE_INTEGER          = 2,
  TYPE_BIT_STRING       = 3,
  TYPE_OCTET_STRING     = 4,
  TYPE_NULL             = 5,
  TYPE_OID              = 6,
  TYPE_REAL             = 9,
  TYPE_ENUMERATED       = 10,
  TYPE_UTF8_STRING      = 12,
  TYPE_RELATIVE_OID     = 13,
  TYPE_SEQUENCE         = 16,
  TYPE_SET              = 17,
  TYPE_NUMERIC_STRING   = 18,
  TYPE_PRINTABLE_STRING = 19,
  TYPE_TELETEX_STRING   = 20,
  TYPE_VIDEOTEX_STRING  = 21,
  TYPE_IA5_STRING       = 22,
  TYPE_UTC_TIME         = 23,
  TYPE_GENERALIZED_TIME = 24,
  TYPE_GRAPHIC_STRING   = 25,
  TYPE_VISIBLE_STRING   = 26,
  TYPE_GENERAL_STRING   = 27,
  TYPE_UNIVERSAL_STRING = 28,
  TYPE_CHARACTER_STRING = 29,
  TYPE_BMP_STRING       = 30
 };


 class element
 {
  public:
   enum
   {
    FLAG_OWN_BUFFER = 1,
    FLAG_HEAP_ALLOC = 2
   };
   
   const uint8_t *data;
   size_t size;
   element *child;
   element *sibling;
   unsigned tag;
   uint8_t cls;
   uint8_t flags;
   
   element();
   element(const void *data, size_t size);
   element(unsigned type, const void *data = nullptr, size_t size = 0);
   ~element();

   static element *create();
   static element *create(const void *data, size_t size);
   static element *create(unsigned type, const void *data = nullptr, size_t size = 0);

   bool get_small_uint(unsigned &val) const;
   bool get_small_int(int &val) const;   
   bool is_valid_int() const;
   bool is_valid_positive_int() const;
   bool is_sequence() const;
   bool is_obj_id() const;
   bool is_octet_string() const;
   bool is_aligned_bit_string() const;

   element *clone_tree() const;
   bool remove_child(element *old_child);
   bool replace_child(element *old_child, element *new_child);

   element(const element &) = delete;
   element &operator= (const element &) = delete;
 };

 void delete_tree(element *el);

}

#endif // __asn1_element_h__
