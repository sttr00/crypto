#include "encoder.h"
#include <platform/bits.h>
#include <platform/word.h>
#include <vector>
#include <cstring>

using std::vector;

namespace asn1
{

struct encoder_stack_item
{
 element *last;
 size_t *psize;
};

static inline size_t count_tag_bytes(unsigned tag)
{
 if (tag < 31) return 1;
 return (bsr32(tag) + 7)/7; 
}

static inline size_t count_length_bytes(size_t size)
{
 if (size < 128) return 1;
 #ifdef ENV_64BIT
 int bs = bsr64(size);
 #else
 int bs = bsr32(size);
 #endif
 return 1 + ((bs + 8) >> 3);
}

size_t calc_encoded_size(element *el)
{
 size_t size = 0;
 vector<encoder_stack_item> v;
 encoder_stack_item item = { el, &size };
 v.push_back(item);
 for (;;)
 {
  encoder_stack_item &top = v.back();
  if (!top.last)
  {
   size_t size = *top.psize;
   v.pop_back();
   if (v.empty()) break;
   *v.back().psize += count_length_bytes(size) + size;
   continue;
  }
  element *el = top.last;
  if (el->child)
  {
   item.last = el->child;
   item.psize = &el->size;
   el->size = 0;
   *top.psize += count_tag_bytes(el->child->tag);
   top.last = el->sibling;
   v.push_back(item);
   continue;
  }
  *top.psize += count_length_bytes(el->size) + count_tag_bytes(el->tag) + el->size;
  top.last = el->sibling;
 }
 return size;
}

bool encode_def_length(void *out, size_t &size, const element *el)
{
 uint8_t *p = static_cast<uint8_t*>(out);
 vector<const element*> v;
 v.push_back(el);
 while (!v.empty())
 {
  el = v.back();
  if (!el)
  {
   v.pop_back();
   continue;
  }
  size_t tag_bytes = count_tag_bytes(el->tag);
  size_t len_bytes = count_length_bytes(el->size);  
  size_t hdr_bytes = tag_bytes + len_bytes;
  if (hdr_bytes > size) return false;
  size -= hdr_bytes;
  uint8_t tag = el->cls << 6;
  if (el->child) tag |= 0x20;
  if (el->tag < 31)
  {
   *p++ = tag | el->tag;
  } else
  {
   *p++ = tag | 0x1F;
   unsigned shift = static_cast<unsigned>((tag_bytes-2)*7);
   while (shift)
   {
    *p++ = (el->tag >> shift) | 0x80;
    shift -= 7;
   }
   *p++ = el->tag & 0x7F;
  }
  if (el->size < 128)  
  {
   *p++ = static_cast<uint8_t>(el->size);
  } else
  {
   *p++ = static_cast<uint8_t>(--len_bytes | 0x80);
   int shift = static_cast<int>((len_bytes-1)<<3);
   while (shift >= 0)
   {
    *p++ = static_cast<uint8_t>(el->size >> shift);
    shift -= 8;
   }
  }
  v.back() = el->sibling;
  if (!el->child)
  {
   if (el->size > size) return false;
   memcpy(p, el->data, el->size);
   p += el->size;
   size -= el->size;
  } else v.push_back(el->child);
 }
 size = p - static_cast<uint8_t*>(out);
 return true;
}

size_t get_indef_length_encoded_size(const element *el)
{
 size_t size = 0;
 vector<const element*> v; 
 v.push_back(el);
 while (!v.empty())
 {
  el = v.back();
  if (!el)
  {
   v.pop_back();
   continue;
  }
  const element *child = el->child;
  size += count_tag_bytes(el->tag);
  v.back() = el->sibling;
  if (child)
  {
   size += 3;
   v.push_back(child);   
  } else size += count_length_bytes(el->size) + el->size;
 }
 return size;
}

bool encode_indef_length(void *out, size_t &size, const element *el)
{
 uint8_t *p = static_cast<uint8_t*>(out);
 vector<const element*> v;
 v.push_back(el);
 for (;;)
 {
  el = v.back();
  if (!el)
  {
   v.pop_back();
   if (v.empty()) break;
   if (size < 2) return false;
   p[0] = p[1] = 0;
   p += 2;
   continue;
  }
  size_t tag_bytes = count_tag_bytes(el->tag);
  if (tag_bytes > size) return false;
  size -= tag_bytes;
  uint8_t tag = el->cls << 6;
  if (el->child) tag |= 0x20;
  if (el->tag < 31)
  {
   *p++ = tag | el->tag;
  } else
  {
   *p++ = tag | 0x1F;
   unsigned shift = static_cast<unsigned>((tag_bytes-2)*7);
   while (shift)
   {
    *p++ = (el->tag >> shift) | 0x80;
    shift -= 7;
   }
   *p++ = el->tag & 0x7F;
  }
  v.back() = el->sibling;
  if (!el->child)
  {
   size_t len_bytes = count_length_bytes(el->size);
   if (size < len_bytes) return false;
   size -= len_bytes;
   if (el->size < 128)
   {
    *p++ = static_cast<uint8_t>(el->size);
   } else
   {
    *p++ = static_cast<uint8_t>(--len_bytes | 0x80);
    int shift = static_cast<int>((len_bytes-1)<<3);
    while (shift >= 0)
    {
     *p++ = static_cast<uint8_t>(el->size >> shift);
     shift -= 8;
    }
   }
   if (el->size > size) return false;
   memcpy(p, el->data, el->size);
   p += el->size;
   size -= el->size;
  } else
  {
   if (!size) return false;
   size--;
   *p++ = 0x80;
   v.push_back(el->child);
  }
 } 
 size = p - static_cast<uint8_t*>(out);
 return true;
}

} // namespace asn1
