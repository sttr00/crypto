#include "decoder.h"
#include <vector>
#include <cassert>

using std::vector;

namespace asn1
{

struct decoder_stack_item
{
 element *last;
 element *parent;
 const uint8_t *buf; 
 size_t size;
 bool indef;
};

element *decode(const void *data, size_t size, unsigned flags, int *error)
{
 int result = 0;
 vector<decoder_stack_item> v;
 element *root = nullptr;
 decoder_stack_item item = { nullptr, nullptr, static_cast<const uint8_t*>(data), size, false };
 v.push_back(item); 
 while (!v.empty())
 {
  decoder_stack_item &top = v.back();
  size = top.size;
  if (!size)
  {
   if (top.indef)
   {
    result = DECODE_ERROR_NO_DATA;
    break;
   }
   v.pop_back();
   continue;
  }
  const uint8_t *buf = top.buf;
  unsigned byte_tag = *buf++;
  size--;
  if (!byte_tag)
  {
   if (!top.indef || !size || *buf)
   {
    result = DECODE_ERROR_INVALID_TAG;
    break;
   }
   buf++;
   size--;
   assert(v.size() >= 2);
   v.pop_back();
   decoder_stack_item &top = v.back();
   if (top.indef || size)
   {
    top.buf = buf;
    top.size = size;
   } else v.pop_back();
   continue;
  }
  unsigned tag = byte_tag & 31;
  if (tag == 31)
  {
   tag = 0;
   unsigned len_octets = 0;
   for (;;)
   {
    if (!size)
    {
     result = DECODE_ERROR_NO_DATA;
     break;
    }
    if (++len_octets > sizeof(unsigned))
    {
     result = DECODE_ERROR_TOO_MANY_LENGTH_OCTETS;
     break;
    }
    uint8_t val = *buf++;
    tag = tag<<7 | (val & 0x7F);
    size--;
    if (!(val & 0x80)) break;
   }
   if (result) break;
  }
  if (!size)
  {
   result = DECODE_ERROR_NO_DATA;
   break;
  }
  size_t len;
  unsigned byte_len = *buf++;
  size--;
  item.indef = false;
  if (byte_len & 0x80)
  {
   byte_len ^= 0x80;
   if (byte_len)
   {
    if (byte_len > sizeof(size_t))
    {
     result = DECODE_ERROR_TOO_MANY_LENGTH_OCTETS;
     break;
    }
    if (byte_len > size)
    {
     result = DECODE_ERROR_NO_DATA;
     break;
    }
    size -= byte_len;
    len = 0;
    while (byte_len)
    {
     len = len<<8 | *buf++;
     byte_len--;
    }
   } else
   if (flags & DECODE_FLAG_ALLOW_INDEF_LENGTH)
   {
    if (!(byte_tag & 0x20))
    {
     result = DECODE_ERROR_CONSTRUCTED_FORM_EXPECTED;
     break;
    }
    len = 0;
    item.indef = true;
   } else
   {
    result = DECODE_ERROR_INDEFINITE_LENGTH;
    break;
   }
  } else len = byte_len;
  if (len > size)
  {
   result = DECODE_ERROR_NO_DATA;
   break;
  }
  element *el = element::create();
  if (!root) root = el;
  el->tag = tag;
  el->cls = byte_tag>>6;
  if (top.last) top.last->sibling = el;
  if (top.parent)
  {
   top.parent->child = el;
   top.parent = nullptr;
  }
  el->data = buf;
  el->size = len;
  if (byte_tag & 0x20)
  {
   item.last = nullptr;
   item.parent = el;
   item.buf = buf;
   item.size = item.indef? size : len;
   top.last = el;
   top.buf = buf + len;
   top.size = size - len;
   v.push_back(item);
  } else
  {
   top.last = el;
   top.buf = buf + len;
   top.size = size - len;
  }
 }

 if (error) *error = result;
 if (result)
 {
  delete_tree(root);
  return nullptr;
 }
 return root;
}

} // namespace asn1
