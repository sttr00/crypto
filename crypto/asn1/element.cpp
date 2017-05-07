#include "element.h"
#include <vector>
#include <cassert>

using namespace asn1;
using std::vector;

element::element()
{
 data = nullptr;
 size = 0;
 child = sibling = nullptr;
 tag = 0;
 cls = flags = 0;
}

element::element(const void *data, size_t size)
{
 this->data = static_cast<const uint8_t*>(data);
 this->size = size;
 child = sibling = nullptr;
 tag = 0;
 cls = flags = 0;
}

element::element(unsigned type, const void *data, size_t size)
{
 this->data = static_cast<const uint8_t*>(data);
 this->size = size;
 child = sibling = nullptr;
 tag = type;
 cls = CLASS_UNIVERSAL;
 flags = 0;
}

element *element::create()
{
 element *el = new element;
 el->flags |= FLAG_HEAP_ALLOC;
 return el;
}

element *element::create(const void *data, size_t size)
{
 element *el = new element(data, size);
 el->flags |= FLAG_HEAP_ALLOC;
 return el;
}

element *element::create(unsigned type, const void *data, size_t size)
{
 element *el = new element(type, data, size);
 el->flags |= FLAG_HEAP_ALLOC;
 return el;
}

element::~element()
{
 if (flags & FLAG_OWN_BUFFER) ::operator delete(const_cast<uint8_t*>(data));
}

bool element::get_small_uint(unsigned &val) const
{
 if (cls != CLASS_UNIVERSAL || tag != TYPE_INTEGER || !size) return false;
 size_t max_size = sizeof(unsigned);
 if (!data[0]) max_size++;
 if (size > max_size) return false;
 val = 0;
 for (size_t i = 0; i < size; i++)
  val = val<<8 | data[i];
 return true;
}

bool element::get_small_int(int &val) const
{
 if (cls != CLASS_UNIVERSAL || tag != TYPE_INTEGER || !size) return false;
 size_t max_size = sizeof(int);
 if (!data[0]) max_size++;
 if (size > max_size) return false;
 val = 0;
 for (size_t i = 0; i < size; i++)
  val = val<<8 | data[i];
 if ((data[0] & 0x80) && size < sizeof(int))
  val |= ~0u << (size<<3);
 return true;
}

bool element::is_valid_int() const
{
 if (cls != CLASS_UNIVERSAL || tag != TYPE_INTEGER || !size) return false;
 if (!data[0])
 {
  if (size == 1) return true;
  return (data[1] & 0x80) != 0;
 }
 return true;
}

bool element::is_valid_positive_int() const
{
 if (cls != CLASS_UNIVERSAL || tag != TYPE_INTEGER || !size) return false;
 if (data[0] & 0x80) return false;
 if (!data[0])
 {
  if (size == 1) return false;
  return (data[1] & 0x80) != 0;
 }
 return true;
}

bool element::is_sequence() const
{
 return cls == CLASS_UNIVERSAL && tag == TYPE_SEQUENCE;
}

bool element::is_obj_id() const
{
 return cls == CLASS_UNIVERSAL && tag == TYPE_OID && size;
}

bool element::is_octet_string() const
{
 return cls == CLASS_UNIVERSAL && tag == TYPE_OCTET_STRING;
}

bool element::is_aligned_bit_string() const
{
 return cls == CLASS_UNIVERSAL && tag == TYPE_BIT_STRING && size > 1 && data[0] == 0;
}

void asn1::delete_tree(element *el)
{
 if (!el) return;
 vector<element*> v;
 v.push_back(el);
 while (!v.empty())
 {
  el = v.back();
  element *next = el->child;
  if (next)
  {
   el->child = nullptr;
   v.push_back(next);
   continue;
  }
  next = el->sibling;
  if (next)
  {
   if (el->flags & element::FLAG_HEAP_ALLOC) delete el;
   v.back() = next;
   continue;
  }
  if (el->flags & element::FLAG_HEAP_ALLOC) delete el;
  v.pop_back();
 }
}

static inline element *clone(const element *el)
{
 element *result = element::create(el->data, el->size);
 result->tag = el->tag;
 result->cls = el->cls;
 return result;
}

element *element::clone_tree() const
{
 struct clone_stack_item
 {
  const element *src;
  element *dest;
 } item;
 vector<clone_stack_item> v;
 item.src = this;
 element *result = item.dest = clone(this);
 v.push_back(item);
 while (!v.empty())
 {
  clone_stack_item &top = v.back();
  if (!top.src)
  {
   v.pop_back();
   continue;
  }
  const element *child = top.src->child;
  const element *sibling = top.src->sibling;
  if (child)
  {
   item.src = child;
   top.dest->child = item.dest = clone(child);
   if (sibling)
   {
    element *next = clone(sibling);
    top.dest->sibling = next;
    top.dest = next;
   }
   top.src = sibling;
   v.push_back(item);
   continue;
  }
  if (sibling)
  {
   element *next = clone(sibling);
   top.dest->sibling = next;
   top.dest = next;
   top.src = sibling;
  } else v.pop_back();
 }
 return result;
}

bool element::remove_child(element *old_child)
{
 if (child == old_child)
 {
  assert(child);
  child = child->sibling;
  old_child->sibling = nullptr;
  return true;
 }
 element *prev = child;
 element *next = prev->sibling;
 while (next)
 {
  if (next == old_child)
  {
   prev->sibling = next->sibling;
   old_child->sibling = nullptr;
   return true;
  }
  prev = next;
  next = next->sibling;
 } 
 return false;
}

bool element::replace_child(element *old_child, element *new_child)
{
 if (child == old_child)
 {
  assert(old_child);
  new_child->sibling = old_child->sibling;
  child = new_child;
  old_child->sibling = nullptr;
  return true;
 }
 element *prev = child;
 element *next = prev->sibling;
 while (next)
 {
  if (next == old_child)
  {
   prev->sibling = new_child;
   new_child->sibling = next->sibling;
   old_child->sibling = nullptr;  
   return true;
  }
  prev = next;
  next = next->sibling;
 } 
 return false;
}
