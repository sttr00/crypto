#include "element.h"
#include <vector>

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
