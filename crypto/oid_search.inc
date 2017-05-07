#include <stdint.h>

int oid::find(const void *data, size_t size)
{
 const oid_search_node *current = &n0;
 for (size_t i = 0; i < size; i++)
 {
  unsigned val = (static_cast<const uint8_t*>(data))[i];
  const oid_search_node *next = nullptr;
  for (int j = 0; j < current->count; j++)
  {
   if (val == current->links[j].byte)
   {
    next = current->links[j].next;
    break;
   }
   if (val < current->links[j].byte) break;
  }
  if (!next) return 0;
  current = next;
 }
 return current->id;
}
