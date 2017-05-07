#include "oid_storage.h"
#include <algorithm>

struct sort_func
{
 bool operator()(const oid_info_ex &l, const oid_info_ex &r) const
 {
  return l.order < r.order;
 }
};

void get_sorted_oids(std::vector<oid_info_ex> &out, const named_oid_map &in)
{
 out.clear();
 out.reserve(in.size());
 for (named_oid_map::const_iterator it = in.begin(); it != in.end(); it++)
  if (!(it->second.flags & oid_info_ex::FLAG_NO_EXPORT))
   out.push_back(it->second);
 std::sort(out.begin(), out.end(), sort_func());
}
