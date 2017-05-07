#ifndef __oid_storage_h__
#define __oid_storage_h__

#include <string>
#include <list>
#include <map>
#include <vector>

struct oid_component
{
 unsigned number;
 std::string id;
};

typedef std::list<oid_component> oid_info;

struct oid_info_ex
{
 std::string name;
 oid_info oid;
 unsigned flags;
 unsigned order;
 
 static const unsigned FLAG_NO_EXPORT = 1; 
};

typedef std::map<std::string, oid_info_ex> named_oid_map;

void get_sorted_oids(std::vector<oid_info_ex> &out, const named_oid_map &in);

#endif // __oid_storage_h__
