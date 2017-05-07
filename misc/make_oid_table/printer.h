#ifndef __printer_h__
#define __printer_h__

#include "oid_storage.h"
#include <vector>

bool print_constants(const char *filename, const char *text_filename, const std::vector<oid_info_ex> &v);
bool print_definitions(const char *filename, const char *const_filename, const std::vector<oid_info_ex> &v);
bool print_search_tree(const char *filename, const char *const_filename, const std::vector<oid_info_ex> &v);

#endif // __printer_h__
