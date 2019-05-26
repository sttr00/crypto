#include "scanner.h"
#include "printer.h"
#include "oid_parser.h"
#include <iostream>

int main(int argc, char *argv[])
{
 static const char *file_const = "oid_const.h";
 static const char *file_const_text = "oid_const_text.inc";
 static const char *file_def = "oid_def.cpp";
 static const char *file_search = "oid_search.cpp";
 
 if (argc < 2)
 {
  std::cout << "Usage: " << argv[0] << " <input_files>\n";
  return 1;
 }

 named_oid_map result;
 oid_parser parser(result);
 for (int i=1; i<argc; i++)
 {
  if (!scan_file(parser, argv[i])) return 2;
  parser.clear();
 }
 std::vector<oid_info_ex> v;
 get_sorted_oids(v, result);
 print_constants(file_const, file_const_text, v);
 print_definitions(file_def, file_const, v);
 print_search_tree(file_search, file_const, v);
 return 0;
}
