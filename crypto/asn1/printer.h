#ifndef __asn1_printer_h__
#define __asn1_printer_h__

#include "element.h"
#include <string>

namespace asn1
{

 void print_tree(std::string &out, const element *root, const void *start = nullptr);
 void print_element(std::string &out, const element *el, const void *start = nullptr);

}

#endif // __asn1_printer_h__
