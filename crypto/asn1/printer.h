#ifndef __asn1_printer_h__
#define __asn1_printer_h__

#include "element.h"
#include <string>

namespace asn1
{

 void print_tree(std::string &out, const element *root);
 void print_element(std::string &out, const element *el);

}

#endif // __asn1_printer_h__
