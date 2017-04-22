#include "printer.h"
#include <vector>

using namespace asn1;
using std::string;
using std::vector;

#define countof(a) (sizeof(a)/sizeof(a[0]))

static const char *str_types[] =
{
 "Boolean",
 "Integer",
 "BitString",
 "OctetString",
 "Null",
 "ObjectIdentifier",
 "ObjectDescriptor",
 "External",
 "Real",
 "Enumerated",
 "EmbeddedPDV",
 "UTF8String",
 "RelativeOID",
 nullptr,
 nullptr,
 "Sequence",
 "Set",
 "NumericString",
 "PrintableString",
 "TeletexString",
 "VideotexString",
 "IA5String",
 "UniversalTime",
 "GeneralizedTime",
 "GraphicString",
 "VisibleString",
 "GeneralString",
 "UniversalString",
 "CharacterString",
 "BMPString"
};

static const char hex[] = { '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' };

static void print_hex(string &out, const element *el, size_t offset = 0)
{
 out.reserve(out.length() + ((el->size-offset)<<1));
 for (size_t i = offset; i < el->size; i++)
 {
  out += hex[el->data[i]>>4];
  out += hex[el->data[i] & 0xF];
 }
}

static void print_string(string &out, const element *el)
{
 for (size_t i = 0; i < el->size; i++)
  if (el->data[i] >= 0x20 && el->data[i] < 0x80)
  {
   if (el->data[i] == '\\') out += '\\';
   out += (char) el->data[i]; 
  } else
  {
   out.append("\\x", 2);
   out += hex[el->data[i]>>4];
   out += hex[el->data[i] & 0xF];
  }
}

static void print_utf8_string(string &out, const element *el)
{
 for (size_t i = 0; i < el->size; i++)
  if (el->data[i] >= 0x20)
  {
   if (el->data[i] == '\\') out += '\\';
   out += (char) el->data[i]; 
  } else
  {
   out.append("\\x", 2);
   out += hex[el->data[i]>>4];
   out += hex[el->data[i] & 0xF];
  }
}

static void print_oid(string &out, const element *el, bool absolute)
{
 size_t size = el->size;
 if (!size || (el->data[size-1] & 0x80))
 {
  out += "INVALID";
  return;
 }
 char tmp[256];
 unsigned value = 0;
 bool first = true;
 for (size_t i = 0; i < size; i++)
 {
  value = value << 7 | (el->data[i] & 0x7F);
  if (!(el->data[i] & 0x80))
  {
   if (absolute)
   {
    unsigned root;
    if (value >= 80) { root = 2; value -= 80; } else
    if (value >= 40) { root = 1; value -= 40; } else root = 0;
    int len = sprintf(tmp, "%u.%u", root, value);
    out.append(tmp, len);
    absolute = first = false;
   } else
   {
    if (!first) out += '.';
    int len = sprintf(tmp, "%u", value);
    out.append(tmp, len);
    first = false;
   }
   value = 0;
  }
 }
}

static const char *str_classes[] =
{
 "UNIVERSAL", "APPLICATION", "CONTEXT SPECIFIC", "PRIVATE"
};

void asn1::print_element(string &out, const element *el)
{
 char tmp[256];
 const char *type = nullptr;
 if (el->cls == CLASS_UNIVERSAL && el->tag && el->tag <= countof(str_types))
  type = str_types[el->tag-1];
 if (type)
 {
  out.append(type);
 } else
 {
  out += '[';
  out += str_classes[el->cls & 3];
  int len = sprintf(tmp, " %u]", el->tag);
  out.append(tmp, len);
 }
 out += el->child? " C" : " P";
 if (el->size)
 {
  int len = sprintf(tmp, " %u", (unsigned) el->size);
  out.append(tmp, len);
 }
 if (!el->child)
 {
  if (el->cls == CLASS_UNIVERSAL)
  {
   if (el->tag == TYPE_BOOLEAN)
   {
    out += " \"";
    if (el->size == 1 && (el->data[0] == 0 || el->data[0] == 0xFF))
     out.append(el->data[0]? "TRUE" : "FALSE"); else print_hex(out, el);
    out += '"';
   } else
   if (el->tag == TYPE_INTEGER || el->tag == TYPE_ENUMERATED)
   {
    out += " \"";
    int val;
    if (el->get_small_int(val))
    {
     int len = sprintf(tmp, "%d (0x%X)", val, val);
     out.append(tmp, len);
    } else print_hex(out, el);
    out += '"';
   } else
   if (el->tag == TYPE_OID)
   {
    out += " \"";
    print_oid(out, el, true);
    out += '"';
   } else
   if (el->tag == TYPE_RELATIVE_OID)
   {
    out += " \"";
    print_oid(out, el, false);
    out += '"';
   } else
   if (el->tag == TYPE_OCTET_STRING || el->tag == TYPE_UNIVERSAL_STRING || el->tag == TYPE_BMP_STRING)
   {
    out += " \"";
    print_hex(out, el);
    out += '"';
   } else
   if (el->tag == TYPE_BIT_STRING)
   {
    out += " \"";
    if (el->size)
    {
     int len = sprintf(tmp, "%u:", el->data[0]);
     out.append(tmp, len);
     print_hex(out, el, 1);
    } else out += "INVALID";
    out += '"';
   } else
   if (el->tag >= TYPE_NUMERIC_STRING && el->tag <= TYPE_CHARACTER_STRING)
   {
    out += " \"";
    print_string(out, el);
    out += '"';
   } else
   if (el->tag == TYPE_UTF8_STRING)
   {
    out += " \"";
    print_utf8_string(out, el);
    out += '"';
   }
  } else
  {
   out += " \"";
   print_hex(out, el);
   out += '"';
  }
 }
 out += '\n';
}

void asn1::print_tree(string &out, const element *root)
{
 vector<const element*> v;
 v.push_back(root);
 while (!v.empty())
 {
  const element *el = v.back();
  if (!el)
  {
   v.pop_back();
   continue;
  }
  out.append(v.size()-1, ' ');
  print_element(out, el);
  v.back() = el->sibling;
  if (el->child) v.push_back(el->child);
 }
}
