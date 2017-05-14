#include "file_utils.h"
#include <crypto/oid_search.h>
#include <crypto/asn1/decoder.h>
#include <crypto/utils/pem_file.h>
#include <platform/file.h>
#include <utils/base64.h>
#include <string.h>

int get_format(const char *fmt)
{
 static const char *formats[] = { "bin", "hex", "base64" };
 for (unsigned i = 0; i < sizeof(formats)/sizeof(formats[0]); i++)
  if (!strcmp(fmt, formats[i])) return FORMAT_BIN + i;
 return -1;
}

static const char *get_stdin_file_name()
{
#ifdef _WIN32
 return "CON:";
#else
 return "/dev/stdin";
#endif
}

static const char *get_stdout_file_name()
{
#ifdef _WIN32
 return "CON:";
#else
 return "/dev/stdout";
#endif
}

void *load_file(const char *filename, int &size, bool use_stdin)
{
 if (use_stdin) filename = get_stdin_file_name();
 platform::file_t f = platform::open_file(filename);
 if (f == platform::INVALID_FILE)
 {
  fprintf(stderr, "%s: Can't open file\n", filename);
  return nullptr;
 }
 if (use_stdin)
 {
  size = 32768;
 } else
 {
  uint64_t size64 = platform::get_file_size(f);
  if (size64 == (uint64_t) -1)
  {
   fprintf(stderr, "%s: Can't get file size\n", filename);
   return nullptr;
  }
  size = (int) size64;
 }
 void *buf = operator new(size);
 int out_size = 0;
 while (out_size < size)
 {
  int rd_size = platform::read_file(f, static_cast<uint8_t*>(buf) + out_size, size - out_size);
  if (use_stdin && !rd_size) break;
  if (rd_size <= 0)
  {
   fprintf(stderr, "%s: Read error\n", filename);
   operator delete(buf);
   platform::close_file(f);
   return nullptr;
  }
  out_size += rd_size;
 }
 platform::close_file(f);
 size = out_size;
 return buf;
}

void *load_pem_file(const char *filename, int &size, const std::string &type, std::string *found_type)
{
 void *out = nullptr;
 int out_size = 0;
 int pem_size;
 void *pem_data = load_file(filename, pem_size, false);
 if (pem_data)
 {
  int error;
  std::string tmp;
  if (!found_type) found_type = &tmp;
  size_t pos = 0, bin_size;
  if (!pem_file::decode(pem_data, pem_size, out, bin_size, type.empty()? nullptr : &type, found_type, &pos, &error))
  {
   if (error == pem_file::DECODE_ERROR_WRONG_TYPE)
    fprintf(stderr, "%s: Expected PEM file of type '%s', but found '%s'\n",
            filename, type.c_str(), found_type->c_str());
   else
    fprintf(stderr, "%s: PEM decoding error %d\n", filename, error);
  } else out_size = bin_size;
  operator delete(pem_data);
 }
 size = out_size;
 return out;
}


static inline int get_hex_digit(char c)
{
 if (c>='0' && c<='9') return c-'0';
 if (c>='A' && c<='F') return c-'A'+10;
 if (c>='a' && c<='f') return c-'a'+10;
 return -1;
}

static size_t parse_hex(uint8_t *out, size_t buf_size, const char *in, size_t in_size)
{
 size_t ptr = 0;
 unsigned byte = 0;
 int shift = 4;
 for (size_t i = 0; i < in_size; i++)
 {
  int digit = get_hex_digit(in[i]);
  if (digit < 0)
  {
   if (shift) continue;
   if ((in[i]=='x' || in[i]=='X') && !byte)
   {
    shift = 4;
    continue;
   }
   return 0;
  }
  byte |= digit << shift;
  shift -= 4;
  if (shift < 0)
  {
   if (ptr == buf_size) break;
   out[ptr++] = static_cast<uint8_t>(byte);
   byte = 0;
   shift = 4;
  }
 }
 if (!shift) return 0;
 return ptr;
}

void *load_input_file(const char *filename, int &size, bool use_stdin, int format, std::string *out_type)
{
 void *data = load_file(filename, size, use_stdin);
 if (!data || format == FORMAT_BIN) return data;
 if (format == FORMAT_BASE64)
 {
  int error;
  size_t pos = 0, bin_size;
  void *bin_data;
  if (!pem_file::decode(data, size, bin_data, bin_size, nullptr, out_type, &pos, &error))
  {
   if (use_stdin) filename = get_stdin_file_name();
   fprintf(stderr, "%s: PEM decoding error %d\n", filename, error);
   operator delete(data);
   data = nullptr;
   size = 0;
  } else
  {
   operator delete(data);
   data = bin_data;
   size = bin_size;
  }
 } else
 {
  size_t bin_size = size >> 1;
  uint8_t *bin_data = static_cast<uint8_t*>(operator new(bin_size));
  bin_size = parse_hex(bin_data, bin_size, static_cast<const char*>(data), size);
  operator delete(data);
  if (!bin_size)
  {
   fprintf(stderr, "%s: Error decoding hex data\n", filename);
   operator delete(bin_data);
   data = nullptr;
   size = 0;
  } else
  {
   operator delete(data);
   data = bin_data;
   size = bin_size;  
  }
 }
 return data;
}

bool save_output_file(const char *filename, const void *data, int size, bool use_stdout, int format, const char *pem_type)
{
 if (use_stdout)
 {
  fflush(stdout);
  filename = get_stdout_file_name();
 }
 platform::file_t f = platform::create_file(filename);
 if (!f)
 {
  fprintf(stderr, "%s: Can't create file\n", filename);
  return false;
 }
 if (format == FORMAT_BASE64)
 {
  static const int pem_line_size = 64;
  static const int bin_line_size = 3*(pem_line_size/4);
  std::string str("-----BEGIN ");
  str += pem_type;
  str += "-----\n";
  platform::write_file(f, str.c_str(), str.length());
  char *pem_out = static_cast<char*>(alloca(pem_line_size + 1));
  while (size)
  {
   int line_size = bin_line_size;
   if (size < line_size) line_size = size;
   size_t out_size = pem_line_size;
   base64::encode(pem_out, out_size, data, line_size, 0);
   pem_out[out_size] = '\n';
   platform::write_file(f, pem_out, out_size + 1);
   data = static_cast<const uint8_t*>(data) + line_size;
   size -= line_size;
  }
  str = "-----END ";
  str += pem_type;
  str += "-----\n";
  platform::write_file(f, str.c_str(), str.length());
 } else
 if (format == FORMAT_HEX)
 {
  static const char hex_char[] = "0123456789ABCDEF";
  char hex_line[16*3 + 1];
  int hex_ptr = 0;
  int bin_ptr = 0;
  const uint8_t *p = static_cast<const uint8_t*>(data);
  for (int i=0; i<size; i++)
  {
   if (hex_ptr) hex_line[hex_ptr++] = ' ';
   hex_line[hex_ptr++] = hex_char[p[i] >> 4];
   hex_line[hex_ptr++] = hex_char[p[i] & 0xF];
   if (++bin_ptr == 16)
   {
    hex_line[hex_ptr++] = '\n';
    platform::write_file(f, hex_line, hex_ptr);
    bin_ptr = hex_ptr = 0;
   }
  }
  if (hex_ptr)
  {
   hex_line[hex_ptr++] = '\n';
   platform::write_file(f, hex_line, hex_ptr);
  }
 } else
 {
  platform::write_file(f, data, size);
 }
 platform::close_file(f);
 return true;
}

static std::string print_oid(const uint8_t *data, size_t size)
{
 std::string s;
 if (!size || (data[size-1] & 0x80)) return s;
 char tmp[256];
 unsigned value = 0;
 bool first = true;
 for (size_t i = 0; i < size; i++)
 {
  value = value << 7 | (data[i] & 0x7F);
  if (!(data[i] & 0x80))
  {
   if (first)
   {
    unsigned root;
    if (value >= 80) { root = 2; value -= 80; } else
    if (value >= 40) { root = 1; value -= 40; } else root = 0;
    int len = sprintf(tmp, "%u.%u", root, value);
    s.append(tmp, len);
    first = false;
   } else
   {
    int len = sprintf(tmp, ".%u", value);
    s.append(tmp, len);
   }
   value = 0;
  }
 }
 return s;
}

const void *decode_pkcs8(const char *filename, const void *data, size_t size, int req_alg_id, size_t &out_size)
{
 asn1::element *root = asn1::decode(data, size, 0, nullptr);
 if (!root)
 {
  fprintf(stderr, "%s: Can't decode PKCS#8 structure\n", filename);
  return nullptr;
 }
 const void *result = nullptr;
 out_size = 0;
 if (root->is_sequence())
 {
  const asn1::element *el = root->child;
  unsigned version;
  if (el && el->get_small_uint(version) && version == 0)
  {
   el = el->sibling;
   if (el && el->is_sequence())
   {
    const asn1::element *alg_id = el->child;
    if (alg_id && alg_id->is_obj_id())
    {
     int id = oid::find(alg_id->data, alg_id->size);
     if (id == req_alg_id)
     {
      el = el->sibling;
      if (el && el->is_octet_string())
      {
       result = el->data;
       out_size = el->size;
      }
     } else fprintf(stderr, "%s: Algorithm %s not supported\n", filename, print_oid(alg_id->data, alg_id->size).c_str());
    }
   }
  }
 }
 asn1::delete_tree(root);
 return result;
}
