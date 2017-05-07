#include <crypto/asn1/decoder.h>
#include <crypto/asn1/encoder.h>
#include <crypto/asn1/printer.h>
#include <crypto/utils/pem_file.h>
#include <platform/file.h>
#include <string>
#include <iostream>
#include <cstring>
#include <cassert>

#ifdef ENCODE
static void encode_file(const char *filename, asn1::element *el, bool indef_length)
{
 size_t out_size = indef_length? asn1::get_indef_length_encoded_size(el) : asn1::calc_encoded_size(el);
 void *buf = operator new(out_size);
 size_t size = out_size;
 bool result = indef_length? asn1::encode_indef_length(buf, size, el) : asn1::encode_def_length(buf, size, el);
 if (!result)
 {
  std::cerr << "encoding failed\n";
  operator delete(buf);
  return;
 }
 assert(out_size == size);
 platform::file_t f = platform::create_file(filename);
 if (f != platform::INVALID_FILE)
 {
  platform::write_file(f, buf,size);
  platform::close_file(f);
 } else std::cerr << filename << ": can't create file\n";
 operator delete(buf);
}
#endif

static void *load_file(const char *filename, int &size)
{
 platform::file_t f = platform::open_file(filename);
 if (f == platform::INVALID_FILE)
 {
  std::cerr << filename << ": can't open file\n";
  return nullptr;
 }
 uint64_t size64 = platform::get_file_size(f);
 if (size64 == (uint64_t) -1)
 {
  std::cerr << filename << ": can't get file size\n";
  return nullptr;
 }
 size = (int) size64;
 void *buf = operator new(size);
 if (platform::read_file(f, buf, size) != size)
 {
  std::cerr << filename << ": read error\n";
  operator delete(buf);
  platform::close_file(f);
  return nullptr;
 }
 platform::close_file(f);
 return buf;
}

static void decode_data(const void *buf, size_t size, unsigned decode_flags, const char *filename)
{
 int error;
 asn1::element *elem = asn1::decode(buf, size, decode_flags, &error);
 if (elem)
 {
  std::string str;
  asn1::print_tree(str, elem, buf);
  #ifdef ENCODE
  std::string out_file = filename;
  size_t len = out_file.length();
  out_file += ".def";
  encode_file(out_file.c_str(), elem, false);
  out_file.erase(len);
  out_file += ".indef";
  encode_file(out_file.c_str(), elem, true);
  #endif
  asn1::delete_tree(elem);
  std::cout << str;
 } else std::cerr << filename << ": decoding error " << error << '\n';
}

static void process_file(const char *filename, unsigned decode_flags, bool pem)
{
 int size;
 void *buf = load_file(filename, size);
 if (!buf) return;
 if (pem)
 {
  bool pem_found = false;
  size_t pos = 0;
  while (pos < (size_t) size)
  {
   int error;
   std::string type;
   void *bin_data;
   size_t bin_size;
   if (pem_file::decode(buf, size, bin_data, bin_size, nullptr, &type, &pos, &error))
   {
    pem_found = true;
    std::cout << "* Decoding PEM data of type " << type << '\n';
    decode_data(bin_data, bin_size, decode_flags, filename);
    operator delete(bin_data);
   } else
   if (!(type.empty() && pem_found))
    std::cerr << filename << ": PEM error " << error << '\n';
  }
 } else decode_data(buf, size, decode_flags, filename);
 operator delete(buf);
}


int main(int argc, char *argv[])
{
 if (argc < 2)
 {
  std::cerr << "Usage: " << argv[0] << " [options...] files...\n\n";
  return 1;
 }
 bool pem_mode = false;
 unsigned decode_flags = asn1::DECODE_FLAG_ALLOW_INDEF_LENGTH;
 for (int i=1; i<argc; i++)
 {
  const char *opt = argv[i];
  if (opt[0] == '-')
  {
   if (!strcmp(opt, "-pem"))
    pem_mode = true; else
   if (!strcmp(opt, "-der"))
    pem_mode = false; else
   if (!strcmp(opt, "-allow-indef"))
    decode_flags = asn1::DECODE_FLAG_ALLOW_INDEF_LENGTH; else
   if (!strcmp(opt, "-no-indef"))   
    decode_flags = 0; else
   if (!strcmp(opt, "-file"))
   {
    if (i == argc-1)
    {
     std::cerr << opt << ": argument required\n";
     return 2;
    }
    process_file(argv[++i], decode_flags, pem_mode);
   } else
   {
    std::cerr << opt << ": unknown option\n";
    return 2;
   }
  } else process_file(opt, decode_flags, pem_mode);
 }
 return 0;
}
