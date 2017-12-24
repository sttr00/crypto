#ifndef __file_utils_h__
#define __file_utils_h__

#include <crypto/asn1/element.h>
#include <string>

enum
{
 FORMAT_DEFAULT,
 FORMAT_BIN,
 FORMAT_HEX,
 FORMAT_BASE64
};

struct pkcs8_result
{
 int alg_id;
 asn1::element *params;
 const void *data;
 size_t size;
};

int get_format(const char *fmt);
void *load_file(const char *filename, int &size, bool use_stdin);
void *load_pem_file(const char *filename, int &size, const std::string &type, std::string *found_type = nullptr);
void *load_input_file(const char *filename, int &size, bool use_stdin, int format, std::string *out_type);
bool save_output_file(const char *filename, const void *data, int size, bool use_stdout, int format, const char *pem_type);
bool decode_pkcs8(pkcs8_result &result, const char *filename, const void *data, size_t size, const int *req_alg_id);
std::string print_oid(const uint8_t *data, size_t size);

#endif // __file_utils_h__
