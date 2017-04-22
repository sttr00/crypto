#include "pem_file.h"
#include <utils/base64.h>
#include <cstring>

using std::string;

static const size_t max_line_size = 96;

enum
{
 LINE_NONE,
 LINE_BEGIN,
 LINE_END
};

static int check_line(const char *start, size_t size, string &type)
{
 if (size < 10 || size > max_line_size) return LINE_NONE;
 for (size_t i = 0; i < 5; i++)
  if (start[i] != '-' || start[size-1-i] != '-') return LINE_NONE;
 if (size > 10 + 6 && !memcmp(start + 5, "BEGIN ", 6))
 {
  type.assign(start + 5 + 6, size - (10 + 6));
  return LINE_BEGIN;
 }
 if (size > 10 + 4 && !memcmp(start + 5, "END ", 4))
 {
  type.assign(start + 5 + 4, size - (10 + 4));
  return LINE_END;
 }
 return LINE_NONE;
}

static inline bool is_whitespace(char c)
{
 return (c>=0x9 && c<=0xD) || c==' ';
}

bool pem_file::decode(const void *text_data, size_t text_size, void* &bin_data, size_t &bin_size,
                      const string *required_type, string *found_type, size_t *ppos, int *error)
{
 const char *str = static_cast<const char*>(text_data);
 string type, start_type;
 int expect_what = LINE_BEGIN;
 size_t line_size, next_pos;
 size_t data_start, data_end = 0;
 size_t pos = ppos? *ppos : 0;
 while (pos < text_size)
 {
  const char *start = str + pos;
  const char *sep = static_cast<const char*>(memchr(start, '\n', text_size - pos));
  if (sep)
  {
   line_size = sep - start;
   next_pos = sep - str + 1;
  } else
  {
   line_size = text_size - pos;
   next_pos = text_size;
  }
  while (line_size && is_whitespace(start[line_size-1])) line_size--;
  if (!line_size)
  {
   pos = next_pos;
   continue;
  }
  int what = check_line(start, line_size, type);
  if (what == expect_what)
  {
   if (expect_what == LINE_BEGIN)
   {
    if (required_type && *required_type != type)
    {
     pos = next_pos;
     continue;
    }
    expect_what = LINE_END;
    data_start = next_pos;
    start_type = type;
    pos = next_pos;
   } else
   {
    if (type != start_type)
    {
     if (error) *error = DECODE_ERROR_BAD_PEM_FILE;
     return false;
    }
    data_end = pos;
    if (found_type) *found_type = type;
    break;
   }
  }
  pos = next_pos;
 }
 if (ppos) *ppos = next_pos;
 if (!data_end)
 {
  if (error)
   *error = (!start_type.empty() && required_type)? DECODE_ERROR_WRONG_TYPE : DECODE_ERROR_BAD_PEM_FILE;
  return false;
 }
 size_t out_size = base64::get_decoded_size(str + data_start, data_end - data_start);
 size_t out_ptr = 0;
 char *buf = static_cast<char*>(operator new(out_size));
 while (data_start < data_end)
 {
  const char *start = str + data_start;
  const char *sep = static_cast<const char*>(memchr(start, '\n', data_end - data_start));
  if (sep)
  {
   line_size = sep - start;
   next_pos = sep - str + 1;
  } else
  {
   line_size = data_end - data_start;
   next_pos = data_end;
  }
  while (line_size && is_whitespace(start[line_size-1])) line_size--;
  if (!line_size)
  {
   data_start = next_pos;
   continue;
  }
  size_t size = out_size - out_ptr;
  if (!base64::decode(buf + out_ptr, size, start, line_size, 0))
  {
   operator delete(buf);
   if (error) *error = DECODE_ERROR_BASE64_ERROR;
   return false;
  }
  out_ptr += size;
  data_start = next_pos;
 }
 bin_data = buf;
 bin_size = out_ptr;
 return true;
}
