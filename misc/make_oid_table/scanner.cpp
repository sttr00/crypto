#include "scanner.h"
#include "oid_parser.h"
#include "asn1_lexer.h"
#include "asn1_keywords.h"
#include <platform/file.h>
#include <iostream>
#include <string.h>
#include <stdio.h>

using std::string;
using namespace asn1_tokens;

static void count_lines(int &line_number, const char *data, size_t &pos)
{
 for (;;)
 {
  if (!pos) break;
  const char *next = static_cast<const char*>(memchr(data, '\n', pos)); 
  if (!next)
  {
   pos++; // position starts from 1
   return;
  }
  next++;
  size_t size = next - data;
  pos -= size;
  data += size;
  line_number++;
 }
}

static string print_oid(const oid_info &oid)
{
 string result = "{";
 for (oid_info::const_iterator it = oid.begin(); it != oid.end(); it++)
 {
  result += ' ';
  if (!it->id.empty())
  {
   result += it->id;
   result += '(';
  }
  char tmp[64];
  int len = sprintf(tmp, "%u", it->number);
  result.append(tmp, len);
  if (!it->id.empty()) result += ')';
 }
 result += " }";
 return result;
}

static string print_oid(named_oid_map::iterator it)
{
 string result;
 if (it->second.flags & oid_info_ex::FLAG_NO_EXPORT)
  result += "-- no-export\n";
 result += it->first;
 result += " OBJECT IDENTIFIER ::= ";
 result += print_oid(it->second.oid);
 result += '\n';
 return result;
}

bool scan_file(named_oid_map &out, const char *filename)
{
 platform::file_t f = platform::open_file(filename);
 if (f == platform::INVALID_FILE)
 {
  std::cerr << "Can't open input file '" << filename << "'\n";
  return false;
 }
 char buf[4096];
 asn1_lexer lexer;
 token_list tl;
 oid_parser parser(out);
 int line_number = 1;
 for (;;)
 {
  int rd_size = platform::read_file(f, buf, sizeof(buf));
  if (rd_size < 0)
  {
   std::cerr << "Error reading input file\n";
   platform::close_file(f);
   return false;
  }
  if (!rd_size)
  {
   platform::close_file(f);
   break;
  }
  bool process_definition = false;
  size_t size = rd_size;
  size_t pos = 0;
  while (pos < size)
  {
   size_t prev_pos = pos;
   int result = lexer.process_buffer(buf, size, pos);
   if (result == asn1_lexer::RESULT_ERROR)
   {
    count_lines(line_number, buf, pos);
    std::cerr << "Error #" << lexer.get_error() << " at line " << line_number << " pos " << pos;
    platform::close_file(f);
    return false;
   }
   if (result == asn1_lexer::RESULT_TOKEN)
   {
    const string &token = lexer.get_token();
    if (process_definition)
    {
     if (!parser.process_token(lexer.get_token_type(), token))
     {
      count_lines(line_number, buf, prev_pos);
      std::cerr << "Invalid OID definition at line " << line_number << " pos " << prev_pos;
      platform::close_file(f);
      return false;
     }
     if (parser.is_finished())
     {
      parser.clear();
      std::cout << print_oid(parser.get_inserted_element());
      process_definition = false;
     }
    } else
    if (token == "::=" &&
        get_prev_token(tl, 0, NULL) == TOKEN_KW_IDENTIFIER &&
        get_prev_token(tl, 1, NULL) == TOKEN_KW_OBJECT &&
        get_prev_token(tl, 2, NULL) == TOKEN_IDENTIFIER)
    {
     remove_tokens(tl, 2);
     if (!parser.start(tl))
     {
      std::cerr << "Internal error\n";
      platform::close_file(f);
      return false;
     }
     process_definition = true;     
    } else add_token(tl, lexer.get_token_type(), token);
    lexer.clear_token();
   }
  }
  count_lines(line_number, buf, size);
 }
 return true;
}
