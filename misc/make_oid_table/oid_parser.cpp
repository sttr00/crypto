#include "oid_parser.h"
#include "asn1_lexer.h"
#include "asn1_keywords.h"
#include <iostream>
#include <cassert>

using std::string;
using namespace asn1_tokens;

static inline bool is_whitespace(char c)
{
 return (c>=0x9 && c<=0xD) || c==' ';
}

static string get_comment_contents(const string &str)
{
 if (str.length() < 2) return string();
 string::size_type start_pos = 2, end_pos = str.length();
 if (str.length() >= 4 &&
     ((str[end_pos-1] == '-' && str[end_pos-2] == '-') ||
      (str[end_pos-1] == '/' && str[end_pos-2] == '*'))) end_pos -= 2;
 while (start_pos < end_pos && is_whitespace(str[end_pos-1])) end_pos--;
 while (start_pos < end_pos && is_whitespace(str[start_pos])) start_pos++;
 assert(start_pos <= end_pos);
 return str.substr(start_pos, end_pos-start_pos);
}

bool oid_parser::start(const token_list &tl)
{
 int type = get_prev_token(tl, 0, &name);
 if (type != TOKEN_IDENTIFIER) return false;
 string data;
 type = get_prev_token(tl, 1, &data);
 if (type == TOKEN_COMMENT || type == TOKEN_MULTILINE_COMMENT)
 {
  data = get_comment_contents(data);
  if (data == "no-export") flags |= oid_info_ex::FLAG_NO_EXPORT;
 }
 state = STATE_STARTED;
 return true;
}

static bool parse_integer(unsigned &result, const string &str)
{
 result = 0;
 for (string::size_type i = 0; i < str.length(); i++)
  if (str[i] >= '0' && str[i] <= '9')
   result = result*10 + str[i]-'0';
  else
   return false;
 return !str.empty();
}

bool oid_parser::process_token(int token_type, const string &token)
{
 if (token_type == TOKEN_COMMENT || token_type == TOKEN_MULTILINE_COMMENT) return true;
 if (state == STATE_STARTED)
 {
  if (!(token_type == TOKEN_PUNCT && token == "{")) return false;
  state = STATE_COMPONENT;
  return true;
 }
 if (state == STATE_COMPONENT)
 {
  if (token_type == TOKEN_IDENTIFIER)
  {
   if (oid.empty())
   {
    named_oid_map::const_iterator it = storage.find(token);
    if (it != storage.end())
    {
     const oid_info &root = it->second.oid;
     oid.insert(oid.end(), root.begin(), root.end());
     return true; // state unchanged
    }
   }
   oid_component comp; 
   comp.id = token;
   oid.push_back(comp);
   state = STATE_PAREN_OPEN;
   return true;
  }
  if (token_type == TOKEN_INTEGER)
  {
   oid_component comp;
   if (!parse_integer(comp.number, token)) return false;
   oid.push_back(comp);
   state = STATE_COMPONENT;
   return true;
  }
  if (token_type == TOKEN_PUNCT && token == "}")
  {
   state = STATE_FINISHED;
   assert(!name.empty());
   oid_info_ex result;
   std::swap(result.oid, oid);
   result.name = name;
   result.flags = flags;
   result.order = order++;
   std::pair<named_oid_map::iterator, bool> p = storage.insert(named_oid_map::value_type(name, result));
   if (p.second)
    last_elem = p.first;
   else
    std::cerr << "Warning: Duplicate OID name " << name << '\n';
   return true;
  }
  return false;
 }
 if (state == STATE_PAREN_OPEN)
 {
  if (!(token_type == TOKEN_PUNCT && token == "(")) return false;
  state = STATE_NUMBER_PAREN;
  return true;
 }
 if (state == STATE_PAREN_CLOSED)
 {
  if (!(token_type == TOKEN_PUNCT && token == ")")) return false;
  state = STATE_COMPONENT;
  return true;
 }
 if (state == STATE_NUMBER_PAREN)
 {
  assert(!oid.empty());
  if (!parse_integer(oid.back().number, token)) return false;
  state = STATE_PAREN_CLOSED;
  return true;
 }
 return false;
}

oid_parser::oid_parser(named_oid_map &storage): storage(storage)
{
 state = STATE_IDLE;
 flags = 0;
 last_elem = storage.end();
 order = 0;
}

void oid_parser::clear()
{
 oid.clear();
 name.clear();
 state = STATE_IDLE;
 flags = 0;
}
