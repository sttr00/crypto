#include "make_constant.h"
#include <list>

using std::string;

enum
{
 LOWER = 1,
 UPPER = 2
};

static inline int get_letter_class(char c)
{
 if (c >= 'a' && c <= 'z') return LOWER;
 if (c >= 'A' && c <= 'Z') return UPPER;
 return 0;
}

static inline bool is_digit(char c)
{
 return c >= '0' && c <= '9';
}

static inline void convert_word(string &s)
{
 for (string::size_type i = 0; i < s.length(); i++)
  if (s[i] >= 'a' && s[i] <= 'z') s[i] = s[i] - 'a' + 'A'; else
  if (s[i] == '-') s[i] = '_';
}

static inline bool is_hash_name(const string &s)
{
 if (s.length() == 3 && s[0] == 'M' && s[1] == 'D') return true;
 if (s.length() >= 3 && s[0] == 'S' && s[1] == 'H' && s[2] == 'A') return true;
 return false; 
}

string make_constant(const string &oid)
{
 std::list<string> words;
 string::size_type start = 0;
 while (start < oid.length())
 {
  int sep_class = UPPER;
  if (start + 1 < oid.length() &&
      get_letter_class(oid[start]) == UPPER &&
      get_letter_class(oid[start + 1]) == UPPER) sep_class = LOWER;
  string::size_type end = start + 1, skip = 0;  
  while (end < oid.length())
  {
   if (oid[end] == '-' && !(end + 1 < oid.length() && is_digit(oid[end + 1])))
   {
    skip = 1;
    break;
   }
   if (get_letter_class(oid[end]) == sep_class) break;
   end++;
  }
  if (sep_class == LOWER && end < oid.length() && !skip) end--;
  string word = oid.substr(start, end - start);
  convert_word(word);
  if (word != "ENCRYPTION") words.push_back(word);
  start = end + skip;
 }
 if (words.size() > 1 && words.front() == "ID") words.pop_front();
 string result = "ID";
 string hash_token;
 std::list<string> other_tokens;
 bool with = false;
 for (std::list<string>::const_iterator it = words.begin(); it != words.end(); it++)
 {
  result += '_';
  result += *it;
  if (*it == "WITH") with = true; else
  if (is_hash_name(*it)) hash_token = *it; else other_tokens.push_back(*it);  
 }
 if (!hash_token.empty())
 {
  if (with && other_tokens.size() == 1)
   return "ID_SIGN_" + other_tokens.front() + "_" + hash_token;
  if (other_tokens.empty())
   return "ID_HASH_" + hash_token;
 }
 return result;
}
