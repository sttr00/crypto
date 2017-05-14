#include "str_int_cvt.h"
#include <limits>

using std::string;

template<typename T>
struct MAX_DIGITS { enum { value = 5*(sizeof(T)/2) }; };

template<>
struct MAX_DIGITS<int64_t> { enum { value = 19 }; };

template<typename T>
T _str_to_uint(const string &s, int *ppos, bool *ok)
{
 int pos = ppos? *ppos : 0;
 int start_pos = pos;
 T result = 0;
 if (pos < static_cast<int>(s.length()) && s[pos] == '+') pos++;
 while (pos < static_cast<int>(s.length()))
 {
  if (!(s[pos] >= '0' && s[pos] <= '9'))
  {
   if (ok) *ok = false;
   if (ppos) *ppos = pos;
   return result;
  }
  unsigned val = s[pos] - '0';
  T prev = result;
  result = result*10 + val;
  if (result < prev)
  {
   if (ok) *ok = false;
   if (ppos) *ppos = pos;
   return prev;
  }
  pos++;
 }
 if (ok) *ok = pos != start_pos;
 if (ppos) *ppos = pos;
 return result;
}

template<typename T>
T _str_to_int(const string &s, int *ppos, bool *ok)
{
 int pos = ppos? *ppos : 0;
 int start_pos = pos;
 T result = 0;
 bool negative = false;
 if (pos < static_cast<int>(s.length()))
 {
  if (s[pos] == '+') pos++; else
  if (s[pos] == '-') { pos++; negative = true; }
 }
 if (negative)
  while (pos < static_cast<int>(s.length()))
  {
   if (!(s[pos] >= '0' && s[pos] <= '9'))
   {
    if (ok) *ok = false;
    if (ppos) *ppos = pos;
    return result;
   }
   int val = s[pos] - '0';
   T prev = result;
   result = result*10 - val;
   if (result > 0)
   {
    if (ok) *ok = false;
    if (ppos) *ppos = pos;
    return prev;   
   }
   pos++;
  }
 else
  while (pos < static_cast<int>(s.length()))
  {
   if (!(s[pos] >= '0' && s[pos] <= '9'))
   {
    if (ok) *ok = false;
    if (ppos) *ppos = pos;
    return result;
   }
   int val = s[pos] - '0';
   T prev = result;
   result = result*10 + val;
   if (result < 0)
   {
    if (ok) *ok = false;
    if (ppos) *ppos = pos;
    return prev;   
   }
   pos++;
  }  
 if (ok) *ok = pos != start_pos;
 if (ppos) *ppos = pos;
 return result;
}

uint32_t str_to_uint32(const string &s, int *ppos, bool *ok)
{
 return _str_to_uint<uint32_t>(s, ppos, ok);
}

uint64_t str_to_uint64(const string &s, int *ppos, bool *ok)
{
 return _str_to_uint<uint64_t>(s, ppos, ok);
}

int32_t str_to_int32(const string &s, int *ppos, bool *ok)
{
 return _str_to_int<int32_t>(s, ppos, ok);
}

int64_t str_to_int64(const string &s, int *ppos, bool *ok)
{
 return _str_to_int<int64_t>(s, ppos, ok);
}

template<typename T>
void _uint_to_str(string &s, T val)
{
 char buf[MAX_DIGITS<T>::value];
 int pos = sizeof(buf);
 while (val)
 {
  buf[--pos] = '0' + val % 10;
  val /= 10;
 }
 if (pos != sizeof(buf)) s.append(buf + pos, sizeof(buf) - pos);
  else s += '0';
}

template<typename T>
void _int_to_str(string &s, T val)
{
 char buf[MAX_DIGITS<T>::value + 1];
 int pos = sizeof(buf);
 if (val < 0)
 {
  while (val)
  {
   buf[--pos] = '0' - val % 10;
   val /= 10;
  }
  buf[--pos] = '-';
 } else
 {
  while (val)
  {
   buf[--pos] = '0' + val % 10;
   val /= 10;
  }
 }
 if (pos != sizeof(buf)) s.append(buf + pos, sizeof(buf) - pos);
  else s += '0';
}

void uint32_to_str(string &s, uint32_t val)
{
 _uint_to_str<uint32_t>(s, val);
}

void uint64_to_str(string &s, uint64_t val)
{
 _uint_to_str<uint64_t>(s, val);
}

void int32_to_str(string &s, int32_t val)
{
 _int_to_str<int32_t>(s, val);
}

void int64_to_str(string &s, int64_t val)
{
 _int_to_str<int64_t>(s, val);
}

string uint32_to_str(uint32_t val)
{
 string s;
 uint32_to_str(s, val);
 return s;
}

string uint64_to_str(uint64_t val)
{
 string s;
 uint64_to_str(s, val);
 return s;
}

string int32_to_str(int32_t val)
{
 string s;
 int32_to_str(s, val);
 return s;
}

string int64_to_str(int64_t val)
{
 string s;
 int64_to_str(s, val);
 return s;
}
