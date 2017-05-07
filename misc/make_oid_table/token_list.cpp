#include "token_list.h"

using std::string;

static const token_list::size_type TOKEN_LIST_SIZE = 5;

void add_token(token_list &tl, int type, const string &text)
{
 token_info ti = { type, text };
 tl.push_back(ti);
 if (tl.size() > TOKEN_LIST_SIZE) tl.pop_front();
}

int get_prev_token(const token_list &tl, int n, string *text)
{
 token_list::const_reverse_iterator it = tl.rbegin();
 while (it != tl.rend())
 {
  if (!n)
  {
   if (text) *text = it->text;
   return it->type;
  }
  n--;
  it++;
 } 
 return 0;
}

void remove_tokens(token_list &tl, int n)
{
 while (n && !tl.empty())
 {
  tl.pop_back();
  n--;
 }
}
