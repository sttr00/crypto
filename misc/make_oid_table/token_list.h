#ifndef __token_list_h__
#define __token_list_h__

#include <string>
#include <list>

struct token_info
{
 int type;
 std::string text;
};

typedef std::list<token_info> token_list;

void add_token(token_list &tl, int type, const std::string &text);
int get_prev_token(const token_list &tl, int n, std::string *text);
void remove_tokens(token_list &tl, int n);

#endif // __token_list_h__
