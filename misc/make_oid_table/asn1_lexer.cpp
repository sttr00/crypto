#include "asn1_lexer.h"
#include "asn1_keywords.h"
#include <cassert>

#define countof(a) (sizeof(a)/sizeof(a[0]))

using std::string;
using namespace asn1_tokens;

enum
{
 CC_WHITE_SPACE = 0x01,
 CC_NEW_LINE    = 0x02,
 CC_DIGIT       = 0x04,
 CC_LETTER      = 0x08,
 CC_PUNCT       = 0x10
};

static unsigned get_char_class(char c)
{
 if (c >= 10 && c <= 13) return CC_WHITE_SPACE | CC_NEW_LINE;
 if (c == '\t' || c == ' ') return CC_WHITE_SPACE;
 if (c >= '0' && c <= '9') return CC_DIGIT;
 if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) return CC_LETTER;
 if (c == '{' || c == '}' || c == '<' || c == '>' ||
     c == ',' || c == '.' || c == '(' || c == ')' ||
     c == '[' || c == ']' || c == '-' || c == ':' ||
     c == '=' || c == ';' || c == '@' || c == '|' ||
     c == '!' || c == '^' || c == '&' ||
     c == '*' || c == '/') return CC_PUNCT;
 return 0;
}

struct long_punct_t
{
 const char *text;
 unsigned len;
 int token;
};

static const long_punct_t long_punct[] =
{
 { "::=", 3, TOKEN_PUNCT_ASSIGNMENT     },
 { "..",  2, TOKEN_PUNCT_RANGE          },
 { "...", 3, TOKEN_PUNCT_ELLIPSIS       },
 { "[[",  2, TOKEN_PUNCT_DOUBLE_BRACKET },
 { "]]",  2, TOKEN_PUNCT_DOUBLE_BRACKET },
 { "--",  2, TOKEN_COMMENT              },
 { "/*",  2, TOKEN_MULTILINE_COMMENT    },
 { "*/",  2, TOKEN_MULTILINE_COMMENT    }
};

static inline bool compare(const long_punct_t &info, const string &str)
{
 if (info.text[0] != str[0]) return false;
 if (str.length() > 1 && info.text[1] != str[1]) return false;
 return true;
}

// these token types are used internally
enum
{
 TOKEN_WORD = 1024,
 TOKEN_NUMBER,
 TOKEN_SQ_STRING,
};

enum
{
 NUMBER_FLAG_HAS_DOT      = 1,
 NUMBER_FLAG_HAS_EXPONENT = 2
};

int asn1_lexer::process_buffer(const char *data, size_t size, size_t &pos)
{
 for (size_t i = pos; i < size; i++)
 {
  char c = data[i];
  if (token_type == TOKEN_SQ_STRING)
  {
   if (string_term)
   {
    if (c == 'B' || c == 'H')
    {
     token += c;
     if (c == 'B')
     {      
      for (string::size_type j = 1; j < token.length() - 2; j++)
       if (!(token[j] == '0' || token[j] == '1'))
       {
        pos = i + 1 - token.length() + j;
        error = ERROR_INVALID_BIN_STRING;
        return RESULT_ERROR;
       }
      token_type = TOKEN_BIN_STRING;
     } else
     {
      for (string::size_type j = 1; j < token.length() - 2; j++)
       if (!((token[j] >= '0' && token[j] <= '9') || (token[j] >= 'A' && token[j] <= 'F')))
       {
        pos = i + 1 - token.length() + j;
        error = ERROR_INVALID_HEX_STRING;
        return RESULT_ERROR;
       }
      token_type = TOKEN_HEX_STRING;
     }
     pos = i + 1;
     return RESULT_TOKEN;
    }
    pos = i;
    error = ERROR_INVALID_SQ_STRING;
    return RESULT_ERROR;
   }
   token += c;
   if (c == '\'') string_term = true;
   continue;
  }
  if (token_type == TOKEN_STRING)
  {
   if (string_term && c != '"')
   {
    pos = i;
    return RESULT_TOKEN;
   }
   token += c;
   if (c == '"') string_term = !string_term;
   continue;
  }
  if (token_type == TOKEN_COMMENT)
  {
   if (c == '-')
   {
    if (token.length() > 2 && token.back() == '-')
    {
     token += c;
     pos = i + 1;
     return RESULT_TOKEN;
    }
    token += c;
    continue;
   }
   if (get_char_class(c) & CC_NEW_LINE)
   {
    pos = i + 1;
    return RESULT_TOKEN;
   }
   token += c;
   continue;
  }
  if (token_type == TOKEN_MULTILINE_COMMENT)
  {   
   if (c == '*' && token.back() == '/')
   {
    token += c;
    comment_nesting++;
   } else
   if (c == '/' && token.back() == '*')
   {
    token += c;
    if (--comment_nesting == 0)
    {
     pos = i + 1;
     return RESULT_TOKEN;
    }
   } else token += c;
   continue;
  }
  if (token_type == TOKEN_WORD)
  {
   if (c == '-')
   {
    if (token.back() == '-')
    {
     pos = i;
     error = ERROR_INVALID_COMMENT;
     return RESULT_ERROR;
    }
    token += c;
    continue;
   }
   if (get_char_class(c) & (CC_LETTER | CC_DIGIT))
   {
    token += c;
    continue;
   }
   pos = i;
   process_word();
   return RESULT_TOKEN;
  }
  if (token_type == TOKEN_NUMBER)
  {
   if ((token.back() == 'e' || token.back() == 'E') && (c == '+' || c == '-'))
   {
    token += c;
    continue;
   }
   if (c == 'e' || c == 'E')
   {
    if (number_flags & NUMBER_FLAG_HAS_EXPONENT)
    {
     pos = i;
     error = ERROR_INVALID_NUMBER;
     return RESULT_ERROR;
    }
    number_flags |= NUMBER_FLAG_HAS_EXPONENT;
    token += c;
    continue;
   }
   if (c == '.')
   {
    if (token.back() == '.')
    {
     // special case for INTEGER(0..255) etc
     token.erase(token.length()-1);
     next_token_start = '.';
     pos = i;
     return RESULT_TOKEN;
    }
    if (number_flags & (NUMBER_FLAG_HAS_EXPONENT | NUMBER_FLAG_HAS_DOT))
    {
     pos = i;
     error = ERROR_INVALID_NUMBER;
     return RESULT_ERROR;    
    }
    number_flags |= NUMBER_FLAG_HAS_DOT;
    token += c;
    continue;
   }
   if (c >= '0' && c <= '9')
   {
    token += c;
    continue;
   }
   token_type = (number_flags & (NUMBER_FLAG_HAS_EXPONENT | NUMBER_FLAG_HAS_DOT))?
    TOKEN_REAL : TOKEN_INTEGER;
   pos = i;
   return RESULT_TOKEN;
  }
  if (token_type == TOKEN_PUNCT)
  {
   if (get_char_class(c) && CC_PUNCT)
   {
    int found = -1;
    for (unsigned k=0; k<countof(long_punct); k++)
     if (token.length() < long_punct[k].len &&
         compare(long_punct[k], token) &&
         long_punct[k].text[token.length()] == c)
     {
      found = k;
      break;
     }
    if (found != -1)
    {
     token += c;
     if (token.length() != long_punct[found].len) continue;
     token_type = long_punct[found].token;
     if (token_type == TOKEN_COMMENT) continue;
     if (token_type == TOKEN_MULTILINE_COMMENT)
     {
      if (token.back() == '/')
      {
       pos = i;
       error = ERROR_INVALID_COMMENT_NESTING;
       return RESULT_ERROR;       
      }
      comment_nesting = 1;
      continue;
     }
     pos = i + 1;
     return RESULT_TOKEN;
    }
   }
   pos = i;
   return RESULT_TOKEN;
  }
  assert(token_type == TOKEN_NONE);
  if (c == '\'')
  {
   string_term = false;
   token += c;
   token_type = TOKEN_SQ_STRING;
   continue;
  }
  if (c == '"')
  {
   string_term = false;
   token += c;
   token_type = TOKEN_STRING;
   continue;
  }
  unsigned cc = get_char_class(c);
  if (cc & CC_WHITE_SPACE) continue;
  if (cc & CC_DIGIT)
  {
   token += c;
   token_type = TOKEN_NUMBER;
   number_flags = 0;
   continue;
  }
  if (cc & CC_LETTER)
  {
   token += c;
   token_type = TOKEN_WORD;
   continue;
  }
  if (cc & CC_PUNCT)
  {
   token += c;
   token_type = TOKEN_PUNCT;
   continue;
  }
  pos = i;
  error = ERROR_INVALID_CHARACTER;
  return RESULT_ERROR;
 }
 pos = size;
 return RESULT_NONE;
}

int asn1_lexer::flush()
{
 if (comment_nesting)
 {
  error = ERROR_INVALID_COMMENT_NESTING;
  return RESULT_ERROR;
 }
 if (token_type == TOKEN_SQ_STRING || token_type == TOKEN_STRING)
 {
  error = ERROR_STRING_NOT_TERM;
  return RESULT_ERROR;
 }
 if (token_type == TOKEN_WORD)
 {
  process_word();
  return RESULT_TOKEN;
 }
 if (token_type == TOKEN_PUNCT) return RESULT_TOKEN;
 if (token_type == TOKEN_NUMBER)
 {
  token_type = (number_flags & (NUMBER_FLAG_HAS_EXPONENT | NUMBER_FLAG_HAS_DOT))?
   TOKEN_REAL : TOKEN_INTEGER;
  return RESULT_TOKEN;
 }
 return RESULT_NONE;
}

void asn1_lexer::process_word()
{
 int kw = get_keyword(token);
 if (kw) token_type = kw; else token_type = TOKEN_IDENTIFIER;
}

void asn1_lexer::clear_token()
{
 token.clear();
 token_type = TOKEN_NONE;
 if (next_token_start)
 {
  token += next_token_start;
  token_type = TOKEN_PUNCT;
  next_token_start = 0;
 }
}

asn1_lexer::asn1_lexer()
{
 token_type = TOKEN_NONE;
 error = 0;
 comment_nesting = 0;
 next_token_start = 0;
}
