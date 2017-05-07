#ifndef __asn1_lexer_h__
#define __asn1_lexer_h__

#include <string>
#include <stddef.h>

namespace asn1_tokens
{
 enum
 {
  TOKEN_NONE,
  TOKEN_COMMENT,
  TOKEN_MULTILINE_COMMENT,
  TOKEN_IDENTIFIER,
  TOKEN_INTEGER,
  TOKEN_REAL,
  TOKEN_STRING,
  TOKEN_HEX_STRING,
  TOKEN_BIN_STRING,
  TOKEN_PUNCT,
  TOKEN_PUNCT_ASSIGNMENT,
  TOKEN_PUNCT_RANGE,
  TOKEN_PUNCT_ELLIPSIS,
  TOKEN_PUNCT_DOUBLE_BRACKET
 };
}

class asn1_lexer
{
 public:
  enum
  {
   ERROR_INVALID_CHARACTER = 1,
   ERROR_INVALID_NUMBER,
   ERROR_INVALID_SQ_STRING,
   ERROR_INVALID_BIN_STRING,
   ERROR_INVALID_HEX_STRING,
   ERROR_INVALID_COMMENT,
   ERROR_INVALID_COMMENT_NESTING,
   ERROR_STRING_NOT_TERM
  };

  enum
  {
   RESULT_NONE  = 0,
   RESULT_TOKEN = 1,
   RESULT_ERROR = -1
  };

  asn1_lexer();
  int process_buffer(const char *data, size_t size, size_t &pos);
  int flush();
  const std::string &get_token() const { return token; }
  int get_token_type() const { return token_type; }
  int get_error() const { return error; }
  void clear_token();

 protected:
  std::string token;  
  int token_type;
  int error;
  bool string_term;
  int comment_nesting;
  unsigned number_flags;
  char next_token_start;

  void process_word();
};

#endif // __asn1_lexer_h__
