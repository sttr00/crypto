#ifndef __asn1_keywords_h__
#define __asn1_keywords_h__

#include <string>

namespace asn1_tokens
{

 enum
 {
  MIN_TOKEN_KW = 256,
  TOKEN_KW_ABSENT = MIN_TOKEN_KW,
  TOKEN_KW_ABSTRACT_SYNTAX,
  TOKEN_KW_ALL,
  TOKEN_KW_APPLICATION,
  TOKEN_KW_AUTOMATIC,
  TOKEN_KW_BEGIN,
  TOKEN_KW_BIT,
  TOKEN_KW_BMP_STRING,
  TOKEN_KW_BOOLEAN,
  TOKEN_KW_BY,
  TOKEN_KW_CHARACTER,
  TOKEN_KW_CHOICE,
  TOKEN_KW_CLASS,
  TOKEN_KW_COMPONENT,
  TOKEN_KW_COMPONENTS,
  TOKEN_KW_CONSTRAINED,
  TOKEN_KW_CONTAINING,
  TOKEN_KW_DEFAULT,
  TOKEN_KW_DEFINITIONS,
  TOKEN_KW_EMBEDDED,
  TOKEN_KW_ENCODED,
  TOKEN_KW_END,
  TOKEN_KW_ENUMERATED,
  TOKEN_KW_EXCEPT,
  TOKEN_KW_EXPLICIT,
  TOKEN_KW_EXPORTS,
  TOKEN_KW_EXTENSIBILITY,
  TOKEN_KW_EXTERNAL,
  TOKEN_KW_FALSE,
  TOKEN_KW_FROM,
  TOKEN_KW_GENERAL_STRING,
  TOKEN_KW_GENERALIZED_TIME,
  TOKEN_KW_GRAPHIC_STRING,
  TOKEN_KW_IA5_STRING,
  TOKEN_KW_IDENTIFIER,
  TOKEN_KW_IMPLICIT,
  TOKEN_KW_IMPLIED,
  TOKEN_KW_IMPORTS,
  TOKEN_KW_INCLUDES,
  TOKEN_KW_INSTANCE,
  TOKEN_KW_INTEGER,
  TOKEN_KW_INTERSECTION,
  TOKEN_KW_ISO646_STRING,
  TOKEN_KW_MAX,
  TOKEN_KW_MIN,
  TOKEN_KW_MINUS_INFINITY,
  TOKEN_KW_NULL,
  TOKEN_KW_NUMERIC_STRING,
  TOKEN_KW_OBJECT,
  TOKEN_KW_OCTET,
  TOKEN_KW_OF,
  TOKEN_KW_OPTIONAL,
  TOKEN_KW_OBJECT_DESCRIPTOR,
  TOKEN_KW_PATTERN,
  TOKEN_KW_PDV,
  TOKEN_KW_PLUS_INFINITY,
  TOKEN_KW_PRESENT,
  TOKEN_KW_PRIVATE,
  TOKEN_KW_PRINTABLE_STRING,
  TOKEN_KW_REAL,
  TOKEN_KW_RELATIVE_OID,
  TOKEN_KW_SEQUENCE,
  TOKEN_KW_SET,
  TOKEN_KW_SIZE,
  TOKEN_KW_STRING,
  TOKEN_KW_SYNTAX,
  TOKEN_KW_T61_STRING,
  TOKEN_KW_TAGS,
  TOKEN_KW_TRUE,
  TOKEN_KW_TYPE_IDENTIFIER,
  TOKEN_KW_TELETEX_STRING,
  TOKEN_KW_UNION,
  TOKEN_KW_UNIQUE,
  TOKEN_KW_UNIVERSAL,
  TOKEN_KW_UTC_TIME,
  TOKEN_KW_UTF8_STRING,
  TOKEN_KW_UNIVERSAL_STRING,
  TOKEN_KW_VIDEOTEX_STRING,
  TOKEN_KW_VISIBLE_STRING,
  TOKEN_KW_WITH,
  MAX_TOKEN_KW = TOKEN_KW_WITH
 };

 int get_keyword(const std::string &str);

}

#endif // __asn1_keywords_h__