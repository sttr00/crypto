/* Command-line: gperf -L ANSI-C -I -C -G -E -m 20 keywords.txt  */
/* Computed positions: -k'1,3-4' */

#include "asn1_keywords.h"
#include <cstring>

using namespace asn1_tokens;

enum
{
 TOTAL_KEYWORDS = 80,
 MIN_WORD_LENGTH = 2,
 MAX_WORD_LENGTH = 16,
 MIN_HASH_VALUE = 3,
 MAX_HASH_VALUE = 84
};

/* maximum key range = 82, duplicates = 0 */

static unsigned hash(const char *str, unsigned len)
{
 static const unsigned char asso_values[] =
 {
  85, 85, 85, 85, 85, 85, 85, 85, 85, 85,
  85, 85, 85, 85, 85, 85, 85, 85, 85, 85,
  85, 85, 85, 85, 85, 85, 85, 85, 85, 85,
  85, 85, 85, 85, 85, 85, 85, 85, 85, 85,
  85, 85, 85, 85, 85, 85, 85, 85, 85, 64,
  85, 85, 85, 62, 68, 85, 57, 85, 85, 85,
  85, 85, 85, 85, 85, 16, 54, 23, 45,  1,
   7, 18,  0,  0, 71, 85,  4, 12, 26,  1,
   9, 49, 28, 11,  0,  6, 32,  0, 63, 85,
  57, 85, 85, 85, 85, 85, 85, 21, 85, 85,
   7, 17, 85, 85, 85,  5, 35, 85, 38,  6,
  17, 85, 20, 85, 85,  1, 85, 85, 24, 85,
  85, 85, 85, 85, 85, 85, 85, 85, 85, 85,
  85, 85, 85, 85, 85, 85, 85, 85, 85, 85,
  85, 85, 85, 85, 85, 85, 85, 85, 85, 85,
  85, 85, 85, 85, 85, 85, 85, 85, 85, 85,
  85, 85, 85, 85, 85, 85, 85, 85, 85, 85,
  85, 85, 85, 85, 85, 85, 85, 85, 85, 85,
  85, 85, 85, 85, 85, 85, 85, 85, 85, 85,
  85, 85, 85, 85, 85, 85, 85, 85, 85, 85,
  85, 85, 85, 85, 85, 85, 85, 85, 85, 85,
  85, 85, 85, 85, 85, 85, 85, 85, 85, 85,
  85, 85, 85, 85, 85, 85, 85, 85, 85, 85,
  85, 85, 85, 85, 85, 85, 85, 85, 85, 85,
  85, 85, 85, 85, 85, 85, 85, 85, 85, 85,
  85, 85, 85, 85, 85, 85
 };
 int hval = len;
 switch (hval)
 {
  default:
   hval += asso_values[(unsigned char) str[3]];
   /*FALLTHROUGH*/
  case 3:
   hval += asso_values[(unsigned char) str[2]];
   /*FALLTHROUGH*/
  case 2:
  case 1:
   hval += asso_values[(unsigned char) str[0]];
   break;
 }
 return hval;
}

static const char * const wordlist[] =
{
 "", "", "",
 "OF",
 "WITH",
 "", "",
 "OCTET",
 "INTEGER",
 "OPTIONAL",
 "EXTERNAL",
 "TRUE",
 "UNION",
 "INTERSECTION",
 "SET",
 "EXTENSIBILITY",
 "PATTERN",
 "IMPORTS",
 "EXPORTS",
 "INSTANCE",
 "IMPLIED",
 "IMPLICIT",
 "EXPLICIT",
 "ALL",
 "FROM",
 "TYPE-IDENTIFIER",
 "AUTOMATIC",
 "FALSE",
 "PRESENT",
 "ENUMERATED",
 "CHOICE",
 "EXCEPT",
 "ENCODED",
 "TAGS",
 "ABSENT",
 "INCLUDES",
 "UTCTime",
 "IDENTIFIER",
 "NULL",
 "PLUS-INFINITY",
 "APPLICATION",
 "MIN",
 "ABSTRACT-SYNTAX",
 "SYNTAX",
 "PDV",
 "STRING",
 "PrintableString",
 "UNIVERSAL",
 "PRIVATE",
 "END",
 "UniversalString",
 "VisibleString",
 "REAL",
 "COMPONENT",
 "COMPONENTS",
 "CLASS",
 "BY",
 "BIT",
 "MINUS-INFINITY",
 "CONTAINING",
 "RELATIVE-OID",
 "UNIQUE",
 "NumericString",
 "DEFINITIONS",
 "EMBEDDED",
 "GeneralString",
 "BOOLEAN",
 "GeneralizedTime",
 "TeletexString",
 "ObjectDescriptor",
 "VideotexString",
 "CONSTRAINED",
 "GraphicString",
 "SIZE",
 "SEQUENCE",
 "DEFAULT",
 "CHARACTER",
 "BEGIN",
 "MAX",
 "OBJECT",
 "UTF8String",
 "ISO646String",
 "IA5String",
 "BMPString",
 "T61String"
};

static const int kw_list[] =
{
 0,
 0,
 0,
 TOKEN_KW_OF,
 TOKEN_KW_WITH,
 0,
 0,
 TOKEN_KW_OCTET,
 TOKEN_KW_INTEGER,
 TOKEN_KW_OPTIONAL,
 TOKEN_KW_EXTERNAL,
 TOKEN_KW_TRUE,
 TOKEN_KW_UNION,
 TOKEN_KW_INTERSECTION,
 TOKEN_KW_SET,
 TOKEN_KW_EXTENSIBILITY,
 TOKEN_KW_PATTERN,
 TOKEN_KW_IMPORTS,
 TOKEN_KW_EXPORTS,
 TOKEN_KW_INSTANCE,
 TOKEN_KW_IMPLIED,
 TOKEN_KW_IMPLICIT,
 TOKEN_KW_EXPLICIT,
 TOKEN_KW_ALL,
 TOKEN_KW_FROM,
 TOKEN_KW_TYPE_IDENTIFIER,
 TOKEN_KW_AUTOMATIC,
 TOKEN_KW_FALSE,
 TOKEN_KW_PRESENT,
 TOKEN_KW_ENUMERATED,
 TOKEN_KW_CHOICE,
 TOKEN_KW_EXCEPT,
 TOKEN_KW_ENCODED,
 TOKEN_KW_TAGS,
 TOKEN_KW_ABSENT,
 TOKEN_KW_INCLUDES,
 TOKEN_KW_UTC_TIME,
 TOKEN_KW_IDENTIFIER,
 TOKEN_KW_NULL,
 TOKEN_KW_PLUS_INFINITY,
 TOKEN_KW_APPLICATION,
 TOKEN_KW_MIN,
 TOKEN_KW_ABSTRACT_SYNTAX,
 TOKEN_KW_SYNTAX,
 TOKEN_KW_PDV,
 TOKEN_KW_STRING,
 TOKEN_KW_PRINTABLE_STRING,
 TOKEN_KW_UNIVERSAL,
 TOKEN_KW_PRIVATE,
 TOKEN_KW_END,
 TOKEN_KW_UNIVERSAL_STRING,
 TOKEN_KW_VISIBLE_STRING,
 TOKEN_KW_REAL,
 TOKEN_KW_COMPONENT,
 TOKEN_KW_COMPONENTS,
 TOKEN_KW_CLASS,
 TOKEN_KW_BY,
 TOKEN_KW_BIT,
 TOKEN_KW_MINUS_INFINITY,
 TOKEN_KW_CONTAINING,
 TOKEN_KW_RELATIVE_OID,
 TOKEN_KW_UNIQUE,
 TOKEN_KW_NUMERIC_STRING,
 TOKEN_KW_DEFINITIONS,
 TOKEN_KW_EMBEDDED,
 TOKEN_KW_GENERAL_STRING,
 TOKEN_KW_BOOLEAN,
 TOKEN_KW_GENERALIZED_TIME,
 TOKEN_KW_TELETEX_STRING,
 TOKEN_KW_OBJECT_DESCRIPTOR,
 TOKEN_KW_VIDEOTEX_STRING,
 TOKEN_KW_CONSTRAINED,
 TOKEN_KW_GRAPHIC_STRING,
 TOKEN_KW_SIZE,
 TOKEN_KW_SEQUENCE,
 TOKEN_KW_DEFAULT,
 TOKEN_KW_CHARACTER,
 TOKEN_KW_BEGIN,
 TOKEN_KW_MAX,
 TOKEN_KW_OBJECT,
 TOKEN_KW_UTF8_STRING,
 TOKEN_KW_ISO646_STRING,
 TOKEN_KW_IA5_STRING,
 TOKEN_KW_BMP_STRING,
 TOKEN_KW_T61_STRING
};

int asn1_tokens::get_keyword(const std::string &str)
{
 if (str.length() <= MAX_WORD_LENGTH && str.length() >= MIN_WORD_LENGTH)
 {
  int key = hash(str.c_str(), str.length());
  if (key <= MAX_HASH_VALUE && key >= 0)
  {
   const char *s = wordlist[key];
   if (str[0] == *s && !strcmp(str.c_str() + 1, s + 1))
    return kw_list[key];
  }
 }
 return 0;
}
