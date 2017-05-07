#ifndef __oid_parser_h__
#define __oid_parser_h__

#include "oid_storage.h"
#include "token_list.h"

class oid_parser
{
 public:
  enum
  {
   RESULT_OK = 0,
   RESULT_DONE = 1,
   RESULT_ERROR = -1
  };

  oid_parser(named_oid_map &storage);
  bool start(const token_list &tl);
  bool process_token(int token_type, const std::string &token);
  bool is_finished() const { return state == STATE_FINISHED; }
  void clear();
  named_oid_map::iterator get_inserted_element() const { return last_elem; }

 private:
  oid_info oid; 
  std::string name;
  int state;
  unsigned flags;
  named_oid_map &storage;
  named_oid_map::iterator last_elem;
  unsigned order;

  enum
  {
   STATE_IDLE,
   STATE_STARTED,
   STATE_COMPONENT,
   STATE_PAREN_OPEN,
   STATE_PAREN_CLOSED,
   STATE_NUMBER_PAREN,
   STATE_FINISHED
  };
};

#endif // __oid_parser_h__
