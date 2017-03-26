#if defined(_WIN32)
#include "sys_random_win.h"
#elif defined(unix) || defined(__unix__)
#include "sys_random_unix.h"
#else
#error No suitable sys_random
#endif
