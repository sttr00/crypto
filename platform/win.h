#ifndef __platform_win_h__
#define __platform_win_h__

#ifndef _WIN32
#error _WIN32 is not defined
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#endif /* __platform_win_h__ */
