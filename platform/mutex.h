#ifndef __platform_mutex_h__
#define __platform_mutex_h__

#ifdef _WIN32

#include "win.h"

#ifdef __cplusplus
namespace platform
{
#endif

typedef CRITICAL_SECTION mutex_t;

static __inline int mutex_init(mutex_t *m)
{
 InitializeCriticalSection(m);
 return 0;
}

static __inline void mutex_destroy(mutex_t *m)
{
 DeleteCriticalSection(m);
}

static __inline void mutex_lock(mutex_t *m)
{
 EnterCriticalSection(m);
}

static __inline void mutex_unlock(mutex_t *m)
{
 LeaveCriticalSection(m);
}

#ifdef __cplusplus
} /* end namespace */
#endif

#else

#include <pthread.h>
#include <assert.h>

#ifdef __cplusplus
namespace platform
{
#endif

typedef pthread_mutex_t mutex_t;

static __inline int mutex_init(mutex_t *m)
{
 return pthread_mutex_init(m, 0);
}

static __inline void mutex_destroy(mutex_t *m)
{
 int result = pthread_mutex_destroy(m);
 assert(result == 0);
 (void) result;
}

static __inline void mutex_lock(mutex_t *m)
{
 int result = pthread_mutex_lock(m);
 assert(result == 0);
 (void) result;
}

static __inline void mutex_unlock(mutex_t *m)
{
 int result = pthread_mutex_unlock(m);
 assert(result == 0);
 (void) result;
}

#ifdef __cplusplus
} /* end namespace */
#endif

#endif

#endif /* __platform_mutex_h__ */
