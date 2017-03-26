#ifndef __platform_file_h__
#define __platform_file_h__

#include <stdint.h>

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#ifdef __cplusplus
namespace platform
{
#endif

typedef HANDLE file_t;
typedef WCHAR filename_wchar_t;

#ifdef __cplusplus
static const file_t INVALID_FILE   = INVALID_HANDLE_VALUE;
static const int SEEK_MODE_SET     = FILE_BEGIN;
static const int SEEK_MODE_CURRENT = FILE_CURRENT;
static const int SEEK_MODE_END     = FILE_END;
#else
#define INVALID_FILE      INVALID_HANDLE_VALUE
#define SEEK_MODE_SET     FILE_BEGIN
#define SEEK_MODE_CURRENT FILE_CURRENT
#define SEEK_MODE_END     FILE_END
#endif

static __inline file_t open_file(const char *filename)
{
 return CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
}

static __inline file_t open_file_utf16(const filename_wchar_t *filename)
{
 return CreateFileW(filename, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
}

static __inline file_t create_file(const char *filename)
{
 return CreateFileA(filename, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

static __inline file_t create_file_utf16(const filename_wchar_t *filename)
{
 return CreateFileW(filename, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

static __inline void close_file(file_t f)
{
 CloseHandle(f);
}

static __inline int write_file(file_t f, const void *data, int size)
{
 DWORD result;
 if (!WriteFile(f, data, size, &result, NULL)) return -1;
 return result;
}

static __inline int read_file(file_t f, void *data, int size)
{
 DWORD result;
 if (!ReadFile(f, data, size, &result, NULL)) return -1;
 return result;
}

static __inline uint64_t seek_file(file_t f, uint64_t pos, int mode)
{
 LARGE_INTEGER result;
 if (!SetFilePointerEx(f, *(LARGE_INTEGER *) &pos, &result, mode)) return (uint64_t) -1;
 return result.QuadPart;
}

static __inline uint64_t get_file_size(file_t f)
{
 LARGE_INTEGER result;
 if (!GetFileSizeEx(f, &result)) return (uint64_t) -1;
 return result.QuadPart;
}

#ifdef __cplusplus
} /* end namespace */
#endif

#else

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#ifdef __cplusplus
namespace platform
{
#endif

typedef int file_t;

#ifdef __cplusplus
static const file_t INVALID_FILE   = -1;
static const int SEEK_MODE_SET     = SEEK_SET;
static const int SEEK_MODE_CURRENT = SEEK_CUR;
static const int SEEK_MODE_END     = SEEK_END;
#else
#define INVALID_FILE      (-1)
#define SEEK_MODE_SET     SEEK_SET
#define SEEK_MODE_CURRENT SEEK_CUR
#define SEEK_MODE_END     SEEK_END
#endif

#ifdef O_LARGEFILE
#define __COMPAT_FLAG_LARGEFILE O_LARGEFILE
#else
#define __COMPAT_FLAG_LARGEFILE 0
#endif

#ifdef O_CLOEXEC
#define __COMPAT_FLAG_CLOEXEC O_CLOEXEC
#else
#define __COMPAT_FLAG_CLOEXEC 0
#endif

static __inline file_t open_file(const char *filename)
{
 int fd = open(filename, O_RDONLY | __COMPAT_FLAG_LARGEFILE | __COMPAT_FLAG_CLOEXEC);
 #if !defined(O_CLOEXEC) && defined(FD_CLOEXEC)
 if (fd != -1) fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
 #endif
 return fd;
}

static __inline file_t create_file(const char *filename)
{
 int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | __COMPAT_FLAG_LARGEFILE | __COMPAT_FLAG_CLOEXEC, 0644);
 #if !defined(O_CLOEXEC) && defined(FD_CLOEXEC)
 if (fd != -1) fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
 #endif
 return fd;
}

static __inline file_t create_file_perm(const char *filename, unsigned perm)
{
 int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | __COMPAT_FLAG_LARGEFILE | __COMPAT_FLAG_CLOEXEC, perm);
 #if !defined(O_CLOEXEC) && defined(FD_CLOEXEC)
 if (fd != -1) fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
 #endif
 return fd;
}

static __inline void close_file(file_t f)
{
 close(f);
}

static __inline int write_file(file_t f, const void *data, int size)
{
 return write(f, data, size);
}

static __inline int read_file(file_t f, void *data, int size)
{
 return read(f, data, size);
}

static __inline uint64_t seek_file(file_t f, uint64_t pos, int mode)
{
 #if (defined(_FILE_OFFSET_BITS) && _FILE_OFFSET_BITS == 64) || defined(__LP64__)
 return lseek(f, pos, mode);
 #else
 return lseek64(f, pos, mode);
 #endif
}

static __inline uint64_t get_file_size(file_t f)
{
 #if (defined(_FILE_OFFSET_BITS) && _FILE_OFFSET_BITS == 64) || defined(__LP64__)
 struct stat st;
 int error = fstat(f, &st);
 #else
 struct stat64 st;
 int error = fstat64(f, &st);
 #endif
 if (error) return (uint64_t) -1;
 return st.st_size;
}

#ifdef __cplusplus
} /* end namespace */
#endif

#endif

#endif /* __platform_file_h__ */
