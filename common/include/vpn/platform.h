#pragma once

#ifndef _WIN32
#define AG_ERR_IS_EAGAIN(err) ((EAGAIN == (err)) || (EWOULDBLOCK == (err)))
#define AG_ENETUNREACH ENETUNREACH
#define AG_EHOSTUNREACH EHOSTUNREACH
#define AG_ENOBUFS ENOBUFS
#define AG_EINTR EINTR

#define AG_SHUT_RD SHUT_RD
#define AG_SHUT_WR SHUT_WR
#define AG_SHUT_RDWR SHUT_RDWR
#endif

#ifdef __linux__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define ag_vsnprintf vsnprintf

#ifdef ANDROID
#include <pthread.h>
#else
#include <sys/syscall.h>
#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 30
static inline pid_t gettid(void) {
    return syscall(SYS_gettid);
}
#endif // __GLIBC__ == 2 && __GLIBC_MINOR__ < 30
#endif // ANDROID

#endif //__linux__

#ifdef __MACH__

#include <TargetConditionals.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <pwd.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#define ag_vsnprintf vsnprintf

#if TARGET_OS_IPHONE
#define DEFAULT_CONNECTION_MEMORY_BUFFER_SIZE (128 * 1024)
#endif // TARGET_OS_IPHONE

#endif //__MACH__

#ifdef _WIN32

#ifndef UNICODE
#define UNICODE
#endif

#ifndef _UNICODE
#define _UNICODE
#endif

#define AG_ERR_IS_EAGAIN(err) (WSAEWOULDBLOCK == (err))
#define AG_ENETUNREACH WSAENETUNREACH
#define AG_EHOSTUNREACH WSAEHOSTUNREACH
#define AG_ENOBUFS WSAENOBUFS
#define AG_EINTR WSAEINTR

#define AG_SHUT_RD SD_RECEIVE
#define AG_SHUT_WR SD_SEND
#define AG_SHUT_RDWR SD_BOTH

#define NOCRYPT // don't conflict with openssl
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#undef ERROR
#undef DELETE
#undef PASSTHROUGH
#include <ws2ipdef.h>
#include <ws2tcpip.h>
// Must be included after ws2*
#include <iphlpapi.h>
typedef int sa_family_t;
#define SHUT_WR SD_SEND
#ifndef _MSC_VER
#include <unistd.h>
#else
#include <basetsd.h>
typedef SSIZE_T ssize_t;
#include <io.h>
#endif
#include <process.h>
#include <winbase.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#undef max
#undef min

#define ag_vsnprintf std::vsnprintf

static inline uint32_t gettid() {
    return GetCurrentThreadId();
}

#ifndef PATH_MAX
#define PATH_MAX 260
#endif

#include <malloc.h>
#include <stdio.h>
#undef P_tmpdir
#define P_tmpdir "."
#undef _P_tmpdir
#define _P_tmpdir "."

// Avoid conflicts with Windows headers
#undef X509_NAME
#undef X509_EXTENSIONS
#undef PKCS7_ISSUER_AND_SERIAL
#undef PKCS7_SIGNER_INFO
#undef OCSP_REQUEST
#undef OCSP_RESPONSE

#endif //_WIN32

#ifdef _WIN32
#define AG_EXPORT extern __declspec(dllexport)
#elif defined(__GNUC__)
#define AG_EXPORT __attribute__((visibility("default")))
#else
#define AG_EXPORT
#endif

#ifdef _WIN32
#define WIN_EXPORT AG_EXPORT
#else
#define WIN_EXPORT
#endif

#undef AG_PLATFORM
#if defined _WIN32
#define AG_PLATFORM "Windows"
#elif defined __MACH__ && TARGET_OS_IPHONE
#define AG_PLATFORM "iOS"
#elif defined __MACH__
#define AG_PLATFORM "Mac"
#elif defined __linux__ && defined ANDROID
#define AG_PLATFORM "Android"
#elif defined __linux__
#define AG_PLATFORM "Linux"
#endif

#ifndef DEFAULT_CONNECTION_MEMORY_BUFFER_SIZE
#define DEFAULT_CONNECTION_MEMORY_BUFFER_SIZE (4 * 1024 * 1024)
#endif // DEFAULT_CONNECTION_MEMORY_BUFFER_SIZE

namespace ag::sys {

/** Get the code of the last error happened */
int last_error();

/** Get the error description */
const char *strerror(int code);

#ifdef _WIN32

/**
 * The helper for Windows 11 does not exist yet
 */
bool is_windows_11_or_greater();

#endif

} // namespace ag::sys
