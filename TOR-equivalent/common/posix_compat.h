/*
 * posix_compat.h: Win32 API shim for Linux/POSIX builds
 *
 * The original code was written against Win32 (Winsock2 + kernel32
 * threading/timing primitives). Rather than rewrite every node's control
 * flow, this header re-implements the small slice of the Win32 API surface
 * that the code actually uses, backed by pthreads / POSIX sockets /
 * clock_gettime. Node .c files that used to `#include <windows.h>` now
 * include this header instead; everything else is unchanged.
 *
 * Covers: SOCKET/closesocket, CRITICAL_SECTION, HANDLE (threads + events),
 * CreateThread/CloseHandle, CreateEvent/SetEvent/ResetEvent,
 * WaitForSingleObject, Sleep, QueryPerformanceCounter/Frequency,
 * GetTickCount64, InterlockedIncrement.
 */

#ifndef POSIX_COMPAT_H
#define POSIX_COMPAT_H

#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>

/* winsock2.h/ws2tcpip.h used to bring these in transitively; several node
 * files call setsockopt()/IPPROTO_TCP/TCP_NODELAY etc. directly, so pull
 * in their POSIX equivalents here too. */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define SD_RECEIVE SHUT_RD
#define SD_SEND    SHUT_WR
#define SD_BOTH    SHUT_RDWR

#ifdef __cplusplus
extern "C" {
#endif

/* Basic types */

typedef int             BOOL;
typedef unsigned long   DWORD;
typedef void            *LPVOID;
typedef long             LONG;
typedef long long        LONGLONG;
#ifndef TRUE
#define TRUE  1
#endif
#ifndef FALSE
#define FALSE 0
#endif
#define WINAPI
#define INFINITE ((DWORD)-1)

/* Sockets */
/* Real POSIX sockets are used (see net.c); this just supplies the names
 * the original code was written against. */

typedef int SOCKET;
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR   (-1)
#define closesocket(s) close(s)

/* Critical sections -> pthread mutex */

typedef pthread_mutex_t CRITICAL_SECTION;

static inline void InitializeCriticalSection(CRITICAL_SECTION *cs) {
    pthread_mutex_init(cs, NULL);
}
static inline void DeleteCriticalSection(CRITICAL_SECTION *cs) {
    pthread_mutex_destroy(cs);
}
static inline void EnterCriticalSection(CRITICAL_SECTION *cs) {
    pthread_mutex_lock(cs);
}
static inline void LeaveCriticalSection(CRITICAL_SECTION *cs) {
    pthread_mutex_unlock(cs);
}

/* HANDLE: unifies thread handles and event objects */

typedef struct win_handle {
    int type;               /* 0 = thread, 1 = event */
    pthread_t thread;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int signaled;
    int manual_reset;
} *HANDLE;

#define WIN_HANDLE_THREAD 0
#define WIN_HANDLE_EVENT  1

typedef DWORD (WINAPI *win_thread_fn)(LPVOID);

typedef struct {
    win_thread_fn fn;
    LPVOID arg;
} _win_thread_tramp_arg_t;

static inline void *_win_thread_trampoline(void *p) {
    _win_thread_tramp_arg_t *t = (_win_thread_tramp_arg_t *)p;
    win_thread_fn fn = t->fn;
    LPVOID arg = t->arg;
    free(t);
    fn(arg);
    return NULL;
}

/* CreateThread(lpThreadAttributes, dwStackSize, fn, arg, dwFlags, lpThreadId) */
static inline HANDLE CreateThread(void *sa, size_t stacksize,
                                   win_thread_fn fn, LPVOID arg,
                                   DWORD flags, void *id) {
    (void)sa; (void)stacksize; (void)flags; (void)id;
    HANDLE h = (HANDLE)malloc(sizeof(*h));
    if (!h) return NULL;
    h->type = WIN_HANDLE_THREAD;
    _win_thread_tramp_arg_t *t =
        (_win_thread_tramp_arg_t *)malloc(sizeof(*t));
    t->fn = fn;
    t->arg = arg;
    if (pthread_create(&h->thread, NULL, _win_thread_trampoline, t) != 0) {
        free(t);
        free(h);
        return NULL;
    }
    return h;
}

/* CreateEvent(lpEventAttributes, bManualReset, bInitialState, lpName) */
static inline HANDLE CreateEvent(void *sa, BOOL manual_reset,
                                  BOOL initial_state, const void *name) {
    (void)sa; (void)name;
    HANDLE h = (HANDLE)malloc(sizeof(*h));
    if (!h) return NULL;
    h->type = WIN_HANDLE_EVENT;
    pthread_mutex_init(&h->mutex, NULL);
    pthread_cond_init(&h->cond, NULL);
    h->signaled = initial_state ? 1 : 0;
    h->manual_reset = manual_reset ? 1 : 0;
    return h;
}

static inline void SetEvent(HANDLE h) {
    if (!h) return;
    pthread_mutex_lock(&h->mutex);
    h->signaled = 1;
    if (h->manual_reset)
        pthread_cond_broadcast(&h->cond);
    else
        pthread_cond_signal(&h->cond);
    pthread_mutex_unlock(&h->mutex);
}

static inline void ResetEvent(HANDLE h) {
    if (!h) return;
    pthread_mutex_lock(&h->mutex);
    h->signaled = 0;
    pthread_mutex_unlock(&h->mutex);
}

#define WAIT_OBJECT_0 0
#define WAIT_TIMEOUT  258
#define WAIT_FAILED   ((DWORD)0xFFFFFFFF)

static inline DWORD WaitForSingleObject(HANDLE h, DWORD ms) {
    if (!h) return WAIT_FAILED;

    if (h->type == WIN_HANDLE_THREAD) {
        /* Timeouts on thread joins aren't used meaningfully by this
         * codebase (always called during shutdown after a stop flag is
         * set); a plain join is sufficient and avoids pulling in the
         * non-portable pthread_timedjoin_np GNU extension. */
        (void)ms;
        pthread_join(h->thread, NULL);
        return WAIT_OBJECT_0;
    }

    /* Event object */
    pthread_mutex_lock(&h->mutex);
    DWORD rc = WAIT_OBJECT_0;
    if (!h->signaled) {
        if (ms == INFINITE) {
            while (!h->signaled)
                pthread_cond_wait(&h->cond, &h->mutex);
        } else {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec  += ms / 1000;
            ts.tv_nsec += (long)(ms % 1000) * 1000000L;
            if (ts.tv_nsec >= 1000000000L) {
                ts.tv_sec  += 1;
                ts.tv_nsec -= 1000000000L;
            }
            int err = 0;
            while (!h->signaled && err == 0)
                err = pthread_cond_timedwait(&h->cond, &h->mutex, &ts);
            if (!h->signaled)
                rc = (err == ETIMEDOUT) ? WAIT_TIMEOUT : WAIT_FAILED;
        }
    }
    if (rc == WAIT_OBJECT_0 && !h->manual_reset)
        h->signaled = 0;   /* auto-reset: consume the signal */
    pthread_mutex_unlock(&h->mutex);
    return rc;
}

/* CloseHandle: detaches a running thread (fire-and-forget, matches the
 * original code's CreateThread()+CloseHandle() "detach" idiom) or
 * destroys an event object. */
static inline BOOL CloseHandle(HANDLE h) {
    if (!h) return FALSE;
    if (h->type == WIN_HANDLE_THREAD) {
        pthread_detach(h->thread);
    } else {
        pthread_mutex_destroy(&h->mutex);
        pthread_cond_destroy(&h->cond);
    }
    free(h);
    return TRUE;
}

/* Sleep / timing */

static inline void Sleep(DWORD ms) {
    struct timespec ts;
    ts.tv_sec  = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

typedef struct { int64_t QuadPart; } LARGE_INTEGER;

static inline void QueryPerformanceFrequency(LARGE_INTEGER *f) {
    /* We report a nanosecond-resolution counter, so the "frequency" is
     * a fixed 1e9 ticks/sec regardless of platform. */
    f->QuadPart = 1000000000LL;
}

static inline void QueryPerformanceCounter(LARGE_INTEGER *c) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    c->QuadPart = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static inline uint64_t GetTickCount64(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static inline DWORD GetTickCount(void) {
    return (DWORD)GetTickCount64();
}

/* Atomics */

static inline LONG InterlockedIncrement(volatile LONG *v) {
    return __sync_add_and_fetch(v, 1);
}

static inline LONG InterlockedDecrement(volatile LONG *v) {
    return __sync_sub_and_fetch(v, 1);
}

static inline LONG InterlockedAdd(volatile LONG *v, LONG add) {
    return __sync_add_and_fetch(v, add);
}

/* Misc console / filesystem / process shims */

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* No-op: console codepage selection is a Windows-only concept. */
static inline void SetConsoleOutputCP(unsigned cp) {
    (void)cp;
}

/* CreateDirectoryA(path, securityAttributes) -> BOOL. mkdir 0755;
 * "already exists" is treated as success, matching typical call sites
 * here (best-effort directory creation before writing key files). */
static inline BOOL CreateDirectoryA(const char *path, void *sa) {
    (void)sa;
    if (mkdir(path, 0755) == 0)
        return TRUE;
    return (errno == EEXIST) ? TRUE : FALSE;
}

static inline DWORD GetCurrentProcessId(void) {
    return (DWORD)getpid();
}

#ifdef __cplusplus
}
#endif

#endif /* POSIX_COMPAT_H */
