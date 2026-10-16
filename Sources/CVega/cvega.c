#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "cvega.h"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <errno.h>
#include <process.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// aligned_alloc isn't in the MSVC CRT.
#define cv_aligned_alloc(align, size) _aligned_malloc((size), (align))
#define cv_aligned_free(p) _aligned_free(p)
#else
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stddef.h>
#include <pthread.h>
#include <sched.h>
#include <poll.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <spawn.h>
#if defined(__APPLE__)
#include <TargetConditionals.h>
#if TARGET_OS_IPHONE
// iOS, tvOS, watchOS, visionOS: apps may not fork or spawn processes.
#define CV_NO_SPAWN 1
#endif
#endif
#include <sys/socket.h>
#if defined(__linux__)
#include <sys/prctl.h>
#endif
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#include <linux/futex.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/sendfile.h>
#include <sys/random.h>
#include <sys/syscall.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <os/os_sync_wait_on_address.h>
#include <sys/event.h>
#endif
#define cv_aligned_alloc(align, size) aligned_alloc((align), (size))
#define cv_aligned_free(p) free(p)
#endif

#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define CV_TSAN 1
#endif
#endif

_Thread_local void *cv_current_tls;

#if defined(_WIN32)
uint64_t cv_now_ns(void) {
    static LARGE_INTEGER freq;
    if (!freq.QuadPart) QueryPerformanceFrequency(&freq);
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    // Split to keep the multiply in range: QPC runs at 10 MHz or more.
    uint64_t sec = (uint64_t)t.QuadPart / (uint64_t)freq.QuadPart;
    uint64_t rem = (uint64_t)t.QuadPart % (uint64_t)freq.QuadPart;
    return sec * 1000000000ull + rem * 1000000000ull / (uint64_t)freq.QuadPart;
}

uint64_t cv_now_coarse_ns(void) { return (uint64_t)GetTickCount64() * 1000000ull; }

int cv_cpu_count(void) {
    DWORD n = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    return n > 0 ? (int)n : 1;
}

int cv_affinity_list(int *cpus, int max) {
    (void)cpus;
    (void)max;
    return -1;
}

int cv_current_cpu(void) { return (int)GetCurrentProcessorNumber(); }
#else
uint64_t cv_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

uint64_t cv_now_coarse_ns(void) {
#if defined(CLOCK_MONOTONIC_COARSE)
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
#elif defined(__APPLE__)
    return clock_gettime_nsec_np(CLOCK_UPTIME_RAW_APPROX);
#else
    return cv_now_ns();
#endif
}

int cv_cpu_count(void) {
#if defined(__linux__)
    cpu_set_t set;
    if (sched_getaffinity(0, sizeof set, &set) == 0 && CPU_COUNT(&set) > 0) return CPU_COUNT(&set);
#endif
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? (int)n : 1;
}

int cv_affinity_list(int *cpus, int max) {
#if defined(__linux__)
    cpu_set_t set;
    if (sched_getaffinity(0, sizeof set, &set) != 0) return -1;
    int n = 0;
    for (int cpu = 0; cpu < CPU_SETSIZE && n < max; cpu++) {
        if (CPU_ISSET(cpu, &set)) cpus[n++] = cpu;
    }
    return n;
#else
    (void)cpus;
    (void)max;
    return -1;
#endif
}

int cv_current_cpu(void) {
#if defined(__linux__)
    return sched_getcpu();
#else
    return -1;
#endif
}
#endif

// ---- parker --------------------------------------------------------------

// PARKED_IO: blocked in the I/O driver, woken through it (an eventfd write
// on Linux, an EVFILT_USER trigger on Darwin).
enum { EMPTY = 0, PARKED = 1, NOTIFIED = 2, PARKED_IO = 3 };

struct cv_parker {
    _Atomic uint32_t state;
    int wake_fd; // the driver's eventfd (Linux) or kqueue (Darwin), or -1
    void *wake_port; // Windows: the driver's completion port, or NULL
    char pad[112]; // own cache line pair: parkers are hit from other threads
};
_Static_assert(sizeof(struct cv_parker) == 128, "aligned_alloc needs a multiple of the alignment");

cv_parker *cv_parker_new(void) {
    cv_parker *p = cv_aligned_alloc(128, sizeof(cv_parker));
    if (!p) abort();
    atomic_init(&p->state, EMPTY);
    p->wake_fd = -1;
    p->wake_port = NULL;
    return p;
}

void cv_parker_free(cv_parker *p) { cv_aligned_free(p); }

static void wait_on(_Atomic uint32_t *addr, uint32_t expected, int64_t timeout_ns) {
#if defined(__linux__)
    struct timespec ts, *tp = NULL;
    if (timeout_ns >= 0) {
        ts.tv_sec = (time_t)(timeout_ns / 1000000000);
        ts.tv_nsec = (long)(timeout_ns % 1000000000);
        tp = &ts;
    }
    syscall(SYS_futex, (uint32_t *)addr, FUTEX_WAIT_PRIVATE, expected, tp, NULL, 0);
#elif defined(__APPLE__)
    if (timeout_ns < 0)
        os_sync_wait_on_address((void *)addr, expected, 4, OS_SYNC_WAIT_ON_ADDRESS_NONE);
    else if (timeout_ns > 0) // the timeout is in nanoseconds; 0 is an error
        os_sync_wait_on_address_with_timeout((void *)addr, expected, 4, OS_SYNC_WAIT_ON_ADDRESS_NONE,
                                             OS_CLOCK_MACH_ABSOLUTE_TIME, (uint64_t)timeout_ns);
#elif defined(_WIN32)
    // Milliseconds, rounded up so a short timeout still waits.
    DWORD ms = timeout_ns < 0 ? INFINITE : (DWORD)((timeout_ns + 999999) / 1000000);
    WaitOnAddress((volatile void *)addr, &expected, sizeof expected, ms);
#else
#error "cv_park: unsupported platform"
#endif
}

static void wake_one(_Atomic uint32_t *addr) {
#if defined(__linux__)
    syscall(SYS_futex, (uint32_t *)addr, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);
#elif defined(__APPLE__)
    os_sync_wake_by_address_any((void *)addr, 4, OS_SYNC_WAKE_BY_ADDRESS_NONE);
#elif defined(_WIN32)
    WakeByAddressSingle((void *)addr);
#endif
}

static inline void cpu_relax(void) {
#if defined(__x86_64__) || defined(__i386__)
    __builtin_ia32_pause();
#elif defined(__aarch64__)
    __asm__ __volatile__("yield");
#endif
}

void cv_park(cv_parker *p, int64_t timeout_ns) { cv_park_spin(p, timeout_ns, 0); }

void cv_park_spin(cv_parker *p, int64_t timeout_ns, int64_t spin_ns) {
    uint32_t expected = NOTIFIED;
    if (atomic_compare_exchange_strong(&p->state, &expected, EMPTY)) return;
    if (spin_ns > 0) {
        // Stay EMPTY while spinning: an unpark now is a plain store, no syscall
        // for the waker. Most wake-ups in a burst of work land in this window.
        if (timeout_ns >= 0 && timeout_ns < spin_ns) spin_ns = timeout_ns;
        uint64_t start = cv_now_ns();
        for (uint32_t i = 1;; i++) {
            cpu_relax();
            if (atomic_load_explicit(&p->state, memory_order_relaxed) == NOTIFIED) {
                expected = NOTIFIED;
                atomic_compare_exchange_strong(&p->state, &expected, EMPTY);
                return;
            }
            if ((i & 63) == 0) {
                uint64_t spent = cv_now_ns() - start;
                if (spent >= (uint64_t)spin_ns) {
                    if (timeout_ns >= 0) {
                        timeout_ns -= (int64_t)spent;
                        if (timeout_ns <= 0) return; // timed out while spinning
                    }
                    break;
                }
            }
        }
    }
    expected = EMPTY;
    if (!atomic_compare_exchange_strong(&p->state, &expected, PARKED)) {
        atomic_store(&p->state, EMPTY); // it was NOTIFIED between the two CASes
        return;
    }
    uint64_t deadline = timeout_ns >= 0 ? cv_now_ns() + (uint64_t)timeout_ns : 0;
    for (;;) {
        int64_t remaining = -1;
        if (timeout_ns >= 0) {
            uint64_t now = cv_now_ns();
            if (now >= deadline) break;
            remaining = (int64_t)(deadline - now);
        }
        wait_on(&p->state, PARKED, remaining);
        expected = NOTIFIED;
        if (atomic_compare_exchange_strong(&p->state, &expected, EMPTY)) return;
        // spurious wake-up or EINTR: go round
    }
    atomic_store(&p->state, EMPTY); // timed out; a racing notify is consumed (caller rechecks)
}

/// Interrupt a turn blocked in the driver whose wake fd is `fd`.
/// The completion key of a wake posted to a Windows driver's port.
#define CV_WAKE_KEY ((ULONG_PTR)1)

static void driver_wake(cv_parker *p) {
#if defined(_WIN32)
    PostQueuedCompletionStatus((HANDLE)p->wake_port, 0, CV_WAKE_KEY, NULL);
#else
    int fd = p->wake_fd;
#endif
#if defined(__linux__)
    uint64_t one = 1;
    ssize_t r = write(fd, &one, sizeof one);
    (void)r; // EAGAIN only if the counter is saturated: a wake is pending anyway
#elif defined(__APPLE__)
    struct kevent ev;
    EV_SET(&ev, 0, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
    kevent(fd, &ev, 1, NULL, 0, NULL);
#elif !defined(_WIN32)
    (void)fd;
#endif
}

void cv_unpark(cv_parker *p) {
    uint32_t old = atomic_exchange(&p->state, NOTIFIED);
    if (old == PARKED) {
        wake_one(&p->state);
    } else if (old == PARKED_IO) {
        driver_wake(p);
    }
}

// ---- lock ----------------------------------------------------------------

cv_lock *cv_lock_new(void) {
    // A cache line of its own: the word is written by every locker.
    cv_lock *l = cv_aligned_alloc(128, 128);
    if (!l) abort();
    __atomic_store_n(&l->state, 0, __ATOMIC_RELAXED);
    return l;
}

void cv_lock_free(cv_lock *l) { cv_aligned_free(l); }

void cv_lock_lock_slow(cv_lock *l) {
    // Spin while the holder is likely mid-critical-section: they are short.
    for (int i = 0; i < 100; i++) {
        uint32_t s = __atomic_load_n(&l->state, __ATOMIC_RELAXED);
        if (s == 0) {
            uint32_t expected = 0;
            if (__atomic_compare_exchange_n(&l->state, &expected, 1, 1, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
                return;
        } else if (s == 2) {
            break; // others already sleep: queue up behind them
        }
        cpu_relax();
    }
    // Mark contended (2) so the unlocker wakes someone, and sleep until the
    // exchange finds the lock free. Holding 2 after acquiring is harmless:
    // at worst one spurious wake.
    while (__atomic_exchange_n(&l->state, 2, __ATOMIC_ACQUIRE) != 0)
        wait_on((_Atomic uint32_t *)&l->state, 2, -1);
}

void cv_lock_wake(cv_lock *l) { wake_one((_Atomic uint32_t *)&l->state); }

// ---- threads -------------------------------------------------------------

struct start {
    cv_thread_fn fn;
    void *arg;
    int cpu;
    char name[16];
};

#if defined(_WIN32)
static unsigned __stdcall trampoline(void *raw) {
    struct start s = *(struct start *)raw;
    free(raw);
    if (s.cpu >= 0 && s.cpu < 64) SetThreadAffinityMask(GetCurrentThread(), (DWORD_PTR)1 << s.cpu);
    wchar_t wide[16];
    MultiByteToWideChar(CP_UTF8, 0, s.name, -1, wide, 16);
    SetThreadDescription(GetCurrentThread(), wide);
    s.fn(s.arg);
    return 0;
}

int cv_thread_spawn(cv_thread_fn fn, void *arg, const char *name, int cpu) {
    struct start *s = malloc(sizeof *s);
    if (!s) return ENOMEM;
    s->fn = fn;
    s->arg = arg;
    s->cpu = cpu;
    strncpy(s->name, name ? name : "vega", sizeof s->name - 1);
    s->name[sizeof s->name - 1] = 0;
    uintptr_t h = _beginthreadex(NULL, 2u << 20, trampoline, s, 0, NULL);
    if (h == 0) {
        free(s);
        return errno ? errno : EAGAIN;
    }
    CloseHandle((HANDLE)h); // detached
    return 0;
}
#else
static void *trampoline(void *raw) {
    struct start s = *(struct start *)raw;
    free(raw);
#if defined(__linux__)
    if (s.cpu >= 0) {
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(s.cpu, &set);
        pthread_setaffinity_np(pthread_self(), sizeof set, &set);
    }
    pthread_setname_np(pthread_self(), s.name);
#elif defined(__APPLE__)
    pthread_setname_np(s.name);
#endif
    s.fn(s.arg);
    return NULL;
}

int cv_thread_spawn(cv_thread_fn fn, void *arg, const char *name, int cpu) {
    struct start *s = malloc(sizeof *s);
    if (!s) return ENOMEM;
    s->fn = fn;
    s->arg = arg;
    s->cpu = cpu;
    strncpy(s->name, name ? name : "vega", sizeof s->name - 1);
    s->name[sizeof s->name - 1] = 0;

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&attr, 2u << 20);
    pthread_t t;
    int rc = pthread_create(&t, &attr, trampoline, s);
    pthread_attr_destroy(&attr);
    if (rc != 0) free(s);
    return rc;
}
#endif

// ---- I/O driver ----------------------------------------------------------
// Edge-triggered readiness: epoll with EPOLLET on Linux, kqueue with EV_CLEAR
// on Darwin. Everything but creating, registering and polling is shared.

#if defined(__linux__) || defined(__APPLE__)

#define CV_MAX_EVENTS 1024 // as Tokio: fewer ready sockets left for the next poll

#if defined(__linux__)
typedef struct epoll_event cv_event;
#else
typedef struct kevent cv_event;
#endif

struct cv_driver {
    _Atomic uint32_t locked; // polled by one thread at a time
    char pad0[124];
    _Atomic int registered;
    _Atomic(cv_io *) released; // deregistered, freed by the next turn
    char pad1[112];
    int poll_fd; // the epoll or kqueue instance
    int wake_fd; // Linux: an eventfd; Darwin: poll_fd itself (EVFILT_USER)
    // Used only by the lock holder.
    cv_driver_stats stats;
    cv_event events[CV_MAX_EVENTS];
    uintptr_t wakes[2 * CV_MAX_EVENTS];
};

cv_driver *cv_driver_new(void) {
    cv_driver *d = aligned_alloc(128, (sizeof(cv_driver) + 127) & ~(size_t)127);
    if (!d) return NULL;
    memset(d, 0, sizeof *d);
#if defined(__linux__)
    d->poll_fd = epoll_create1(EPOLL_CLOEXEC);
    d->wake_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (d->poll_fd < 0 || d->wake_fd < 0) goto fail;
    // data.ptr == NULL marks the eventfd.
    struct epoll_event ev = {.events = EPOLLIN | EPOLLET, .data.ptr = NULL};
    if (epoll_ctl(d->poll_fd, EPOLL_CTL_ADD, d->wake_fd, &ev) != 0) goto fail;
#else
    d->wake_fd = -1;
    d->poll_fd = kqueue();
    if (d->poll_fd < 0) goto fail;
    fcntl(d->poll_fd, F_SETFD, FD_CLOEXEC);
    // Wakes are an EVFILT_USER event, re-armed by EV_CLEAR once collected.
    struct kevent ev;
    EV_SET(&ev, 0, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
    if (kevent(d->poll_fd, &ev, 1, NULL, 0, NULL) != 0) goto fail;
    d->wake_fd = d->poll_fd;
#endif
    return d;
fail: {
    int e = errno;
    if (d->poll_fd >= 0) close(d->poll_fd);
    if (d->wake_fd >= 0 && d->wake_fd != d->poll_fd) close(d->wake_fd);
    free(d);
    errno = e;
    return NULL;
}
}

static void release_pending(cv_driver *d) {
    cv_io *io = atomic_exchange_explicit(&d->released, NULL, memory_order_acquire);
    while (io) {
        cv_io *next = io->next;
        free(io);
        io = next;
    }
}

void cv_driver_free(cv_driver *d) {
    if (!d) return;
    release_pending(d);
    if (d->wake_fd != d->poll_fd) close(d->wake_fd);
    close(d->poll_fd);
    free(d);
}

void cv_parker_attach_driver(cv_parker *p, cv_driver *d) { p->wake_fd = d->wake_fd; }

int cv_driver_try_lock(cv_driver *d) {
    return atomic_load_explicit(&d->locked, memory_order_relaxed) == 0 &&
           atomic_exchange_explicit(&d->locked, 1, memory_order_acquire) == 0;
}

void cv_driver_lock(cv_driver *d) {
    // Only contended by a busy worker's zero-timeout poll: short.
    for (uint32_t i = 1; !cv_driver_try_lock(d); i++) {
        cpu_relax();
        if ((i & 1023) == 0) sched_yield();
    }
}

void cv_driver_unlock(cv_driver *d) { atomic_store_explicit(&d->locked, 0, memory_order_release); }

int cv_driver_registered(cv_driver *d) {
    return atomic_load_explicit(&d->registered, memory_order_relaxed);
}

uintptr_t *cv_driver_wakes(cv_driver *d) { return d->wakes; }

cv_driver_stats cv_driver_get_stats(cv_driver *d) { return d->stats; }

/// An event arrived for one direction: hand back the waiter, or leave READY.
static uintptr_t io_ready(cv_io *io, int dir) {
    uintptr_t cur = __atomic_load_n(&io->slot[dir], __ATOMIC_ACQUIRE);
    for (;;) {
        if (cur == CV_IO_READY) return 0;
        // A waiter is taken (it retries the syscall); an idle slot becomes READY.
        uintptr_t next = cur == CV_IO_IDLE ? CV_IO_READY : CV_IO_IDLE;
        if (__atomic_compare_exchange_n(&io->slot[dir], &cur, next, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return cur == CV_IO_IDLE ? 0 : cur;
    }
}

static int poll_events(cv_driver *d, int64_t timeout_ns) {
#if defined(__linux__)
#ifdef SYS_epoll_pwait2
    static _Atomic int no_pwait2;
    if (!atomic_load_explicit(&no_pwait2, memory_order_relaxed)) {
        struct timespec ts, *tp = NULL;
        if (timeout_ns >= 0) {
            ts.tv_sec = (time_t)(timeout_ns / 1000000000);
            ts.tv_nsec = (long)(timeout_ns % 1000000000);
            tp = &ts;
        }
        long n = syscall(SYS_epoll_pwait2, d->poll_fd, d->events, CV_MAX_EVENTS, tp, NULL, 0);
        if (n >= 0 || errno != ENOSYS) return (int)n;
        atomic_store_explicit(&no_pwait2, 1, memory_order_relaxed);
    }
#endif
    // Milliseconds, rounded up so a timer is never polled for early.
    int ms = timeout_ns < 0 ? -1 : (int)((timeout_ns + 999999) / 1000000);
    return epoll_wait(d->poll_fd, d->events, CV_MAX_EVENTS, ms);
#else
    struct timespec ts, *tp = NULL;
    if (timeout_ns >= 0) {
        ts.tv_sec = (time_t)(timeout_ns / 1000000000);
        ts.tv_nsec = (long)(timeout_ns % 1000000000);
        tp = &ts;
    }
    return kevent(d->poll_fd, NULL, 0, d->events, CV_MAX_EVENTS, tp);
#endif
}

int cv_driver_turn(cv_driver *d, cv_parker *p, int64_t timeout_ns) {
    // Registrations released before this turn can't be in its batch; the
    // previous batch, which could name them, is done (we hold the lock).
    release_pending(d);
    if (p) {
        uint32_t expected = NOTIFIED;
        if (atomic_compare_exchange_strong(&p->state, &expected, EMPTY)) {
            timeout_ns = 0; // already notified: just collect what is ready
        } else {
            expected = EMPTY;
            if (!atomic_compare_exchange_strong(&p->state, &expected, PARKED_IO)) {
                atomic_store(&p->state, EMPTY);
                timeout_ns = 0;
            }
        }
    }
    int n = poll_events(d, timeout_ns);
    // Consumes a racing notify, as cv_park does: the caller rechecks.
    if (p) atomic_store(&p->state, EMPTY);
    if (p) d->stats.parked_turns++; else d->stats.busy_turns++;
    if (n > 0) d->stats.events += (uint64_t)n;
    if (n == CV_MAX_EVENTS) d->stats.full_batches++;
    int woken = 0;
    for (int i = 0; i < n; i++) {
        uintptr_t w;
#if defined(__linux__)
        cv_io *io = d->events[i].data.ptr;
        uint32_t e = d->events[i].events;
        if (!io) {
            uint64_t v;
            ssize_t r = read(d->wake_fd, &v, sizeof v);
            (void)r;
            continue;
        }
        // Before io_ready, whose CAS publishes it to the task it wakes.
        if (e & (EPOLLRDHUP | EPOLLHUP | EPOLLERR))
            __atomic_store_n(&io->read_closed, 1, __ATOMIC_RELEASE);
        if ((e & (EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR)) && (w = io_ready(io, CV_IO_READ)))
            d->wakes[woken++] = w;
        if ((e & (EPOLLOUT | EPOLLHUP | EPOLLERR)) && (w = io_ready(io, CV_IO_WRITE)))
            d->wakes[woken++] = w;
#else
        // One event per filter. EVFILT_USER is a wake: EV_CLEAR re-armed it.
        const struct kevent *ev = &d->events[i];
        cv_io *io = ev->udata;
        if (ev->filter == EVFILT_USER || !io) continue;
        if (ev->filter == EVFILT_READ) {
            // EV_EOF: the peer shut down its side, or the socket failed.
            // Before io_ready, whose CAS publishes it to the task it wakes.
            if (ev->flags & (EV_EOF | EV_ERROR))
                __atomic_store_n(&io->read_closed, 1, __ATOMIC_RELEASE);
            if ((w = io_ready(io, CV_IO_READ))) d->wakes[woken++] = w;
        } else if (ev->filter == EVFILT_WRITE) {
            if ((w = io_ready(io, CV_IO_WRITE))) d->wakes[woken++] = w;
        } else if (ev->filter == EVFILT_PROC) {
            // A watched child exited (cv_driver_watch_exit): its read side.
            if ((w = io_ready(io, CV_IO_READ))) d->wakes[woken++] = w;
        }
#endif
    }
    d->stats.wakes += (uint64_t)woken;
    return woken;
}

cv_io *cv_driver_register(cv_driver *d, int fd, int *err) {
    cv_io *io = calloc(1, sizeof *io);
    if (!io) {
        *err = ENOMEM;
        return NULL;
    }
    io->fd = fd;
    io->refs = 1;
#if defined(__linux__)
    struct epoll_event ev = {.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET, .data.ptr = io};
    if (epoll_ctl(d->poll_fd, EPOLL_CTL_ADD, fd, &ev) != 0) {
        *err = errno;
        free(io);
        return NULL;
    }
#else
    // Both filters in one call; EV_RECEIPT reports each one's result.
    struct kevent ch[2], out[2];
    EV_SET(&ch[0], fd, EVFILT_READ, EV_ADD | EV_CLEAR | EV_RECEIPT, 0, 0, io);
    EV_SET(&ch[1], fd, EVFILT_WRITE, EV_ADD | EV_CLEAR | EV_RECEIPT, 0, 0, io);
    int n = kevent(d->poll_fd, ch, 2, out, 2, NULL);
    int e = n < 0 ? errno : 0, added[2] = {0, 0};
    for (int i = 0; i < n; i++) {
        int k = out[i].filter == EVFILT_READ ? 0 : 1;
        if ((out[i].flags & EV_ERROR) && out[i].data != 0) {
            if (!e) e = (int)out[i].data;
        } else {
            added[k] = 1;
        }
    }
    if (e || n < 2) {
        // Take back a filter that went in, so no event names the freed io.
        for (int k = 0; k < 2; k++) {
            if (!added[k]) continue;
            struct kevent del;
            EV_SET(&del, fd, k == 0 ? EVFILT_READ : EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
            kevent(d->poll_fd, &del, 1, NULL, 0, NULL);
        }
        *err = e ? e : EIO;
        free(io);
        return NULL;
    }
#endif
    atomic_fetch_add_explicit(&d->registered, 1, memory_order_relaxed);
    return io;
}

void cv_driver_deregister(cv_driver *d, cv_io *io) {
    if (__atomic_sub_fetch(&io->refs, 1, __ATOMIC_ACQ_REL) != 0) return; // the other half has it
#if defined(__linux__)
    epoll_ctl(d->poll_fd, EPOLL_CTL_DEL, io->fd, NULL);
#endif
    close(io->fd); // kqueue drops an fd's filters when it is closed
    atomic_fetch_sub_explicit(&d->registered, 1, memory_order_relaxed);
    cv_io *head = atomic_load_explicit(&d->released, memory_order_relaxed);
    do {
        io->next = head;
    } while (!atomic_compare_exchange_weak_explicit(&d->released, &head, io,
                                                    memory_order_release, memory_order_relaxed));
}

#if !defined(__linux__)
cv_io *cv_driver_watch_exit(cv_driver *d, int pid, int *err) {
    cv_io *io = calloc(1, sizeof *io);
    if (!io) {
        *err = ENOMEM;
        return NULL;
    }
    io->fd = -1;
    io->refs = 1;
    // One-shot: the exit is the only event, and kqueue drops the filter
    // once it is collected.
    struct kevent ch, out;
    EV_SET(&ch, pid, EVFILT_PROC, EV_ADD | EV_ONESHOT | EV_RECEIPT, NOTE_EXIT, 0, io);
    int n = kevent(d->poll_fd, &ch, 1, &out, 1, NULL);
    int e = n < 0 ? errno : n < 1 ? EIO : (out.flags & EV_ERROR) ? (int)out.data : 0;
    if (e) {
        *err = e; // ESRCH: it has exited already
        free(io);
        return NULL;
    }
    atomic_fetch_add_explicit(&d->registered, 1, memory_order_relaxed);
    return io;
}

void cv_driver_unwatch_exit(cv_driver *d, cv_io *io, int pid) {
    struct kevent del;
    EV_SET(&del, pid, EVFILT_PROC, EV_DELETE, 0, 0, NULL);
    kevent(d->poll_fd, &del, 1, NULL, 0, NULL); // ENOENT once it fired
    atomic_fetch_sub_explicit(&d->registered, 1, memory_order_relaxed);
    cv_io *head = atomic_load_explicit(&d->released, memory_order_relaxed);
    do {
        io->next = head;
    } while (!atomic_compare_exchange_weak_explicit(&d->released, &head, io,
                                                    memory_order_release, memory_order_relaxed));
}
#endif

#elif defined(_WIN32)
// Readiness on Windows, as Tokio's mio does it: one I/O completion port per
// runtime, and IOCTL_AFD_POLL requests against the sockets' base handles
// through a handle to the AFD driver. A poll is one-shot: it's submitted
// when a task arms a direction after WSAEWOULDBLOCK (cv_driver_want), and
// completes on the port at once if the socket is ready already, so no edge
// is lost. Its completion resumes the waiter exactly as an epoll event does.

#include <winsock2.h>
#include <mswsock.h>
#include <timeapi.h>

typedef LONG NTSTATUS;
typedef struct {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} cv_iosb;
typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} cv_unicode_string;
typedef struct {
    ULONG Length;
    HANDLE RootDirectory;
    cv_unicode_string *ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} cv_object_attributes;
typedef struct {
    HANDLE Handle;
    ULONG Events;
    NTSTATUS Status;
} cv_afd_poll_handle;
typedef struct {
    LARGE_INTEGER Timeout;
    ULONG NumberOfHandles;
    ULONG Exclusive;
    cv_afd_poll_handle Handles[1];
} cv_afd_poll_info;

#define CV_IOCTL_AFD_POLL 0x00012024
#define CV_FILE_OPEN 0x00000001
#define CV_STATUS_PENDING ((NTSTATUS)0x00000103L)
#define CV_STATUS_CANCELLED ((NTSTATUS)0xC0000120L)
#define AFD_POLL_RECEIVE 0x0001
#define AFD_POLL_RECEIVE_EXPEDITED 0x0002
#define AFD_POLL_SEND 0x0004
#define AFD_POLL_DISCONNECT 0x0008
#define AFD_POLL_ABORT 0x0010
#define AFD_POLL_LOCAL_CLOSE 0x0020
#define AFD_POLL_ACCEPT 0x0080
#define AFD_POLL_CONNECT_FAIL 0x0100

typedef NTSTATUS(NTAPI *nt_create_file_fn)(PHANDLE, ACCESS_MASK, cv_object_attributes *, cv_iosb *,
                                           PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI *nt_device_io_control_file_fn)(HANDLE, HANDLE, PVOID, PVOID, cv_iosb *, ULONG,
                                                      PVOID, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI *nt_cancel_io_file_ex_fn)(HANDLE, cv_iosb *, cv_iosb *);

static nt_create_file_fn nt_create_file;
static nt_device_io_control_file_fn nt_device_io_control_file;
static nt_cancel_io_file_ex_fn nt_cancel_io_file_ex;

static BOOL CALLBACK load_ntdll(PINIT_ONCE once, PVOID param, PVOID *ctx) {
    (void)once, (void)param, (void)ctx;
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (!nt) return FALSE;
    nt_create_file = (nt_create_file_fn)(void *)GetProcAddress(nt, "NtCreateFile");
    nt_device_io_control_file = (nt_device_io_control_file_fn)(void *)GetProcAddress(nt, "NtDeviceIoControlFile");
    nt_cancel_io_file_ex = (nt_cancel_io_file_ex_fn)(void *)GetProcAddress(nt, "NtCancelIoFileEx");
    return nt_create_file && nt_device_io_control_file && nt_cancel_io_file_ex;
}

#define CV_MAX_EVENTS 1024

// The state word of a registration: a poll in flight per direction, and
// whether the owner let go. Whoever takes it to CLOSING with nothing in
// flight frees it.
#define POLL_READ 1u
#define POLL_WRITE 2u
#define POLL_CLOSING 4u
#define POLL_SOCKET POLL_READ // a socket's one poll is in flight

typedef struct cv_poll_op {
    cv_iosb iosb; // first: the completion's lpOverlapped points here
    cv_afd_poll_info info;
    struct cv_io_win *io;
    int dir;
} cv_poll_op;

// One direction of an overlapped pipe end: the request in flight, and the
// buffer it reads into or writes from.
typedef struct cv_pipe_op {
    OVERLAPPED ov; // first: the completion's lpOverlapped points here
    struct cv_io_win *io;
    int dir;
    uint8_t *buf;
    DWORD len; // read: the bytes the last read brought; write: those being written
    DWORD pos; // read: the bytes taken out so far
    DWORD err; // the last request's Win32 error, 0 if none
} cv_pipe_op;

#define CV_PIPE_BUFFER (64 * 1024)
#define CV_PIPE_KEY ((ULONG_PTR)2)
#define CV_EXIT_KEY ((ULONG_PTR)3)

enum { IO_SOCKET, IO_PIPE, IO_HANDLE };

typedef struct cv_io_win {
    cv_io io; // first: Swift sees a cv_io *
    cv_driver *driver;
    int kind;
    SOCKET base; // the base provider socket, which AFD polls
    // Sockets: POLL_SOCKET while the poll is in flight. Pipes: a read or
    // write in flight. Handles: the wait, until its callback has posted.
    _Atomic uint32_t state;
    // Sockets have one poll at a time, for every direction wanted: AFD
    // loses events when a socket has two (wepoll issue 35, JDK-8334574).
    // op[0] is that poll; `lock` covers it, the fields below, and every
    // change to `state` for a socket.
    SRWLOCK lock;
    uint32_t wanted;  // directions with a waiter (POLL_READ, POLL_WRITE)
    uint32_t polling; // the directions the poll in flight asks about
    int cancelling;   // that poll is being cancelled, to ask about more
    cv_poll_op op[2];
    cv_pipe_op pipe[2];
    HANDLE wait, target; // handles: the wait and our copy of what it waits for
    _Atomic int fired;
} cv_io_win;

static void io_free(cv_io *raw) {
    cv_io_win *io = (cv_io_win *)raw;
    free(io->pipe[0].buf);
    free(io->pipe[1].buf);
    free(io);
}

struct cv_driver {
    _Atomic uint32_t locked;
    char pad0[124];
    _Atomic int registered;
    _Atomic(cv_io *) released;
    char pad1[112];
    HANDLE port;
    HANDLE afd;
    cv_driver_stats stats;
    OVERLAPPED_ENTRY events[CV_MAX_EVENTS];
    uintptr_t wakes[2 * CV_MAX_EVENTS];
};

cv_driver *cv_driver_new(void) {
    static INIT_ONCE once = INIT_ONCE_STATIC_INIT;
    if (!InitOnceExecuteOnce(&once, load_ntdll, NULL, NULL)) {
        errno = ENOSYS;
        return NULL;
    }
    cv_driver *d = cv_aligned_alloc(128, (sizeof(cv_driver) + 127) & ~(size_t)127);
    if (!d) {
        errno = ENOMEM;
        return NULL;
    }
    memset(d, 0, sizeof *d);
    d->port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    if (!d->port) goto fail;
    // A handle to AFD of our own: the name after \Device\Afd is arbitrary.
    static WCHAR name[] = L"\\Device\\Afd\\Vega";
    cv_unicode_string uname = {sizeof name - sizeof(WCHAR), sizeof name, name};
    cv_object_attributes attrs = {sizeof attrs, NULL, &uname, 0, NULL, NULL};
    cv_iosb iosb;
    NTSTATUS st = nt_create_file(&d->afd, SYNCHRONIZE, &attrs, &iosb, NULL, 0,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, CV_FILE_OPEN, 0, NULL, 0);
    if (st != 0) {
        d->afd = NULL;
        goto fail;
    }
    if (!CreateIoCompletionPort(d->afd, d->port, 0, 0)) goto fail;
    SetFileCompletionNotificationModes(d->afd, FILE_SKIP_SET_EVENT_ON_HANDLE);
    // Waits time out on the system tick, 15.6 ms by default: too coarse for
    // timers. 1 ms while a runtime exists (per process since Windows 10 2004).
    timeBeginPeriod(1);
    return d;
fail:
    if (d->afd) CloseHandle(d->afd);
    if (d->port) CloseHandle(d->port);
    cv_aligned_free(d);
    errno = EIO;
    return NULL;
}

static void release_pending(cv_driver *d) {
    cv_io *io = atomic_exchange_explicit(&d->released, NULL, memory_order_acquire);
    while (io) {
        cv_io *next = io->next;
        io_free(io);
        io = next;
    }
}

void cv_driver_free(cv_driver *d) {
    if (!d) return;
    release_pending(d);
    CloseHandle(d->afd);
    CloseHandle(d->port);
    cv_aligned_free(d);
    timeEndPeriod(1);
}

void cv_parker_attach_driver(cv_parker *p, cv_driver *d) { p->wake_port = d->port; }

int cv_driver_try_lock(cv_driver *d) {
    return atomic_load_explicit(&d->locked, memory_order_relaxed) == 0 &&
           atomic_exchange_explicit(&d->locked, 1, memory_order_acquire) == 0;
}

void cv_driver_lock(cv_driver *d) {
    for (uint32_t i = 1; !cv_driver_try_lock(d); i++) {
        cpu_relax();
        if ((i & 1023) == 0) SwitchToThread();
    }
}

void cv_driver_unlock(cv_driver *d) { atomic_store_explicit(&d->locked, 0, memory_order_release); }

int cv_driver_registered(cv_driver *d) {
    return atomic_load_explicit(&d->registered, memory_order_relaxed);
}

uintptr_t *cv_driver_wakes(cv_driver *d) { return d->wakes; }

cv_driver_stats cv_driver_get_stats(cv_driver *d) { return d->stats; }

static uintptr_t io_ready(cv_io *io, int dir) {
    uintptr_t cur = __atomic_load_n(&io->slot[dir], __ATOMIC_ACQUIRE);
    for (;;) {
        if (cur == CV_IO_READY) return 0;
        uintptr_t next = cur == CV_IO_IDLE ? CV_IO_READY : CV_IO_IDLE;
        if (__atomic_compare_exchange_n(&io->slot[dir], &cur, next, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return cur == CV_IO_IDLE ? 0 : cur;
    }
}

static void push_released(cv_driver *d, cv_io *io) {
    cv_io *head = atomic_load_explicit(&d->released, memory_order_relaxed);
    do {
        io->next = head;
    } while (!atomic_compare_exchange_weak_explicit(&d->released, &head, io,
                                                    memory_order_release, memory_order_relaxed));
}

// Errors and closes complete both directions: the retried call reports them.
#define AFD_POLL_COMMON (AFD_POLL_DISCONNECT | AFD_POLL_ABORT | AFD_POLL_LOCAL_CLOSE | AFD_POLL_CONNECT_FAIL)

static ULONG poll_mask(uint32_t dirs) {
    ULONG mask = AFD_POLL_COMMON;
    if (dirs & POLL_READ) mask |= AFD_POLL_RECEIVE | AFD_POLL_ACCEPT;
    if (dirs & POLL_WRITE) mask |= AFD_POLL_SEND;
    return mask;
}

// Submit the socket's poll for every direction wanted. Under io->lock,
// with no poll in flight and the socket not closing.
static void poll_submit(cv_io_win *io) {
    cv_poll_op *op = &io->op[0];
    io->polling = io->wanted;
    io->cancelling = 0;
    atomic_fetch_or_explicit(&io->state, POLL_SOCKET, memory_order_acq_rel);
    memset(&op->iosb, 0, sizeof op->iosb);
    op->info.Timeout.QuadPart = INT64_MAX;
    op->info.NumberOfHandles = 1;
    op->info.Exclusive = FALSE;
    op->info.Handles[0].Handle = (HANDLE)io->base;
    op->info.Handles[0].Events = poll_mask(io->polling);
    op->info.Handles[0].Status = 0;
    op->iosb.Status = CV_STATUS_PENDING;
    NTSTATUS st = nt_device_io_control_file(io->driver->afd, NULL, NULL, &op->iosb, &op->iosb,
                                            CV_IOCTL_AFD_POLL, &op->info, sizeof op->info, &op->info,
                                            sizeof op->info);
    if (st != CV_STATUS_PENDING && st != 0) {
        // Not submitted, so no completion comes: post one that says "ready",
        // and the retried calls find out what's wrong.
        op->info.Handles[0].Events = poll_mask(io->polling);
        op->iosb.Status = 0;
        PostQueuedCompletionStatus(io->driver->port, 0, 0, (LPOVERLAPPED)&op->iosb);
    }
}

void cv_driver_want(cv_io *raw, int dir) {
    cv_io_win *io = (cv_io_win *)raw;
    if (io->kind != IO_SOCKET) return; // the request itself completes on the port
    uint32_t bit = dir == CV_IO_READ ? POLL_READ : POLL_WRITE;
    AcquireSRWLockExclusive(&io->lock);
    uint32_t state = atomic_load_explicit(&io->state, memory_order_acquire);
    if (!(state & POLL_CLOSING)) {
        io->wanted |= bit;
        if (!(state & POLL_SOCKET)) {
            poll_submit(io);
        } else if (!(io->polling & bit) && !io->cancelling) {
            // The poll in flight doesn't ask about this direction: cancel it,
            // and its completion submits one that asks about both.
            io->cancelling = 1;
            cv_iosb cancel;
            nt_cancel_io_file_ex(io->driver->afd, &io->op[0].iosb, &cancel);
        }
    }
    ReleaseSRWLockExclusive(&io->lock);
}

static int pipe_broken(DWORD e) {
    return e == ERROR_BROKEN_PIPE || e == ERROR_NO_DATA || e == ERROR_PIPE_NOT_CONNECTED;
}

// A pipe request finished: note the outcome, then wake the waiter, or,
// once the owner has let go, close and free when nothing else is in flight.
static uintptr_t pipe_completed(OVERLAPPED_ENTRY *e) {
    cv_pipe_op *op = (cv_pipe_op *)(void *)e->lpOverlapped;
    cv_io_win *io = op->io;
    HANDLE h = (HANDLE)(intptr_t)io->io.fd;
    DWORD bytes = 0;
    op->err = GetOverlappedResult(h, &op->ov, &bytes, FALSE) ? 0 : GetLastError();
    if (op->dir == CV_IO_READ) {
        op->len = op->err ? 0 : bytes;
        op->pos = 0;
    }
    uint32_t bit = op->dir == CV_IO_READ ? POLL_READ : POLL_WRITE;
    uint32_t old = atomic_fetch_and_explicit(&io->state, ~bit, memory_order_acq_rel);
    if (old & POLL_CLOSING) {
        if ((old & ~bit) == POLL_CLOSING) {
            CloseHandle(h);
            io_free(&io->io);
        }
        return 0;
    }
    return io_ready(&io->io, op->dir);
}

intptr_t cv_pipe_read_io(cv_io *raw, void *buf, intptr_t len) {
    cv_io_win *io = (cv_io_win *)raw;
    cv_pipe_op *op = &io->pipe[CV_IO_READ];
    if (atomic_load_explicit(&io->state, memory_order_acquire) & POLL_READ) return -EAGAIN;
    if (op->pos < op->len) {
        DWORD n = op->len - op->pos;
        if ((intptr_t)n > len) n = (DWORD)len;
        memcpy(buf, op->buf + op->pos, n);
        op->pos += n;
        return (intptr_t)n;
    }
    if (op->err) {
        if (pipe_broken(op->err) || op->err == ERROR_HANDLE_EOF) return 0; // for good
        int e = cv_win_errno(op->err);
        op->err = 0;
        return -(intptr_t)e;
    }
    if (len <= 0) return 0;
    if (!op->buf && !(op->buf = malloc(CV_PIPE_BUFFER))) return -ENOMEM;
    op->pos = op->len = 0;
    memset(&op->ov, 0, sizeof op->ov);
    atomic_fetch_or_explicit(&io->state, POLL_READ, memory_order_acq_rel);
    if (!ReadFile((HANDLE)(intptr_t)raw->fd, op->buf, CV_PIPE_BUFFER, NULL, &op->ov)) {
        DWORD e = GetLastError();
        if (e != ERROR_IO_PENDING) { // no completion comes
            atomic_fetch_and_explicit(&io->state, ~POLL_READ, memory_order_acq_rel);
            if (pipe_broken(e) || e == ERROR_HANDLE_EOF) {
                op->err = e;
                return 0;
            }
            return -(intptr_t)cv_win_errno(e);
        }
    }
    return -EAGAIN; // even if it finished already: its completion still comes
}

intptr_t cv_pipe_write_io(cv_io *raw, const void *buf, intptr_t len) {
    cv_io_win *io = (cv_io_win *)raw;
    cv_pipe_op *op = &io->pipe[CV_IO_WRITE];
    if (atomic_load_explicit(&io->state, memory_order_acquire) & POLL_WRITE) return -EAGAIN;
    if (op->err) {
        DWORD e = op->err;
        if (pipe_broken(e)) return -EPIPE; // for good
        op->err = 0;
        return -(intptr_t)cv_win_errno(e);
    }
    if (len <= 0) return 0;
    if (!op->buf && !(op->buf = malloc(CV_PIPE_BUFFER))) return -ENOMEM;
    DWORD n = len > CV_PIPE_BUFFER ? CV_PIPE_BUFFER : (DWORD)len;
    memcpy(op->buf, buf, n);
    op->len = n;
    memset(&op->ov, 0, sizeof op->ov);
    atomic_fetch_or_explicit(&io->state, POLL_WRITE, memory_order_acq_rel);
    if (!WriteFile((HANDLE)(intptr_t)raw->fd, op->buf, n, NULL, &op->ov)) {
        DWORD e = GetLastError();
        if (e != ERROR_IO_PENDING) {
            atomic_fetch_and_explicit(&io->state, ~POLL_WRITE, memory_order_acq_rel);
            if (pipe_broken(e)) {
                op->err = e;
                return -EPIPE;
            }
            return -(intptr_t)cv_win_errno(e);
        }
    }
    return (intptr_t)n;
}

// A watched handle was signalled: the thread pool's callback posted this.
static uintptr_t handle_signalled(OVERLAPPED_ENTRY *e) {
    cv_io_win *io = (cv_io_win *)(void *)e->lpOverlapped;
    uint32_t old = atomic_fetch_and_explicit(&io->state, ~POLL_READ, memory_order_acq_rel);
    if (old & POLL_CLOSING) {
        io_free(&io->io);
        return 0;
    }
    __atomic_store_n(&io->io.read_closed, 1, __ATOMIC_RELEASE);
    return io_ready(&io->io, CV_IO_READ);
}

static VOID CALLBACK handle_callback(PVOID ctx, BOOLEAN timed_out) {
    (void)timed_out;
    cv_io_win *io = ctx;
    atomic_store_explicit(&io->fired, 1, memory_order_release);
    PostQueuedCompletionStatus(io->driver->port, 0, CV_EXIT_KEY, (LPOVERLAPPED)(void *)io);
}

cv_io *cv_driver_watch_handle(cv_driver *d, intptr_t handle, int *err) {
    cv_io_win *io = calloc(1, sizeof *io);
    if (!io) {
        *err = ENOMEM;
        return NULL;
    }
    io->io.fd = -1;
    io->io.refs = 1;
    io->driver = d;
    io->kind = IO_HANDLE;
    atomic_store_explicit(&io->state, POLL_READ, memory_order_relaxed); // the wait
    if (!DuplicateHandle(GetCurrentProcess(), (HANDLE)handle, GetCurrentProcess(), &io->target, SYNCHRONIZE,
                         FALSE, 0)) {
        *err = cv_win_errno(GetLastError());
        free(io);
        return NULL;
    }
    if (!RegisterWaitForSingleObject(&io->wait, io->target, handle_callback, io, INFINITE,
                                     WT_EXECUTEONLYONCE)) {
        *err = cv_win_errno(GetLastError());
        CloseHandle(io->target);
        free(io);
        return NULL;
    }
    atomic_fetch_add_explicit(&d->registered, 1, memory_order_relaxed);
    return &io->io;
}

void cv_driver_unwatch_handle(cv_driver *d, cv_io *raw) {
    cv_io_win *io = (cv_io_win *)raw;
    // Once this returns the callback has run, or never will.
    UnregisterWaitEx(io->wait, INVALID_HANDLE_VALUE);
    CloseHandle(io->target);
    atomic_fetch_sub_explicit(&d->registered, 1, memory_order_relaxed);
    if (!atomic_load_explicit(&io->fired, memory_order_acquire)) {
        push_released(d, raw); // nothing was posted
        return;
    }
    uint32_t old = atomic_fetch_or_explicit(&io->state, POLL_CLOSING, memory_order_acq_rel);
    // Posted but not yet taken: its completion frees it.
    if ((old & POLL_READ) == 0) push_released(d, raw);
}

int cv_driver_turn(cv_driver *d, cv_parker *p, int64_t timeout_ns) {
    release_pending(d);
    if (p) {
        uint32_t expected = NOTIFIED;
        if (atomic_compare_exchange_strong(&p->state, &expected, EMPTY)) {
            timeout_ns = 0;
        } else {
            expected = EMPTY;
            if (!atomic_compare_exchange_strong(&p->state, &expected, PARKED_IO)) {
                atomic_store(&p->state, EMPTY);
                timeout_ns = 0;
            }
        }
    }
    DWORD ms = timeout_ns < 0 ? INFINITE : (DWORD)((timeout_ns + 999999) / 1000000);
    ULONG n = 0;
    if (!GetQueuedCompletionStatusEx(d->port, d->events, CV_MAX_EVENTS, &n, ms, FALSE)) n = 0;
    if (p) atomic_store(&p->state, EMPTY);
    if (p) d->stats.parked_turns++; else d->stats.busy_turns++;
    d->stats.events += n;
    if (n == CV_MAX_EVENTS) d->stats.full_batches++;
    int woken = 0;
    for (ULONG i = 0; i < n; i++) {
        OVERLAPPED_ENTRY *e = &d->events[i];
        if (e->lpCompletionKey == CV_WAKE_KEY || !e->lpOverlapped) continue; // a wake
        if (e->lpCompletionKey == CV_PIPE_KEY || e->lpCompletionKey == CV_EXIT_KEY) {
            uintptr_t w = e->lpCompletionKey == CV_PIPE_KEY ? pipe_completed(e) : handle_signalled(e);
            if (w) d->wakes[woken++] = w;
            continue;
        }
        cv_poll_op *op = (cv_poll_op *)(void *)e->lpOverlapped;
        cv_io_win *io = op->io;
        NTSTATUS status = op->iosb.Status;
        ULONG events = status == 0 && op->info.NumberOfHandles > 0 ? op->info.Handles[0].Events : 0;
        AcquireSRWLockExclusive(&io->lock);
        // Out of flight before waking anyone: a task arming after this
        // submits a new poll rather than waiting on this finished one.
        uint32_t old = atomic_fetch_and_explicit(&io->state, ~POLL_SOCKET, memory_order_acq_rel);
        if (old & POLL_CLOSING) {
            ReleaseSRWLockExclusive(&io->lock);
            if ((old & ~POLL_SOCKET) == POLL_CLOSING) io_free(&io->io); // the last thing holding it
            continue;
        }
        uint32_t ready;
        if (status == CV_STATUS_CANCELLED) {
            ready = 0; // cancelled to ask about more directions
        } else if (status != 0) {
            ready = io->polling; // failed: its waiters retry, and see why
        } else {
            ready = 0;
            if (events & (AFD_POLL_RECEIVE | AFD_POLL_ACCEPT | AFD_POLL_COMMON)) ready |= POLL_READ;
            if (events & (AFD_POLL_SEND | AFD_POLL_COMMON)) ready |= POLL_WRITE;
            ready &= io->polling;
        }
        if (events & AFD_POLL_COMMON) __atomic_store_n(&io->io.read_closed, 1, __ATOMIC_RELEASE);
        io->wanted &= ~ready;
        // Directions still waited on get a new poll.
        if (io->wanted) poll_submit(io);
        ReleaseSRWLockExclusive(&io->lock);
        for (int dir = 0; dir < 2; dir++) {
            if (!(ready & (dir == CV_IO_READ ? POLL_READ : POLL_WRITE))) continue;
            uintptr_t w = io_ready(&io->io, dir);
            if (w) d->wakes[woken++] = w;
        }
    }
    d->stats.wakes += (uint64_t)woken;
    return woken;
}

cv_io *cv_driver_register(cv_driver *d, int fd, int *err) {
    cv_io_win *io = calloc(1, sizeof *io);
    if (!io) {
        *err = ENOMEM;
        return NULL;
    }
    // Layered providers can wrap the socket; AFD wants the one underneath.
    SOCKET base = INVALID_SOCKET;
    DWORD bytes = 0;
    if (WSAIoctl((SOCKET)fd, SIO_BASE_HANDLE, NULL, 0, &base, sizeof base, &bytes, NULL, NULL) != 0) {
        // (Without Winsock started, it can't be a socket of ours.)
        int e = WSAGetLastError();
        if (e == WSAENOTSOCK || e == WSANOTINITIALISED) {
            // An overlapped pipe end: its requests complete on the port.
            if (!CreateIoCompletionPort((HANDLE)(intptr_t)fd, d->port, CV_PIPE_KEY, 0)) {
                *err = cv_win_errno(GetLastError());
                free(io);
                return NULL;
            }
            io->kind = IO_PIPE;
        }
        base = (SOCKET)fd;
    }
    io->io.fd = fd;
    io->io.refs = 1;
    io->driver = d;
    io->base = base;
    InitializeSRWLock(&io->lock);
    for (int dir = 0; dir < 2; dir++) {
        io->op[dir].io = io;
        io->op[dir].dir = dir;
        io->pipe[dir].io = io;
        io->pipe[dir].dir = dir;
    }
    atomic_fetch_add_explicit(&d->registered, 1, memory_order_relaxed);
    return &io->io;
}

void cv_driver_deregister(cv_driver *d, cv_io *raw) {
    if (__atomic_sub_fetch(&raw->refs, 1, __ATOMIC_ACQ_REL) != 0) return;
    cv_io_win *io = (cv_io_win *)raw;
    if (io->kind == IO_SOCKET) {
        // Under the lock, so no completion submits a new poll after this.
        AcquireSRWLockExclusive(&io->lock);
        uint32_t old = atomic_fetch_or_explicit(&io->state, POLL_CLOSING, memory_order_acq_rel);
        if (old & POLL_SOCKET) {
            cv_iosb cancel;
            nt_cancel_io_file_ex(d->afd, &io->op[0].iosb, &cancel);
        }
        ReleaseSRWLockExclusive(&io->lock);
        atomic_fetch_sub_explicit(&d->registered, 1, memory_order_relaxed);
        closesocket((SOCKET)raw->fd);
        // Nothing in flight: no completion will free it, so the next turn does
        // (one may be handling this io's last completion right now).
        if (!(old & POLL_SOCKET)) push_released(d, raw);
        return;
    }
    uint32_t old = atomic_fetch_or_explicit(&io->state, POLL_CLOSING, memory_order_acq_rel);
    atomic_fetch_sub_explicit(&d->registered, 1, memory_order_relaxed);
    if (io->kind == IO_PIPE) {
        // A read is cancelled; a write finishes first (its bytes were taken),
        // and the last completion closes the handle.
        if (old & POLL_READ) CancelIoEx((HANDLE)(intptr_t)raw->fd, &io->pipe[CV_IO_READ].ov);
        if ((old & (POLL_READ | POLL_WRITE)) == 0) {
            CloseHandle((HANDLE)(intptr_t)raw->fd);
            push_released(d, raw);
        }
        return;
    }
    closesocket((SOCKET)raw->fd);
    // Nothing in flight: no completion will free it, so the next turn does
    // (one may be handling this io's last completion right now).
    if ((old & (POLL_READ | POLL_WRITE)) == 0) push_released(d, raw);
}

#else // no driver on this platform yet

cv_driver *cv_driver_new(void) {
    errno = ENOSYS;
    return NULL;
}
void cv_driver_free(cv_driver *d) { (void)d; }

#endif

#if !defined(_WIN32) // sockets, pipes, processes, the supervisor: POSIX
// ---- sockets -------------------------------------------------------------

static int set_nonblocking_cloexec(int fd) {
    int fl = fcntl(fd, F_GETFL);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) return -1;
    return fcntl(fd, F_SETFD, FD_CLOEXEC);
}

#if !defined(__linux__) // Linux sets all of this when it creates the fd
/// Non-blocking, close-on-exec, and (where there is no MSG_NOSIGNAL) no
/// SIGPIPE on a write to a closed peer. 0, or -1 with errno.
static int prepare_fd(int fd) {
    if (set_nonblocking_cloexec(fd) != 0) return -1;
#ifdef SO_NOSIGPIPE
    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one) != 0) return -1;
#endif
    return 0;
}
#endif

static int new_socket(int family, int type) {
#if defined(__linux__)
    return socket(family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
#else
    int fd = socket(family, type, 0);
    if (fd >= 0 && prepare_fd(fd) != 0) {
        int e = errno;
        close(fd);
        errno = e;
        return -1;
    }
    return fd;
#endif
}

static struct addrinfo *resolve(const char *host, int port, int passive, int type, int *err) {
    char service[8];
    snprintf(service, sizeof service, "%d", port);
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = type;
    hints.ai_flags = AI_NUMERICSERV | (passive ? AI_PASSIVE : 0);
    int rc = getaddrinfo(host && *host ? host : NULL, service, &hints, &res);
    if (rc != 0) {
        *err = rc == EAI_SYSTEM ? errno : EADDRNOTAVAIL;
        return NULL;
    }
    return res;
}

int cv_tcp_listen(const char *host, int port, int backlog, int reuse_port, int *err) {
    struct addrinfo *res = resolve(host, port, 1, SOCK_STREAM, err);
    if (!res) return -1;
    int fd = -1;
    *err = EADDRNOTAVAIL;
    for (struct addrinfo *a = res; a; a = a->ai_next) {
        fd = new_socket(a->ai_family, SOCK_STREAM);
        if (fd < 0) {
            *err = errno;
            continue;
        }
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
#ifdef SO_REUSEPORT
        if (reuse_port) setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
#endif
        if (bind(fd, a->ai_addr, a->ai_addrlen) == 0 && (backlog < 0 || listen(fd, backlog) == 0)) {
            *err = 0;
            break;
        }
        *err = errno;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

int cv_connect_new(const cv_sockaddr *addr, int type, int *err) {
    const struct sockaddr *sa = (const struct sockaddr *)addr->storage;
    int fd = new_socket(sa->sa_family, type);
    if (fd < 0) {
        *err = errno;
        return -1;
    }
    if (type == SOCK_STREAM && sa->sa_family != AF_UNIX) {
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    }
    if (connect(fd, sa, (socklen_t)addr->len) == 0) {
        *err = 0;
        return fd;
    }
    if (errno == EINPROGRESS) {
        *err = EINPROGRESS;
        return fd;
    }
    *err = errno;
    close(fd);
    return -1;
}

static int accept_nb(int fd, int *err) {
#if defined(__linux__)
    int c = accept4(fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
#else
    int c = accept(fd, NULL, NULL);
    if (c >= 0 && prepare_fd(c) != 0) {
        int e = errno;
        close(c);
        errno = e;
        c = -1;
    }
#endif
    if (c < 0) *err = errno;
    return c;
}

int cv_tcp_accept(int fd, int *err) {
    int c = accept_nb(fd, err);
    if (c < 0) return -1;
    int one = 1;
    setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    return c;
}

int cv_socket_error(int fd) {
    int e = 0;
    socklen_t len = sizeof e;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &e, &len) != 0) return errno;
    return e;
}

_Static_assert(sizeof(((cv_sockaddr *)0)->storage) >= sizeof(struct sockaddr_storage),
               "cv_sockaddr too small");

int cv_resolve_all(const char *host, int port, int numeric_only, cv_sockaddr *out, int max,
                   int *count) {
    char service[8];
    snprintf(service, sizeof service, "%d", port);
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM; // one entry per address, not per protocol
    hints.ai_flags = AI_NUMERICSERV | (numeric_only ? AI_NUMERICHOST : 0);
    *count = 0;
    int rc = getaddrinfo(host && *host ? host : NULL, service, &hints, &res);
    if (rc != 0) {
        if (numeric_only && rc == EAI_NONAME) return -1;
        return rc == EAI_SYSTEM ? errno : EADDRNOTAVAIL;
    }
    for (struct addrinfo *a = res; a && *count < max; a = a->ai_next) {
        if (a->ai_addrlen > sizeof out->storage) continue;
        memcpy(out[*count].storage, a->ai_addr, a->ai_addrlen);
        out[*count].len = (uint32_t)a->ai_addrlen;
        ++*count;
    }
    freeaddrinfo(res);
    return *count > 0 ? 0 : EADDRNOTAVAIL;
}

int cv_sockaddr_family(const cv_sockaddr *a) {
    return ((const struct sockaddr *)a->storage)->sa_family;
}

int cv_sockaddr_ip(cv_sockaddr *out, const uint8_t *ip, int len, int port) {
    memset(out, 0, sizeof *out);
    if (len == 4) {
        struct sockaddr_in *sa = (struct sockaddr_in *)out->storage;
        sa->sin_family = AF_INET;
        sa->sin_port = htons((uint16_t)port);
        memcpy(&sa->sin_addr, ip, 4);
        out->len = sizeof *sa;
#if defined(__APPLE__)
        sa->sin_len = sizeof *sa;
#endif
        return 0;
    }
    if (len == 16) {
        struct sockaddr_in6 *sa = (struct sockaddr_in6 *)out->storage;
        sa->sin6_family = AF_INET6;
        sa->sin6_port = htons((uint16_t)port);
        memcpy(&sa->sin6_addr, ip, 16);
        out->len = sizeof *sa;
#if defined(__APPLE__)
        sa->sin6_len = sizeof *sa;
#endif
        return 0;
    }
    return -1;
}

int cv_sockaddr_ip_bytes(const cv_sockaddr *a, uint8_t *ip) {
    const struct sockaddr *sa = (const struct sockaddr *)a->storage;
    if (sa->sa_family == AF_INET) {
        memcpy(ip, &((const struct sockaddr_in *)sa)->sin_addr, 4);
        return 4;
    }
    if (sa->sa_family == AF_INET6) {
        memcpy(ip, &((const struct sockaddr_in6 *)sa)->sin6_addr, 16);
        return 16;
    }
    return -1;
}

void cv_random_bytes(void *buf, intptr_t n) {
#if defined(__linux__)
    uint8_t *p = buf;
    while (n > 0) {
        ssize_t got = getrandom(p, (size_t)n, 0);
        if (got < 0) {
            if (errno == EINTR) continue;
            abort();  // no entropy source at all: nothing safe to fall back on
        }
        p += got;
        n -= got;
    }
#else
    arc4random_buf(buf, (size_t)n);
#endif
}

intptr_t cv_read_small_file(const char *path, void *buf, intptr_t max) {
    // O_NONBLOCK so opening a fifo doesn't wait for a writer; fstat then
    // refuses it.
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return -1;
    struct stat st;
    long total = 0;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) goto fail;
    for (;;) {
        if (total == max) {
            char probe;
            if (read(fd, &probe, 1) != 0) goto fail;  // longer than max
            break;
        }
        ssize_t n = read(fd, (char *)buf + total, (size_t)(max - total));
        if (n < 0) {
            if (errno == EINTR) continue;
            goto fail;
        }
        if (n == 0) break;
        total += n;
    }
    close(fd);
    return total;
fail:
    close(fd);
    return -1;
}

long long cv_copy_fd(int in, int out) {
    long long total = 0;
#if defined(__linux__)
    // In the kernel where the file systems allow (reflinks on btrfs/XFS,
    // server-side copies on NFS); a plain loop where they don't.
    for (;;) {
        ssize_t n = copy_file_range(in, NULL, out, NULL, 1 << 30, 0);
        if (n > 0) {
            total += n;
            continue;
        }
        if (n == 0) return total;
        if (errno == EINTR) continue;
        if (total > 0 || (errno != EXDEV && errno != ENOSYS && errno != EINVAL && errno != EOPNOTSUPP &&
                          errno != EPERM && errno != EBADF))
            return -errno;
        break;
    }
#endif
    enum { CHUNK = 128 * 1024 };
    char *buf = malloc(CHUNK);
    if (!buf) return -ENOMEM;
    for (;;) {
        ssize_t n = read(in, buf, CHUNK);
        if (n < 0) {
            if (errno == EINTR) continue;
            total = -errno;
            break;
        }
        if (n == 0) break;
        for (ssize_t done = 0; done < n;) {
            ssize_t w = write(out, buf + done, (size_t)(n - done));
            if (w < 0) {
                if (errno == EINTR) continue;
                free(buf);
                return -errno;
            }
            done += w;
        }
        total += n;
    }
    free(buf);
    return total;
}

// MARK: - Pipes and processes

int cv_pipe(int fds[2]) {
#if defined(__linux__)
    if (pipe2(fds, O_CLOEXEC) != 0) return errno;
#else
    if (pipe(fds) != 0) return errno;
    for (int i = 0; i < 2; i++) {
        if (fcntl(fds[i], F_SETFD, FD_CLOEXEC) != 0) {
            int e = errno;
            close(fds[0]);
            close(fds[1]);
            return e;
        }
    }
#endif
    return 0;
}

int cv_pipe_prepare(int fd) {
    int fl = fcntl(fd, F_GETFL);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) != 0) return errno;
    int fdfl = fcntl(fd, F_GETFD);
    if (fdfl < 0 || fcntl(fd, F_SETFD, fdfl | FD_CLOEXEC) != 0) return errno;
#ifdef F_SETNOSIGPIPE
    (void)fcntl(fd, F_SETNOSIGPIPE, 1); // a pipe end; harmless to fail on others
#endif
    return 0;
}

intptr_t cv_fd_read(int fd, void *buf, intptr_t len) {
    ssize_t n = read(fd, buf, (size_t)len);
    return n >= 0 ? (long)n : -(long)errno;
}

intptr_t cv_pipe_write(int fd, const void *buf, intptr_t len) {
#if defined(F_SETNOSIGPIPE)
    ssize_t n = write(fd, buf, (size_t)len);
    return n >= 0 ? (long)n : -(long)errno;
#else
    // No per-fd switch: block SIGPIPE on this thread for the write, and
    // swallow the one a closed reader raises (it is thread-directed).
    sigset_t pipe_set, old, pending;
    sigemptyset(&pipe_set);
    sigaddset(&pipe_set, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &pipe_set, &old);
    int was_pending = sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE);
    ssize_t n = write(fd, buf, (size_t)len);
    int err = errno;
    if (n < 0 && err == EPIPE && !was_pending) {
        struct timespec zero = {0, 0};
        while (sigtimedwait(&pipe_set, NULL, &zero) < 0 && errno == EINTR) {}
    }
    if (!sigismember(&old, SIGPIPE)) pthread_sigmask(SIG_SETMASK, &old, NULL);
    return n >= 0 ? (long)n : -(long)err;
#endif
}

int cv_spawn(const char *path, char *const argv[], char *const envp[], const char *cwd,
             const int stdio[3], int pgroup, int *pid) {
#ifdef CV_NO_SPAWN
    return ENOTSUP;
#else
    posix_spawn_file_actions_t fa;
    posix_spawnattr_t attr;
    int rc = posix_spawn_file_actions_init(&fa);
    if (rc != 0) return rc;
    rc = posix_spawnattr_init(&attr);
    if (rc != 0) {
        posix_spawn_file_actions_destroy(&fa);
        return rc;
    }
    for (int i = 0; i < 3 && rc == 0; i++) {
        if (stdio[i] == CV_STDIO_NULL)
            rc = posix_spawn_file_actions_addopen(&fa, i, "/dev/null", i == 0 ? O_RDONLY : O_WRONLY, 0);
        else if (stdio[i] >= 0)
            rc = posix_spawn_file_actions_adddup2(&fa, stdio[i], i);
    }
    if (rc == 0 && cwd) rc = posix_spawn_file_actions_addchdir_np(&fa, cwd);
    // The child starts with no signals blocked (a worker thread may block
    // some) and SIGPIPE at its default.
    sigset_t none, def;
    sigemptyset(&none);
    sigemptyset(&def);
    sigaddset(&def, SIGPIPE);
    short flags = POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF;
    if (rc == 0) rc = posix_spawnattr_setsigmask(&attr, &none);
    if (rc == 0) rc = posix_spawnattr_setsigdefault(&attr, &def);
    if (rc == 0 && pgroup >= 0) {
        flags |= POSIX_SPAWN_SETPGROUP;
        rc = posix_spawnattr_setpgroup(&attr, pgroup);
    }
    if (rc == 0) rc = posix_spawnattr_setflags(&attr, flags);
    if (rc == 0) {
        pid_t child = 0;
        rc = posix_spawn(&child, path, &fa, &attr, argv, envp);
        if (rc == 0) *pid = child;
    }
    posix_spawnattr_destroy(&attr);
    posix_spawn_file_actions_destroy(&fa);
    return rc;
#endif
}

char **cv_environ(void) {
#if defined(__APPLE__)
    extern char ***_NSGetEnviron(void);
    return *_NSGetEnviron();
#else
    extern char **environ;
    return environ;
#endif
}

int cv_pidfd_open(int pid) {
#if defined(__linux__) && defined(SYS_pidfd_open)
    long fd = syscall(SYS_pidfd_open, pid, 0);
    return fd >= 0 ? (int)fd : -errno;
#else
    (void)pid;
    return -ENOSYS;
#endif
}

int cv_pidfd_signal(int pidfd, int sig) {
#if defined(__linux__) && defined(SYS_pidfd_send_signal)
    return syscall(SYS_pidfd_send_signal, pidfd, sig, NULL, 0) == 0 ? 0 : errno;
#else
    (void)pidfd;
    (void)sig;
    return ENOSYS;
#endif
}

int cv_waitpid(int pid, int nohang, int *status) {
    for (;;) {
        int r = waitpid(pid, status, nohang ? WNOHANG : 0);
        if (r > 0) return 1;
        if (r == 0) return 0;
        if (errno != EINTR) return -errno;
    }
}

// MARK: - Shard supervisor
//
// The supervisor is single-threaded and takes its signals synchronously:
// blocked and collected with sigtimedwait on Linux; ignored and reported
// by a kqueue's EVFILT_SIGNAL on Darwin (which has no sigtimedwait).

static sigset_t sup_old_mask;
static int sup_ready;
#if defined(__APPLE__)
static int sup_kq = -1;
#endif

static void sup_set(sigset_t *set) {
    sigemptyset(set);
    sigaddset(set, SIGCHLD);
    sigaddset(set, SIGTERM);
    sigaddset(set, SIGINT);
    sigaddset(set, SIGQUIT);
    sigaddset(set, SIGHUP);
}

int cv_supervisor_init(void) {
    if (sup_ready) return 0;
    sigset_t set;
    sup_set(&set);
#if defined(__APPLE__)
    sup_kq = kqueue();
    if (sup_kq < 0) return errno;
    struct kevent ev[5];
    int sigs[5] = {SIGCHLD, SIGTERM, SIGINT, SIGQUIT, SIGHUP};
    for (int i = 0; i < 5; i++) EV_SET(&ev[i], sigs[i], EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
    if (kevent(sup_kq, ev, 5, NULL, 0, NULL) < 0) return errno;
    // Ignored, not blocked: kqueue still records them. SIGCHLD stays at its
    // default (ignoring it would reap children for us).
    signal(SIGTERM, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    sigemptyset(&set);
#endif
    int rc = pthread_sigmask(SIG_BLOCK, &set, &sup_old_mask);
    if (rc != 0) return rc;
    sup_ready = 1;
    return 0;
}

#if defined(__APPLE__)
static void *sup_parent_watch(void *raw) {
    int kq = (int)(intptr_t)raw;
    struct kevent ev;
    while (kevent(kq, NULL, 0, &ev, 1, NULL) < 0 && errno == EINTR) {}
    kill(getpid(), SIGTERM);
    return NULL;
}

static int sup_watch_parent(pid_t parent) {
    int kq = kqueue(); // the supervisor's kqueue isn't inherited across fork
    if (kq < 0) return errno;
    struct kevent ev;
    EV_SET(&ev, parent, EVFILT_PROC, EV_ADD | EV_ONESHOT, NOTE_EXIT, 0, NULL);
    if (kevent(kq, &ev, 1, NULL, 0, NULL) < 0) { // ESRCH: gone already
        int e = errno;
        close(kq);
        return e;
    }
    fcntl(kq, F_SETFD, FD_CLOEXEC);
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&attr, 64 * 1024);
    pthread_t t;
    int rc = pthread_create(&t, &attr, sup_parent_watch, (void *)(intptr_t)kq);
    pthread_attr_destroy(&attr);
    return rc;
}
#endif

int cv_supervisor_fork(void) {
#ifdef CV_NO_SPAWN
    return -ENOTSUP;
#else
    pid_t parent = getpid();
    pid_t pid = fork();
    if (pid < 0) return -errno;
    if (pid > 0) return pid;
    // The shard: default dispositions, the mask from before the supervisor.
    signal(SIGTERM, SIG_DFL);
    signal(SIGINT, SIG_DFL);
    signal(SIGQUIT, SIG_DFL);
    signal(SIGHUP, SIG_DFL);
    pthread_sigmask(SIG_SETMASK, &sup_old_mask, NULL);
#if defined(__linux__)
    // Go when the supervisor does (it may have died before we got here).
    prctl(PR_SET_PDEATHSIG, SIGTERM);
    if (getppid() != parent) _exit(1);
#else
    // No PR_SET_PDEATHSIG: a small thread waits for the supervisor's exit
    // (EVFILT_PROC) and sends us SIGTERM, as Linux would.
    if (sup_watch_parent(parent) != 0 || getppid() != parent) _exit(1);
#endif
    return 0;
#endif
}

int cv_shard_spawn(const char *path, char *const argv[], char *const envp[],
                   const int *fds, const int *targets, int count, int *pid) {
#ifdef CV_NO_SPAWN
    return ENOTSUP;
#else
    posix_spawn_file_actions_t fa;
    posix_spawnattr_t attr;
    int rc = posix_spawn_file_actions_init(&fa);
    if (rc != 0) return rc;
    rc = posix_spawnattr_init(&attr);
    if (rc != 0) {
        posix_spawn_file_actions_destroy(&fa);
        return rc;
    }
    // Listeners at the numbers named in the environment. dup2 leaves the
    // copy without FD_CLOEXEC, so it survives the exec.
    for (int i = 0; i < count && rc == 0; i++) rc = posix_spawn_file_actions_adddup2(&fa, fds[i], targets[i]);
    // The mask from before the supervisor blocked its signals (Linux), and
    // the dispositions it set to SIG_IGN (Darwin) back at their defaults:
    // both would survive the exec.
    sigset_t def;
    sup_set(&def);
    short flags = POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF;
#if defined(__APPLE__)
    flags |= POSIX_SPAWN_CLOEXEC_DEFAULT; // stdio and the listeners only
    for (int i = 0; i < 3 && rc == 0; i++) rc = posix_spawn_file_actions_addinherit_np(&fa, i);
#endif
    if (rc == 0) rc = posix_spawnattr_setsigmask(&attr, &sup_old_mask);
    if (rc == 0) rc = posix_spawnattr_setsigdefault(&attr, &def);
    if (rc == 0) rc = posix_spawnattr_setflags(&attr, flags);
    if (rc == 0) {
        pid_t child = 0;
        rc = posix_spawn(&child, path, &fa, &attr, argv, envp);
        if (rc == 0) *pid = child;
    }
    posix_spawnattr_destroy(&attr);
    posix_spawn_file_actions_destroy(&fa);
    return rc;
#endif
}

void cv_supervisor_restarted(void) {
    // The supervisor's signals were blocked by the image before; the mask
    // shards start with is the one from before that.
    sigdelset(&sup_old_mask, SIGCHLD);
    sigdelset(&sup_old_mask, SIGTERM);
    sigdelset(&sup_old_mask, SIGINT);
    sigdelset(&sup_old_mask, SIGQUIT);
    sigdelset(&sup_old_mask, SIGHUP);
}

int cv_supervisor_exec(const char *path, char *const argv[]) {
#ifdef CV_NO_SPAWN
    return ENOTSUP;
#else
    // The signals stay blocked (Linux) or ignored (Darwin) across the exec:
    // one that arrives in between waits for the new image.
    execv(path, argv);
    return errno;
#endif
}

int cv_shard_adopt(int parent) {
#if defined(__linux__)
    // PR_SET_PDEATHSIG doesn't carry over from the supervisor: set it here.
    prctl(PR_SET_PDEATHSIG, SIGTERM);
#else
    if (sup_watch_parent(parent) != 0) return -1;
#endif
    return getppid() == parent ? 0 : -1;
}

int cv_shared_memory(intptr_t size, int *err) {
#if defined(__linux__)
    int fd = (int)syscall(SYS_memfd_create, "vega-shared", 1 /* MFD_CLOEXEC */);
#else
    char name[64];
    static _Atomic int serial;
    int fd = -1;
    for (int tries = 0; tries < 16 && fd < 0; tries++) {
        snprintf(name, sizeof name, "/vega-%d-%d", (int)getpid(), atomic_fetch_add(&serial, 1));
        fd = shm_open(name, O_RDWR | O_CREAT | O_EXCL, 0600);
        if (fd >= 0) shm_unlink(name);
        else if (errno != EEXIST) break;
    }
    if (fd >= 0) fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif
    if (fd < 0) {
        *err = errno;
        return -1;
    }
    if (ftruncate(fd, (off_t)size) != 0) {
        *err = errno;
        close(fd);
        return -1;
    }
    return fd;
}

int cv_self_exe(char *buf, int len) {
#if defined(__APPLE__)
    uint32_t size = (uint32_t)len;
    if (_NSGetExecutablePath(buf, &size) != 0) return ENAMETOOLONG;
    return 0;
#else
    ssize_t n = readlink("/proc/self/exe", buf, (size_t)len - 1);
    if (n < 0) return errno;
    buf[n] = 0;
    return 0;
#endif
}

int cv_supervisor_next(int64_t timeout_ns, int *pid, int *status) {
    for (;;) {
        int st = 0;
        pid_t p = waitpid(-1, &st, WNOHANG);
        if (p > 0) {
            *pid = p;
            *status = st;
            return 1;
        }
#if defined(__linux__)
        sigset_t set;
        sup_set(&set);
        struct timespec ts, *tsp = NULL;
        if (timeout_ns >= 0) {
            ts.tv_sec = timeout_ns / 1000000000;
            ts.tv_nsec = timeout_ns % 1000000000;
            tsp = &ts;
        }
        siginfo_t si;
        int sig = sigtimedwait(&set, &si, tsp);
        if (sig < 0) {
            if (errno == EAGAIN) return 0;
            if (errno == EINTR) continue;
            return -errno;
        }
#else
        struct timespec ts, *tsp = NULL;
        if (timeout_ns >= 0) {
            ts.tv_sec = timeout_ns / 1000000000;
            ts.tv_nsec = timeout_ns % 1000000000;
            tsp = &ts;
        }
        struct kevent ev;
        int n = kevent(sup_kq, NULL, 0, &ev, 1, tsp);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -errno;
        }
        if (n == 0) return 0;
        int sig = (int)ev.ident;
#endif
        if (sig == SIGCHLD) continue; // reaped at the top
        *status = sig;
        return 2;
    }
}

int cv_thread_count(void) {
#if defined(__linux__)
    char buf[4096];
    long n = cv_read_small_file("/proc/self/status", buf, sizeof buf - 1);
    if (n <= 0) return -1;
    buf[n] = 0;
    char *t = strstr(buf, "\nThreads:");
    return t ? atoi(t + 9) : -1;
#elif defined(__APPLE__)
    thread_act_array_t threads;
    mach_msg_type_number_t n = 0;
    if (task_threads(mach_task_self(), &threads, &n) != KERN_SUCCESS) return -1;
    for (mach_msg_type_number_t i = 0; i < n; i++) mach_port_deallocate(mach_task_self(), threads[i]);
    vm_deallocate(mach_task_self(), (vm_address_t)threads, n * sizeof *threads);
    return (int)n;
#else
    return -1;
#endif
}

int cv_sockaddr_port(const cv_sockaddr *a) {
    const struct sockaddr *sa = (const struct sockaddr *)a->storage;
    if (sa->sa_family == AF_INET) return ntohs(((const struct sockaddr_in *)sa)->sin_port);
    if (sa->sa_family == AF_INET6) return ntohs(((const struct sockaddr_in6 *)sa)->sin6_port);
    return -1;
}

int cv_sockaddr_host(const cv_sockaddr *a, char *buf, int buflen) {
    const struct sockaddr *sa = (const struct sockaddr *)a->storage;
    switch (sa->sa_family) {
    case AF_INET:
        return inet_ntop(AF_INET, &((const struct sockaddr_in *)sa)->sin_addr, buf,
                         (socklen_t)buflen) ? 0 : -1;
    case AF_INET6:
        return inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)sa)->sin6_addr, buf,
                         (socklen_t)buflen) ? 0 : -1;
    case AF_UNIX: {
        // An unnamed socket (a connecting client, a socketpair) has no path.
        const struct sockaddr_un *un = (const struct sockaddr_un *)sa;
        size_t off = offsetof(struct sockaddr_un, sun_path);
        size_t max = a->len > off ? a->len - off : 0;
        if (max > sizeof un->sun_path) max = sizeof un->sun_path;
        size_t n = strnlen(un->sun_path, max);
        if (n >= (size_t)buflen) return -1;
        memcpy(buf, un->sun_path, n);
        buf[n] = 0;
        return 0;
    }
    default:
        return -1;
    }
}

int cv_local_address(int fd, cv_sockaddr *out) {
    socklen_t len = sizeof out->storage;
    if (getsockname(fd, (struct sockaddr *)out->storage, &len) != 0) return errno;
    out->len = (uint32_t)len;
    return 0;
}

int cv_peer_address(int fd, cv_sockaddr *out) {
    socklen_t len = sizeof out->storage;
    if (getpeername(fd, (struct sockaddr *)out->storage, &len) != 0) return errno;
    out->len = (uint32_t)len;
    return 0;
}

int cv_input_waiting(int fd) {
    struct pollfd p = {.fd = fd, .events = POLLIN};
    return poll(&p, 1, 0) > 0 ? 1 : 0;
}

int cv_local_port(int fd) {
    cv_sockaddr a;
    return cv_local_address(fd, &a) == 0 ? cv_sockaddr_port(&a) : -1;
}

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0 // Darwin: SO_NOSIGPIPE, set on every socket by prepare_fd
#endif

intptr_t cv_recv(int fd, void *buf, intptr_t len) {
    ssize_t n = recv(fd, buf, (size_t)len, 0);
    return n >= 0 ? (long)n : -(long)errno;
}

/// What a cv_arrival's space holds.
struct arrival_msg {
    struct msghdr mh;
    struct iovec iov;
    union {
        char buf[CMSG_SPACE(sizeof(struct timeval))];
        struct cmsghdr align;
    } control;
};
_Static_assert(sizeof(struct arrival_msg) <= sizeof(((cv_arrival *)0)->space), "cv_arrival's space is too small");

static struct msghdr *arrival_prepare(cv_arrival *arrival, void *buf, size_t len) {
    struct arrival_msg *m = (struct arrival_msg *)arrival->space;
    memset(m, 0, sizeof *m);
    m->iov.iov_base = buf;
    m->iov.iov_len = len;
    m->mh.msg_iov = &m->iov;
    m->mh.msg_iovlen = 1;
    m->mh.msg_control = m->control.buf;
    m->mh.msg_controllen = sizeof m->control.buf;
    arrival->micros = 0;
    return &m->mh;
}

void cv_arrival_settle(cv_arrival *arrival) {
    struct arrival_msg *m = (struct arrival_msg *)arrival->space;
    arrival->micros = 0;
    // The control space was zeroed, so a stamp the kernel did not write is
    // a header of length 0, which ends the walk.
    for (struct cmsghdr *cm = CMSG_FIRSTHDR(&m->mh); cm; cm = CMSG_NXTHDR(&m->mh, cm)) {
        if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_TIMESTAMP &&
            cm->cmsg_len >= CMSG_LEN(sizeof(struct timeval))) {
            struct timeval tv;
            memcpy(&tv, CMSG_DATA(cm), sizeof tv);
            arrival->micros = (uint64_t)tv.tv_sec * 1000000u + (uint64_t)tv.tv_usec;
        }
    }
}

intptr_t cv_recv_stamped(int fd, void *buf, intptr_t len, cv_arrival *arrival) {
    struct msghdr *mh = arrival_prepare(arrival, buf, (size_t)len);
    ssize_t n = recvmsg(fd, mh, 0);
    if (n < 0) return -(long)errno;
    cv_arrival_settle(arrival);
    return (long)n;
}

intptr_t cv_sendfile(int fd, int file, int64_t offset, intptr_t count) {
#if defined(__linux__)
    off_t off = (off_t)offset;
    ssize_t n = sendfile(fd, file, &off, (size_t)count);
    return n >= 0 ? (intptr_t)n : -(intptr_t)errno;
#elif defined(__APPLE__)
    off_t len = (off_t)count;
    int rc = sendfile(file, fd, (off_t)offset, &len, NULL, 0);
    // EAGAIN with some sent: report what went; the next call says EAGAIN.
    if (rc == 0 || len > 0) return (intptr_t)len;
    return -(intptr_t)errno;
#else
    (void)fd; (void)file; (void)offset; (void)count;
    return -ENOSYS;
#endif
}

#if defined(__linux__) && __has_include(<linux/openat2.h>)
#include <linux/openat2.h>
#include <sys/syscall.h>
#endif

int cv_open_beneath(const char *root, const char *relative) {
#if defined(__linux__) && __has_include(<linux/openat2.h>) && defined(SYS_openat2)
    static _Atomic int unavailable = 0;
    if (atomic_load_explicit(&unavailable, memory_order_relaxed)) return -ENOSYS;
    while (*relative == '/') relative++;
    if (!*relative) relative = ".";
    // The root is opened each time rather than kept: a deployment that
    // switches a symlink to a new release directory is served from the new
    // one at once.
    int dir = open(root, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (dir < 0) return -errno;
    struct open_how how;
    memset(&how, 0, sizeof how);
    how.flags = O_RDONLY | O_CLOEXEC;
    how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;
    long fd;
    do {
        fd = syscall(SYS_openat2, dir, relative, &how, sizeof how);
    } while (fd < 0 && errno == EINTR);
    int saved = errno;
    close(dir);
    if (fd >= 0) return (int)fd;
    // No openat2 (old kernel), or a seccomp filter refusing it: the caller
    // checks the path itself from now on.
    if (saved == ENOSYS || saved == EPERM) {
        atomic_store_explicit(&unavailable, 1, memory_order_relaxed);
        return -ENOSYS;
    }
    return -saved;
#else
    (void)root; (void)relative;
    return -ENOSYS;
#endif
}

intptr_t cv_peek(int fd) {
    char c;
    ssize_t n = recv(fd, &c, 1, MSG_PEEK | MSG_DONTWAIT);
    return n >= 0 ? (long)n : -(long)errno;
}

intptr_t cv_send(int fd, const void *buf, intptr_t len) {
    ssize_t n = send(fd, buf, (size_t)len, MSG_NOSIGNAL);
    return n >= 0 ? (long)n : -(long)errno;
}

int cv_udp_bind(const char *host, int port, int reuse_port, int *err) {
    struct addrinfo *res = resolve(host, port, 1, SOCK_DGRAM, err);
    if (!res) return -1;
    int fd = -1;
    *err = EADDRNOTAVAIL;
    for (struct addrinfo *a = res; a; a = a->ai_next) {
        fd = new_socket(a->ai_family, SOCK_DGRAM);
        if (fd < 0) {
            *err = errno;
            continue;
        }
#ifdef SO_REUSEPORT
        int one = 1;
        if (reuse_port) setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
#endif
        if (bind(fd, a->ai_addr, a->ai_addrlen) == 0) {
            *err = 0;
            break;
        }
        *err = errno;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

int cv_connect_address(int fd, const cv_sockaddr *a) {
    return connect(fd, (const struct sockaddr *)a->storage, (socklen_t)a->len) == 0 ? 0 : errno;
}

intptr_t cv_sendto(int fd, const void *buf, intptr_t len, const cv_sockaddr *to) {
    ssize_t n = sendto(fd, buf, (size_t)len, MSG_NOSIGNAL, (const struct sockaddr *)to->storage,
                       (socklen_t)to->len);
    return n >= 0 ? (long)n : -(long)errno;
}

intptr_t cv_recvfrom(int fd, void *buf, intptr_t len, cv_sockaddr *from) {
    socklen_t alen = sizeof from->storage;
    ssize_t n = recvfrom(fd, buf, (size_t)len, 0, (struct sockaddr *)from->storage, &alen);
    if (n < 0) return -(long)errno;
    from->len = (uint32_t)alen;
    return (long)n;
}

static int unix_address(const char *path, struct sockaddr_un *un, socklen_t *len) {
    size_t n = strlen(path);
    if (n == 0 || n >= sizeof un->sun_path) return ENAMETOOLONG;
    memset(un, 0, sizeof *un);
    un->sun_family = AF_UNIX;
    memcpy(un->sun_path, path, n);
    *len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + n + 1);
    return 0;
}

int cv_unix_listen(const char *path, int backlog, int *err) {
    struct sockaddr_un un;
    socklen_t len;
    if ((*err = unix_address(path, &un, &len)) != 0) return -1;
    int fd = new_socket(AF_UNIX, SOCK_STREAM);
    if (fd < 0) {
        *err = errno;
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&un, len) != 0 || listen(fd, backlog) != 0) {
        *err = errno;
        close(fd);
        return -1;
    }
    return fd;
}

int cv_unix_connect(const char *path, int *err) {
    struct sockaddr_un un;
    socklen_t len;
    if ((*err = unix_address(path, &un, &len)) != 0) return -1;
    int fd = new_socket(AF_UNIX, SOCK_STREAM);
    if (fd < 0) {
        *err = errno;
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&un, len) == 0) return fd;
    if (errno == EINPROGRESS) {
        *err = EINPROGRESS;
        return fd;
    }
    *err = errno;
    close(fd);
    return -1;
}

int cv_unix_accept(int fd, int *err) { return accept_nb(fd, err); }

int cv_unix_pair(int fds[2]) {
#if defined(__linux__)
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, fds) != 0) return errno;
#else
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) return errno;
    if (prepare_fd(fds[0]) != 0 || prepare_fd(fds[1]) != 0) {
        int e = errno;
        close(fds[0]);
        close(fds[1]);
        return e;
    }
#endif
    return 0;
}

#else // _WIN32: the few of those the portable code uses

void cv_random_bytes(void *buf, intptr_t n) {
    if (BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) abort();
}

intptr_t cv_read_small_file(const char *path, void *buf, intptr_t max) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    long total = (long)fread(buf, 1, (size_t)max, f);
    int more = total == max && fgetc(f) != EOF;
    int failed = ferror(f);
    fclose(f);
    return more || failed ? -1 : total;
}

int cv_thread_count(void) { return -1; }

#endif

// ---- Swift runtime hooks -------------------------------------------------

static cv_enqueue_fn enqueue_fn;
static void *enqueue_ctx;

// The hook and the original it is handed are swiftcc. With only pointer
// arguments that matches the C convention on every target Swift supports,
// but say so explicitly where clang knows the attribute.
#if __has_attribute(swiftcall)
#define CV_SWIFTCC __attribute__((swiftcall))
#else
#define CV_SWIFTCC
#endif

typedef CV_SWIFTCC void (*enqueue_original)(void *job);
typedef CV_SWIFTCC void (*enqueue_hook)(void *job, enqueue_original original);

static CV_SWIFTCC void enqueue_global(void *job, enqueue_original original) {
    (void)original;
    enqueue_fn(job, enqueue_ctx);
}

int cv_install_enqueue_global_hook(cv_enqueue_fn fn, void *ctx) {
#if defined(_WIN32)
    HMODULE rt = GetModuleHandleA("swift_Concurrency.dll");
    enqueue_hook *slot = rt ? (enqueue_hook *)GetProcAddress(rt, "swift_task_enqueueGlobal_hook") : NULL;
#else
    enqueue_hook *slot = (enqueue_hook *)dlsym(RTLD_DEFAULT, "swift_task_enqueueGlobal_hook");
#endif
    if (!slot) return -1;
    enqueue_fn = fn;
    enqueue_ctx = ctx;
    __atomic_store_n(slot, enqueue_global, __ATOMIC_RELEASE);
    return 0;
}


#if !defined(_WIN32) // socket options, vectored I/O, io_uring, signals: POSIX
// ---- socket options ------------------------------------------------------

#include <netinet/udp.h>
#ifndef SOL_UDP
#define SOL_UDP IPPROTO_UDP
#endif
#if defined(__linux__) && !defined(UDP_SEGMENT)
#define UDP_SEGMENT 103
#endif
#if defined(__linux__) && !defined(UDP_GRO)
#define UDP_GRO 104
#endif

static int sockopt_name(int opt, int *level, int *name) {
    switch (opt) {
    case CV_OPT_TCP_NODELAY: *level = IPPROTO_TCP; *name = TCP_NODELAY; return 0;
    case CV_OPT_KEEPALIVE: *level = SOL_SOCKET; *name = SO_KEEPALIVE; return 0;
#ifdef TCP_KEEPIDLE
    case CV_OPT_TCP_KEEPIDLE: *level = IPPROTO_TCP; *name = TCP_KEEPIDLE; return 0;
#elif defined(TCP_KEEPALIVE)
    case CV_OPT_TCP_KEEPIDLE: *level = IPPROTO_TCP; *name = TCP_KEEPALIVE; return 0;
#endif
#ifdef TCP_KEEPINTVL
    case CV_OPT_TCP_KEEPINTVL: *level = IPPROTO_TCP; *name = TCP_KEEPINTVL; return 0;
#endif
#ifdef TCP_KEEPCNT
    case CV_OPT_TCP_KEEPCNT: *level = IPPROTO_TCP; *name = TCP_KEEPCNT; return 0;
#endif
#ifdef TCP_USER_TIMEOUT
    case CV_OPT_TCP_USER_TIMEOUT: *level = IPPROTO_TCP; *name = TCP_USER_TIMEOUT; return 0;
#endif
#ifdef TCP_QUICKACK
    case CV_OPT_TCP_QUICKACK: *level = IPPROTO_TCP; *name = TCP_QUICKACK; return 0;
#endif
#ifdef TCP_FASTOPEN
    case CV_OPT_TCP_FASTOPEN: *level = IPPROTO_TCP; *name = TCP_FASTOPEN; return 0;
#endif
    case CV_OPT_RCVBUF: *level = SOL_SOCKET; *name = SO_RCVBUF; return 0;
    case CV_OPT_SNDBUF: *level = SOL_SOCKET; *name = SO_SNDBUF; return 0;
    case CV_OPT_REUSEADDR: *level = SOL_SOCKET; *name = SO_REUSEADDR; return 0;
    case CV_OPT_TIMESTAMP: *level = SOL_SOCKET; *name = SO_TIMESTAMP; return 0;
#ifdef SO_REUSEPORT
    case CV_OPT_REUSEPORT: *level = SOL_SOCKET; *name = SO_REUSEPORT; return 0;
#endif
    case CV_OPT_BROADCAST: *level = SOL_SOCKET; *name = SO_BROADCAST; return 0;
    case CV_OPT_IPV6_V6ONLY: *level = IPPROTO_IPV6; *name = IPV6_V6ONLY; return 0;
    case CV_OPT_IP_TTL: *level = IPPROTO_IP; *name = IP_TTL; return 0;
    case CV_OPT_IP_TOS: *level = IPPROTO_IP; *name = IP_TOS; return 0;
    case CV_OPT_IPV6_UNICAST_HOPS: *level = IPPROTO_IPV6; *name = IPV6_UNICAST_HOPS; return 0;
#ifdef IPV6_TCLASS
    case CV_OPT_IPV6_TCLASS: *level = IPPROTO_IPV6; *name = IPV6_TCLASS; return 0;
#endif
    case CV_OPT_IP_MULTICAST_TTL: *level = IPPROTO_IP; *name = IP_MULTICAST_TTL; return 0;
    case CV_OPT_IP_MULTICAST_LOOP: *level = IPPROTO_IP; *name = IP_MULTICAST_LOOP; return 0;
    case CV_OPT_IPV6_MULTICAST_HOPS: *level = IPPROTO_IPV6; *name = IPV6_MULTICAST_HOPS; return 0;
    case CV_OPT_IPV6_MULTICAST_LOOP: *level = IPPROTO_IPV6; *name = IPV6_MULTICAST_LOOP; return 0;
#if defined(__linux__)
    case CV_OPT_UDP_GRO: *level = SOL_UDP; *name = UDP_GRO; return 0;
#endif
    default: return ENOPROTOOPT;
    }
}

/// On/off options, read back as 0 or 1.
static int is_flag(int opt) {
    switch (opt) {
    case CV_OPT_TCP_NODELAY: case CV_OPT_KEEPALIVE: case CV_OPT_TCP_QUICKACK:
    case CV_OPT_REUSEADDR: case CV_OPT_REUSEPORT: case CV_OPT_BROADCAST: case CV_OPT_TIMESTAMP:
    case CV_OPT_IPV6_V6ONLY: case CV_OPT_IP_MULTICAST_LOOP: case CV_OPT_IPV6_MULTICAST_LOOP:
        return 1;
    default:
        return 0;
    }
}

int cv_sockopt_set(int fd, int opt, int value) {
    if (opt == CV_OPT_LINGER) {
        struct linger l = {.l_onoff = value >= 0, .l_linger = value >= 0 ? value : 0};
        return setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, sizeof l) == 0 ? 0 : errno;
    }
    int level, name, e = sockopt_name(opt, &level, &name);
    if (e) return e;
#if !defined(__linux__)
    // BSDs take a byte for these; Linux takes either.
    if (level == IPPROTO_IP && (name == IP_MULTICAST_TTL || name == IP_MULTICAST_LOOP)) {
        unsigned char b = (unsigned char)value;
        return setsockopt(fd, level, name, &b, sizeof b) == 0 ? 0 : errno;
    }
#endif
    return setsockopt(fd, level, name, &value, sizeof value) == 0 ? 0 : errno;
}

int cv_sockopt_get(int fd, int opt, int *value) {
    if (opt == CV_OPT_LINGER) {
        struct linger l = {0};
        socklen_t len = sizeof l;
        if (getsockopt(fd, SOL_SOCKET, SO_LINGER, &l, &len) != 0) return errno;
        *value = l.l_onoff ? l.l_linger : -1;
        return 0;
    }
    int level, name, e = sockopt_name(opt, &level, &name);
    if (e) return e;
    int v = 0;
    socklen_t len = sizeof v;
    if (getsockopt(fd, level, name, &v, &len) != 0) return errno;
    *value = len == 1 ? (int)*(unsigned char *)&v : v;
    // Darwin reports some flags as their internal bit (SO_KEEPALIVE is 8).
    if (is_flag(opt)) *value = *value != 0;
    return 0;
}

int cv_multicast(int fd, const cv_sockaddr *group, unsigned interface, int join) {
    const struct sockaddr *sa = (const struct sockaddr *)group->storage;
    if (sa->sa_family == AF_INET) {
#if defined(__linux__)
        struct ip_mreqn m = {0};
        m.imr_multiaddr = ((const struct sockaddr_in *)sa)->sin_addr;
        m.imr_ifindex = (int)interface;
#else
        struct ip_mreq m = {0};
        m.imr_multiaddr = ((const struct sockaddr_in *)sa)->sin_addr;
        (void)interface; // INADDR_ANY: the kernel picks
#endif
        int op = join ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP;
        return setsockopt(fd, IPPROTO_IP, op, &m, sizeof m) == 0 ? 0 : errno;
    }
    if (sa->sa_family == AF_INET6) {
        struct ipv6_mreq m = {0};
        m.ipv6mr_multiaddr = ((const struct sockaddr_in6 *)sa)->sin6_addr;
        m.ipv6mr_interface = interface;
        int op = join ? IPV6_JOIN_GROUP : IPV6_LEAVE_GROUP;
        return setsockopt(fd, IPPROTO_IPV6, op, &m, sizeof m) == 0 ? 0 : errno;
    }
    return EAFNOSUPPORT;
}

// ---- vectored and batched I/O --------------------------------------------

#include <sys/uio.h>

_Static_assert(sizeof(cv_iovec) == sizeof(struct iovec) &&
                   offsetof(cv_iovec, base) == offsetof(struct iovec, iov_base) &&
                   offsetof(cv_iovec, len) == offsetof(struct iovec, iov_len),
               "cv_iovec must match struct iovec");

intptr_t cv_sendv(int fd, const cv_iovec *iov, int count) {
    struct msghdr mh = {0};
    mh.msg_iov = (struct iovec *)iov;
    mh.msg_iovlen = count;
    ssize_t n = sendmsg(fd, &mh, MSG_NOSIGNAL);
    return n >= 0 ? (long)n : -(long)errno;
}

enum { CV_BATCH_CHUNK = 64 };

// Room for a datagram's path cmsgs (an in6_pktinfo and a traffic class)
// plus a UDP_SEGMENT.
enum { CV_PATH_CMSG_ROOM = 128 };
typedef union {
    char buf[CV_PATH_CMSG_ROOM];
    struct cmsghdr align;
} cv_path_control;

// The local address and ECN bits from a received datagram's cmsgs.
static void cv_read_path(struct msghdr *mh, cv_dgram_path *path) {
    path->local.len = 0;
    path->ecn = 0;
    if (mh->msg_controllen == 0) return;
    for (struct cmsghdr *cm = CMSG_FIRSTHDR(mh); cm; cm = CMSG_NXTHDR(mh, cm)) {
#ifdef IP_PKTINFO
        if (cm->cmsg_level == IPPROTO_IP && cm->cmsg_type == IP_PKTINFO) {
            struct in_pktinfo pi;
            memcpy(&pi, CMSG_DATA(cm), sizeof pi);
            struct sockaddr_in a;
            memset(&a, 0, sizeof a);
            a.sin_family = AF_INET;
            a.sin_addr = pi.ipi_addr;
            memcpy(path->local.storage, &a, sizeof a);
            path->local.len = sizeof a;
            continue;
        }
#elif defined(IP_RECVDSTADDR)
        if (cm->cmsg_level == IPPROTO_IP && cm->cmsg_type == IP_RECVDSTADDR) {
            struct sockaddr_in a;
            memset(&a, 0, sizeof a);
            a.sin_family = AF_INET;
            memcpy(&a.sin_addr, CMSG_DATA(cm), sizeof a.sin_addr);
            memcpy(path->local.storage, &a, sizeof a);
            path->local.len = sizeof a;
            continue;
        }
#endif
#ifdef IPV6_PKTINFO
        if (cm->cmsg_level == IPPROTO_IPV6 && cm->cmsg_type == IPV6_PKTINFO) {
            struct in6_pktinfo pi;
            memcpy(&pi, CMSG_DATA(cm), sizeof pi);
            struct sockaddr_in6 a;
            memset(&a, 0, sizeof a);
            a.sin6_family = AF_INET6;
            a.sin6_addr = pi.ipi6_addr;
            a.sin6_scope_id = pi.ipi6_ifindex;
            memcpy(path->local.storage, &a, sizeof a);
            path->local.len = sizeof a;
            continue;
        }
#endif
#ifdef IP_TOS
        if (cm->cmsg_level == IPPROTO_IP && (cm->cmsg_type == IP_TOS
#ifdef IP_RECVTOS
                                             || cm->cmsg_type == IP_RECVTOS
#endif
                                             )) {
            // One byte on Linux and Darwin alike.
            unsigned char tos = 0;
            memcpy(&tos, CMSG_DATA(cm), 1);
            path->ecn = tos & 3u;
            continue;
        }
#endif
#ifdef IPV6_TCLASS
        if (cm->cmsg_level == IPPROTO_IPV6 && cm->cmsg_type == IPV6_TCLASS) {
            int tclass = 0;
            memcpy(&tclass, CMSG_DATA(cm), sizeof tclass);
            path->ecn = (uint32_t)tclass & 3u;
            continue;
        }
#endif
    }
}

// Write path's cmsgs (source address, ECN) into control from offset used;
// family is the destination's address family. Returns the new offset.
static size_t cv_put_path(char *control, size_t used, const cv_dgram_path *path, int family) {
    if (!path) return used;
    if (path->local.len) {
        const struct sockaddr *sa = (const struct sockaddr *)path->local.storage;
#ifdef IP_PKTINFO
        if (sa->sa_family == AF_INET) {
            struct cmsghdr *cm = (struct cmsghdr *)(control + used);
            cm->cmsg_level = IPPROTO_IP;
            cm->cmsg_type = IP_PKTINFO;
            cm->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
            struct in_pktinfo pi;
            memset(&pi, 0, sizeof pi);
            pi.ipi_spec_dst = ((const struct sockaddr_in *)sa)->sin_addr;
            memcpy(CMSG_DATA(cm), &pi, sizeof pi);
            used += CMSG_SPACE(sizeof(struct in_pktinfo));
        }
#elif defined(IP_SENDSRCADDR)
        if (sa->sa_family == AF_INET) {
            struct cmsghdr *cm = (struct cmsghdr *)(control + used);
            cm->cmsg_level = IPPROTO_IP;
            cm->cmsg_type = IP_SENDSRCADDR;
            cm->cmsg_len = CMSG_LEN(sizeof(struct in_addr));
            memcpy(CMSG_DATA(cm), &((const struct sockaddr_in *)sa)->sin_addr, sizeof(struct in_addr));
            used += CMSG_SPACE(sizeof(struct in_addr));
        }
#endif
#ifdef IPV6_PKTINFO
        if (sa->sa_family == AF_INET6) {
            struct cmsghdr *cm = (struct cmsghdr *)(control + used);
            cm->cmsg_level = IPPROTO_IPV6;
            cm->cmsg_type = IPV6_PKTINFO;
            cm->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
            struct in6_pktinfo pi;
            memset(&pi, 0, sizeof pi);
            pi.ipi6_addr = ((const struct sockaddr_in6 *)sa)->sin6_addr;
            pi.ipi6_ifindex = ((const struct sockaddr_in6 *)sa)->sin6_scope_id;
            memcpy(CMSG_DATA(cm), &pi, sizeof pi);
            used += CMSG_SPACE(sizeof(struct in6_pktinfo));
        }
#endif
    }
    if (path->ecn) {
        int bits = (int)(path->ecn & 3u);
        struct cmsghdr *cm = (struct cmsghdr *)(control + used);
        if (family == AF_INET6) {
#ifdef IPV6_TCLASS
            cm->cmsg_level = IPPROTO_IPV6;
            cm->cmsg_type = IPV6_TCLASS;
            cm->cmsg_len = CMSG_LEN(sizeof bits);
            memcpy(CMSG_DATA(cm), &bits, sizeof bits);
            used += CMSG_SPACE(sizeof bits);
#endif
        } else {
#ifdef IP_TOS
            cm->cmsg_level = IPPROTO_IP;
            cm->cmsg_type = IP_TOS;
            cm->cmsg_len = CMSG_LEN(sizeof bits);
            memcpy(CMSG_DATA(cm), &bits, sizeof bits);
            used += CMSG_SPACE(sizeof bits);
#endif
        }
    }
    return used;
}

// The destination's family, which picks the ECN cmsg: to's, else the
// socket's, looked up (one getsockname) only when ECN is set and kept in
// *cached for the rest of a batch.
static int cv_path_family(int fd, const cv_sockaddr *to, const cv_dgram_path *path, int *cached) {
    if (!path->ecn) return AF_INET;
    if (to && to->len) return ((const struct sockaddr *)to->storage)->sa_family;
    if (*cached < 0) {
        struct sockaddr_storage ss;
        socklen_t len = sizeof ss;
        *cached = getsockname(fd, (struct sockaddr *)&ss, &len) == 0 ? ss.ss_family : AF_INET;
    }
    return *cached;
}

int cv_udp_path_info(int fd, int on) {
    // The options of both families: on a dual-stack IPv6 socket, IPv4
    // datagrams report through the IPv4 ones. Those that don't apply to
    // this socket fail and are skipped.
    int v = on ? 1 : 0, ok = 0, err = EINVAL;
#ifdef IPV6_RECVPKTINFO
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &v, sizeof v) == 0) ok = 1; else err = errno;
#endif
#ifdef IPV6_RECVTCLASS
    (void)setsockopt(fd, IPPROTO_IPV6, IPV6_RECVTCLASS, &v, sizeof v);
#endif
#ifdef IP_PKTINFO
    if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &v, sizeof v) == 0) ok = 1; else err = errno;
#elif defined(IP_RECVDSTADDR)
    if (setsockopt(fd, IPPROTO_IP, IP_RECVDSTADDR, &v, sizeof v) == 0) ok = 1; else err = errno;
#endif
#ifdef IP_RECVTOS
    (void)setsockopt(fd, IPPROTO_IP, IP_RECVTOS, &v, sizeof v);
#endif
    return ok ? 0 : err;
}

int cv_udp_dont_fragment(int fd, int on) {
    int ok = 0, err = EINVAL;
#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DO)
    int mode = on ? IP_PMTUDISC_DO : IP_PMTUDISC_WANT;
    if (setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &mode, sizeof mode) == 0) ok = 1; else err = errno;
#elif defined(IP_DONTFRAG)
    int v4 = on ? 1 : 0;
    if (setsockopt(fd, IPPROTO_IP, IP_DONTFRAG, &v4, sizeof v4) == 0) ok = 1; else err = errno;
#endif
#if defined(IPV6_MTU_DISCOVER) && defined(IPV6_PMTUDISC_DO)
    int mode6 = on ? IPV6_PMTUDISC_DO : IPV6_PMTUDISC_WANT;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &mode6, sizeof mode6) == 0) ok = 1; else err = errno;
#elif defined(IPV6_DONTFRAG)
    int v6 = on ? 1 : 0;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG, &v6, sizeof v6) == 0) ok = 1; else err = errno;
#endif
    return ok ? 0 : err;
}

intptr_t cv_recv_batch(int fd, void *base, intptr_t stride, int count, cv_sockaddr *from,
                   uint32_t *lens, uint32_t *flags, cv_dgram_path *paths) {
#if defined(__linux__)
    if (count > CV_BATCH_CHUNK) count = CV_BATCH_CHUNK;
    struct mmsghdr hdrs[CV_BATCH_CHUNK];
    struct iovec iov[CV_BATCH_CHUNK];
    cv_path_control control[paths ? CV_BATCH_CHUNK : 1];
    memset(hdrs, 0, sizeof hdrs[0] * (size_t)count);
    for (int i = 0; i < count; i++) {
        iov[i].iov_base = (char *)base + (size_t)i * (size_t)stride;
        iov[i].iov_len = (size_t)stride;
        hdrs[i].msg_hdr.msg_name = from[i].storage;
        hdrs[i].msg_hdr.msg_namelen = sizeof from[i].storage;
        hdrs[i].msg_hdr.msg_iov = &iov[i];
        hdrs[i].msg_hdr.msg_iovlen = 1;
        if (paths) {
            hdrs[i].msg_hdr.msg_control = control[i].buf;
            hdrs[i].msg_hdr.msg_controllen = sizeof control[i].buf;
        }
    }
    int n = recvmmsg(fd, hdrs, (unsigned)count, 0, NULL);
    if (n < 0) return -(long)errno;
    for (int i = 0; i < n; i++) {
        from[i].len = hdrs[i].msg_hdr.msg_namelen;
        lens[i] = hdrs[i].msg_len;
        flags[i] = (hdrs[i].msg_hdr.msg_flags & MSG_TRUNC) ? CV_DGRAM_TRUNCATED : 0;
        if (paths) cv_read_path(&hdrs[i].msg_hdr, &paths[i]);
    }
    return n;
#else
    int got = 0;
    for (; got < count; got++) {
        struct iovec v = {(char *)base + (size_t)got * (size_t)stride, (size_t)stride};
        struct msghdr mh = {0};
        cv_path_control control;
        mh.msg_name = from[got].storage;
        mh.msg_namelen = sizeof from[got].storage;
        mh.msg_iov = &v;
        mh.msg_iovlen = 1;
        if (paths) {
            mh.msg_control = control.buf;
            mh.msg_controllen = sizeof control.buf;
        }
        ssize_t n = recvmsg(fd, &mh, 0);
        if (n < 0) {
            if (got > 0) break;
            return -(long)errno;
        }
        from[got].len = mh.msg_namelen;
        lens[got] = (uint32_t)n;
        flags[got] = (mh.msg_flags & MSG_TRUNC) ? CV_DGRAM_TRUNCATED : 0;
        if (paths) cv_read_path(&mh, &paths[got]);
    }
    return got;
#endif
}

intptr_t cv_send_batch(int fd, const void *base, intptr_t stride, const uint32_t *lens,
                   const cv_sockaddr *to, int count, const cv_dgram_path *paths) {
    int family = -1; // the socket's, looked up once if a datagram needs it
#if defined(__linux__)
    if (count > CV_BATCH_CHUNK) count = CV_BATCH_CHUNK;
    struct mmsghdr hdrs[CV_BATCH_CHUNK];
    struct iovec iov[CV_BATCH_CHUNK];
    cv_path_control control[paths ? CV_BATCH_CHUNK : 1];
    memset(hdrs, 0, sizeof hdrs[0] * (size_t)count);
    for (int i = 0; i < count; i++) {
        iov[i].iov_base = (char *)base + (size_t)i * (size_t)stride;
        iov[i].iov_len = lens[i];
        if (to && to[i].len) {
            hdrs[i].msg_hdr.msg_name = (void *)to[i].storage;
            hdrs[i].msg_hdr.msg_namelen = to[i].len;
        }
        hdrs[i].msg_hdr.msg_iov = &iov[i];
        hdrs[i].msg_hdr.msg_iovlen = 1;
        if (paths) {
            int fam = cv_path_family(fd, to ? &to[i] : NULL, &paths[i], &family);
            size_t used = cv_put_path(control[i].buf, 0, &paths[i], fam);
            if (used) {
                hdrs[i].msg_hdr.msg_control = control[i].buf;
                hdrs[i].msg_hdr.msg_controllen = used;
            }
        }
    }
    int n = sendmmsg(fd, hdrs, (unsigned)count, MSG_NOSIGNAL);
    return n >= 0 ? (long)n : -(long)errno;
#else
    int sent = 0;
    for (; sent < count; sent++) {
        const char *p = (const char *)base + (size_t)sent * (size_t)stride;
        struct iovec v = {(void *)p, lens[sent]};
        struct msghdr mh = {0};
        cv_path_control control;
        if (to && to[sent].len) {
            mh.msg_name = (void *)to[sent].storage;
            mh.msg_namelen = (socklen_t)to[sent].len;
        }
        mh.msg_iov = &v;
        mh.msg_iovlen = 1;
        if (paths) {
            int fam = cv_path_family(fd, to ? &to[sent] : NULL, &paths[sent], &family);
            size_t used = cv_put_path(control.buf, 0, &paths[sent], fam);
            if (used) {
                mh.msg_control = control.buf;
                mh.msg_controllen = (socklen_t)used;
            }
        }
        ssize_t n = sendmsg(fd, &mh, MSG_NOSIGNAL);
        if (n < 0) {
            if (sent > 0) break;
            return -(long)errno;
        }
    }
    return sent;
#endif
}

intptr_t cv_send_segments_split(int fd, const void *buf, intptr_t len, int segment, const cv_sockaddr *to,
                                const cv_dgram_path *path) {
    // The segments already lie back to back, segment bytes apart: send them
    // as a batch over the same memory, one datagram each.
    if (segment <= 0 || len <= segment) segment = len > 0 ? (int)len : 1;
    int have_to = to && to->len;
    uint32_t lens[CV_BATCH_CHUNK];
    cv_sockaddr tos[CV_BATCH_CHUNK];
    cv_dgram_path paths[path ? CV_BATCH_CHUNK : 1];
    long done = 0;
    do {
        int k = 0;
        for (long off = done; k < CV_BATCH_CHUNK && (off < len || (len == 0 && k == 0)); k++) {
            long l = len - off < segment ? len - off : segment;
            lens[k] = (uint32_t)l;
            off += l;
            if (have_to) tos[k] = *to;
            if (path) paths[k] = *path;
        }
        long n = cv_send_batch(fd, (const char *)buf + done, segment, lens, have_to ? tos : NULL, k,
                               path ? paths : NULL);
        if (n < 0) return done > 0 ? done : n; // the next call reports the error
        for (long i = 0; i < n; i++) done += lens[i];
        if (n < k) break; // the socket filled up: whole segments sent so far
    } while (done < len);
    return done;
}

intptr_t cv_send_segments(int fd, const void *buf, intptr_t len, int segment, const cv_sockaddr *to,
                          const cv_dgram_path *path) {
#if defined(__linux__)
    if (segment <= 0 || len <= segment)
        return cv_send_segments_split(fd, buf, len, segment, to, path);
    // Whether the kernel knows UDP_SEGMENT (4.18+): the same for every
    // socket, so asked once. An older kernel ignores the cmsg and would
    // send one large datagram instead.
    static _Atomic int gso; // 0 unknown, 1 yes, -1 no
    int known = atomic_load_explicit(&gso, memory_order_relaxed);
    if (known == 0) {
        known = cv_udp_gso_supported(fd) ? 1 : -1;
        atomic_store_explicit(&gso, known, memory_order_relaxed);
    }
    if (known < 0) return cv_send_segments_split(fd, buf, len, segment, to, path);

    struct iovec v = {(void *)buf, (size_t)len};
    struct msghdr mh = {0};
    if (to && to->len) {
        mh.msg_name = (void *)to->storage;
        mh.msg_namelen = to->len;
    }
    mh.msg_iov = &v;
    mh.msg_iovlen = 1;
    union {
        char buf[CV_PATH_CMSG_ROOM + CMSG_SPACE(sizeof(uint16_t))];
        struct cmsghdr align;
    } control;
    memset(&control, 0, sizeof control);
    int family = -1;
    size_t used = path ? cv_put_path(control.buf, 0, path, cv_path_family(fd, to, path, &family)) : 0;
    struct cmsghdr *cm = (struct cmsghdr *)(control.buf + used);
    cm->cmsg_level = SOL_UDP;
    cm->cmsg_type = UDP_SEGMENT;
    cm->cmsg_len = CMSG_LEN(sizeof(uint16_t));
    uint16_t seg = (uint16_t)segment;
    memcpy(CMSG_DATA(cm), &seg, sizeof seg);
    used += CMSG_SPACE(sizeof(uint16_t));
    mh.msg_control = control.buf;
    mh.msg_controllen = used;
    ssize_t n = sendmsg(fd, &mh, MSG_NOSIGNAL);
    if (n >= 0) return (long)n;
    // EIO: this route can't offload the checksum (IPsec, for one).
    if (errno == EIO || errno == EOPNOTSUPP || errno == ENOPROTOOPT)
        return cv_send_segments_split(fd, buf, len, segment, to, path);
    return -(long)errno;
#else
    return cv_send_segments_split(fd, buf, len, segment, to, path);
#endif
}

int cv_udp_gso_supported(int fd) {
#if defined(__linux__)
    int size = 0;
    socklen_t len = sizeof size;
    return getsockopt(fd, SOL_UDP, UDP_SEGMENT, &size, &len) == 0;
#else
    (void)fd;
    return 0;
#endif
}

intptr_t cv_recv_segments(int fd, void *buf, intptr_t len, cv_sockaddr *from, int *segment,
                      uint32_t *flags) {
    struct iovec v = {buf, (size_t)len};
    struct msghdr mh = {0};
    if (from) {
        mh.msg_name = from->storage;
        mh.msg_namelen = sizeof from->storage;
    }
    mh.msg_iov = &v;
    mh.msg_iovlen = 1;
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } control;
    mh.msg_control = control.buf;
    mh.msg_controllen = sizeof control.buf;
    ssize_t n = recvmsg(fd, &mh, 0);
    if (n < 0) return -(long)errno;
    if (from) from->len = mh.msg_namelen;
    *segment = 0;
    // A coalesced burst longer than the buffer loses its tail, as a single
    // datagram does.
    *flags = (mh.msg_flags & MSG_TRUNC) ? CV_DGRAM_TRUNCATED : 0;
#if defined(__linux__)
    for (struct cmsghdr *cm = CMSG_FIRSTHDR(&mh); cm; cm = CMSG_NXTHDR(&mh, cm)) {
        if (cm->cmsg_level == SOL_UDP && cm->cmsg_type == UDP_GRO) {
            memcpy(segment, CMSG_DATA(cm), sizeof(int));
        }
    }
#endif
    return (long)n;
}
// ---- io_uring driver -----------------------------------------------------

#if defined(__linux__)
#include <linux/io_uring.h>
#include <poll.h>
#include <sys/mman.h>

#ifndef FUTEX2_SIZE_U32
#define FUTEX2_SIZE_U32 0x02
#endif
#ifndef FUTEX2_PRIVATE
#define FUTEX2_PRIVATE FUTEX_PRIVATE_FLAG
#endif
#ifndef FUTEX_BITSET_MATCH_ANY
#define FUTEX_BITSET_MATCH_ANY 0xffffffffu
#endif

// Small: ring memory counts against RLIMIT_MEMLOCK, and a full queue is
// just submitted early. NODROP keeps completions past the CQ's size.
#define CV_URING_SQ 128
#define CV_URING_CQ 512
#define CV_URING_BATCH 1024 // completions reaped per turn
#define CV_URING_SLAB 256   // slots added at a time

// user_data of the ring's own requests; slots are 64-byte aligned.
#define TAG_FUTEX ((uint64_t)1)
#define TAG_CANCEL ((uint64_t)2)

// Slot states, in the low 3 bits of `state`; the generation is above them.
enum { OP_FREE = 0, OP_PENDING = 1, OP_CANCEL_REQ = 2, OP_DONE_DEFERRED = 3, OP_CANCEL_SENT = 4 };

struct cv_uring_op {
    _Atomic uint64_t state;
    _Atomic(cv_uring_op *) next_cancel; // the ring's cancel list
    cv_uring_op *next_free;             // owner only
    cv_uring *ring;
    uintptr_t waiter;
    int64_t res; // a completion that came while a cancel was queued
    char pad[16];
};
_Static_assert(sizeof(cv_uring_op) == 64, "one slot per cache line");

struct slab_chunk {
    struct slab_chunk *next;
    cv_uring_op *ops;
};

struct cv_uring {
    // Written by other threads: cancels.
    _Atomic(cv_uring_op *) cancels;
    char pad0[120];
    int fd;
    cv_parker *parker;
    int futex_armed;
    unsigned sq_tail; // ours; published to *sq_ktail
    unsigned sq_mask, sq_entries, cq_mask;
    _Atomic unsigned *sq_khead, *sq_ktail, *sq_kflags, *cq_khead, *cq_ktail;
    struct io_uring_sqe *sqes;
    struct io_uring_cqe *cqes;
    void *sq_map, *cq_map;
    size_t sq_map_len, cq_map_len, sqes_len;
    cv_uring_op *free;
    struct slab_chunk *chunks;
    cv_driver_stats stats;
    int nwakes;
    cv_uring_wake wakes[2 * CV_URING_BATCH];
};

static long uring_setup(unsigned entries, struct io_uring_params *p) {
    return syscall(__NR_io_uring_setup, entries, p);
}

static long uring_enter(int fd, unsigned submit, unsigned wait, unsigned flags, void *arg, size_t argsz) {
    return syscall(__NR_io_uring_enter, fd, submit, wait, flags, arg, argsz);
}

static long uring_register(int fd, unsigned op, void *arg, unsigned n) {
    return syscall(__NR_io_uring_register, fd, op, arg, n);
}

static const unsigned uring_flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN |
                                    IORING_SETUP_TASKRUN_FLAG | IORING_SETUP_CQSIZE |
                                    IORING_SETUP_SUBMIT_ALL;

int cv_uring_probe(void) {
    struct io_uring_params p = {0};
    p.flags = uring_flags;
    p.cq_entries = CV_URING_CQ;
    int fd = (int)uring_setup(8, &p);
    if (fd < 0) return errno;
    int rc = 0;
    if (!(p.features & IORING_FEAT_EXT_ARG) || !(p.features & IORING_FEAT_NODROP)) {
        rc = EOPNOTSUPP;
    } else {
        size_t len = sizeof(struct io_uring_probe) + 256 * sizeof(struct io_uring_probe_op);
        struct io_uring_probe *probe = calloc(1, len);
        if (!probe) {
            rc = ENOMEM;
        } else if (uring_register(fd, IORING_REGISTER_PROBE, probe, 256) < 0) {
            rc = errno;
        } else {
            static const int needed[] = {IORING_OP_RECV, IORING_OP_SEND, IORING_OP_ACCEPT,
                                         IORING_OP_POLL_ADD, IORING_OP_ASYNC_CANCEL,
                                         IORING_OP_FUTEX_WAIT};
            for (size_t i = 0; i < sizeof needed / sizeof needed[0]; i++) {
                int op = needed[i];
                if (op > probe->last_op || !(probe->ops[op].flags & IO_URING_OP_SUPPORTED))
                    rc = EOPNOTSUPP;
            }
        }
        free(probe);
    }
    close(fd);
    return rc;
}

static void slab_grow(cv_uring *r) {
    struct slab_chunk *c = malloc(sizeof *c);
    cv_uring_op *ops = aligned_alloc(64, CV_URING_SLAB * sizeof(cv_uring_op));
    if (!c || !ops) abort();
    memset(ops, 0, CV_URING_SLAB * sizeof(cv_uring_op));
    c->ops = ops;
    c->next = r->chunks;
    r->chunks = c;
    for (int i = CV_URING_SLAB - 1; i >= 0; i--) {
        ops[i].ring = r;
        atomic_init(&ops[i].state, (uint64_t)1 << 3 | OP_FREE); // generation 1
        ops[i].next_free = r->free;
        r->free = &ops[i];
    }
}

cv_uring *cv_uring_new(cv_parker *parker) {
    struct io_uring_params p = {0};
    p.flags = uring_flags | IORING_SETUP_R_DISABLED;
    p.cq_entries = CV_URING_CQ;
    int fd = (int)uring_setup(CV_URING_SQ, &p);
    if (fd < 0) return NULL;
    cv_uring *r = aligned_alloc(128, (sizeof(cv_uring) + 127) & ~(size_t)127);
    if (!r) {
        close(fd);
        errno = ENOMEM;
        return NULL;
    }
    memset(r, 0, sizeof *r);
    r->fd = fd;
    // cv_uring_close on failure below must not unmap what isn't mapped.
    r->sq_map = r->cq_map = MAP_FAILED;
    r->sqes = MAP_FAILED;
    r->parker = parker;
    r->sq_map_len = p.sq_off.array + p.sq_entries * sizeof(unsigned);
    r->cq_map_len = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
    int single = (p.features & IORING_FEAT_SINGLE_MMAP) != 0;
    if (single) {
        if (r->cq_map_len > r->sq_map_len) r->sq_map_len = r->cq_map_len;
        r->cq_map_len = r->sq_map_len;
    }
    r->sq_map = mmap(NULL, r->sq_map_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
                     IORING_OFF_SQ_RING);
    if (r->sq_map == MAP_FAILED) goto fail;
    r->cq_map = single ? r->sq_map
                       : mmap(NULL, r->cq_map_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                              fd, IORING_OFF_CQ_RING);
    if (r->cq_map == MAP_FAILED) goto fail;
    r->sqes_len = p.sq_entries * sizeof(struct io_uring_sqe);
    r->sqes = mmap(NULL, r->sqes_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
                   IORING_OFF_SQES);
    if (r->sqes == MAP_FAILED) goto fail;

    char *sq = r->sq_map, *cq = r->cq_map;
    r->sq_khead = (_Atomic unsigned *)(sq + p.sq_off.head);
    r->sq_ktail = (_Atomic unsigned *)(sq + p.sq_off.tail);
    r->sq_kflags = (_Atomic unsigned *)(sq + p.sq_off.flags);
    r->sq_mask = *(unsigned *)(sq + p.sq_off.ring_mask);
    r->sq_entries = p.sq_entries;
    unsigned *array = (unsigned *)(sq + p.sq_off.array);
    for (unsigned i = 0; i < p.sq_entries; i++) array[i] = i; // slot i is sqe i, always
    r->cq_khead = (_Atomic unsigned *)(cq + p.cq_off.head);
    r->cq_ktail = (_Atomic unsigned *)(cq + p.cq_off.tail);
    r->cq_mask = *(unsigned *)(cq + p.cq_off.ring_mask);
    r->cqes = (struct io_uring_cqe *)(cq + p.cq_off.cqes);
    r->sq_tail = atomic_load_explicit(r->sq_ktail, memory_order_relaxed);
    slab_grow(r);
    return r;
fail: {
    int e = errno;
    cv_uring_free(r);
    errno = e;
    return NULL;
}
}

int cv_uring_enable(cv_uring *r) {
    return uring_register(r->fd, IORING_REGISTER_ENABLE_RINGS, NULL, 0) < 0 ? errno : 0;
}

void cv_uring_close(cv_uring *r) {
    if (r->sqes && r->sqes != MAP_FAILED) munmap(r->sqes, r->sqes_len);
    if (r->cq_map && r->cq_map != MAP_FAILED && r->cq_map != r->sq_map) munmap(r->cq_map, r->cq_map_len);
    if (r->sq_map && r->sq_map != MAP_FAILED) munmap(r->sq_map, r->sq_map_len);
    r->sqes = NULL;
    r->cq_map = r->sq_map = NULL;
    if (r->fd >= 0) close(r->fd);
    r->fd = -1;
}

void cv_uring_free(cv_uring *r) {
    if (!r) return;
    cv_uring_close(r);
    // Slots of operations still in flight go with the ring: their tasks were
    // never resumed, as with any task still waiting at shutdown.
    while (r->chunks) {
        struct slab_chunk *c = r->chunks;
        r->chunks = c->next;
        free(c->ops);
        free(c);
    }
    free(r);
}

static inline unsigned sq_pending(cv_uring *r) {
    return r->sq_tail - atomic_load_explicit(r->sq_khead, memory_order_acquire);
}

static inline int cq_ready(cv_uring *r) {
    return atomic_load_explicit(r->cq_ktail, memory_order_acquire) !=
           atomic_load_explicit(r->cq_khead, memory_order_relaxed);
}

static inline int taskrun_pending(cv_uring *r) {
    return (atomic_load_explicit(r->sq_kflags, memory_order_relaxed) & IORING_SQ_TASKRUN) != 0;
}

/// Submit the queue and run deferred completions; with `wait`, block for one
/// completion or timeout_ns (< 0: forever).
static void enter(cv_uring *r, int wait, int64_t timeout_ns) {
    unsigned flags = IORING_ENTER_GETEVENTS;
    struct __kernel_timespec ts;
    struct io_uring_getevents_arg arg = {0};
    void *argp = NULL;
    size_t argsz = 0;
    if (wait && timeout_ns >= 0) {
        ts.tv_sec = timeout_ns / 1000000000;
        ts.tv_nsec = timeout_ns % 1000000000;
        arg.ts = (uint64_t)(uintptr_t)&ts;
        argp = &arg;
        argsz = sizeof arg;
        flags |= IORING_ENTER_EXT_ARG;
    }
    // ETIME / EINTR end the wait: nothing to retry. EBUSY / EAGAIN mean
    // completions backed up (NODROP keeps them): the caller reaps, and what
    // is still queued goes in next time.
    (void)uring_enter(r->fd, sq_pending(r), wait ? 1 : 0, flags, argp, argsz);
}

static struct io_uring_sqe *get_sqe(cv_uring *r) {
    if (r->sq_tail - atomic_load_explicit(r->sq_khead, memory_order_acquire) >= r->sq_entries) {
        enter(r, 0, 0);
        while (r->sq_tail - atomic_load_explicit(r->sq_khead, memory_order_acquire) >= r->sq_entries) {
            // The kernel took none: completions have backed up. Unusual
            // enough to just yield and retry.
            sched_yield();
            enter(r, 0, 0);
        }
    }
    struct io_uring_sqe *sqe = &r->sqes[r->sq_tail & r->sq_mask];
    memset(sqe, 0, sizeof *sqe);
    return sqe;
}

static inline void push_sqe(cv_uring *r) {
    r->sq_tail++;
    atomic_store_explicit(r->sq_ktail, r->sq_tail, memory_order_release);
}

static cv_uring_op *op_new(cv_uring *r, uintptr_t waiter, uint64_t *gen) {
    if (!r->free) slab_grow(r);
    cv_uring_op *op = r->free;
    r->free = op->next_free;
    uint64_t g = atomic_load_explicit(&op->state, memory_order_relaxed) >> 3;
    op->waiter = waiter;
    atomic_store_explicit(&op->state, g << 3 | OP_PENDING, memory_order_release);
    *gen = g;
    return op;
}

static void op_free(cv_uring *r, cv_uring_op *op, uint64_t state) {
    atomic_store_explicit(&op->state, ((state >> 3) + 1) << 3 | OP_FREE, memory_order_release);
    op->next_free = r->free;
    r->free = op;
}

static cv_uring_op *submit_op(cv_uring *r, uintptr_t waiter, uint64_t *gen, uint8_t opcode, int fd,
                              uint64_t addr, uint32_t len) {
    struct io_uring_sqe *sqe = get_sqe(r);
    cv_uring_op *op = op_new(r, waiter, gen);
    sqe->opcode = opcode;
    sqe->fd = fd;
    sqe->addr = addr;
    sqe->len = len;
    sqe->user_data = (uint64_t)(uintptr_t)op;
    return op;
}

cv_uring_op *cv_uring_recv(cv_uring *r, uintptr_t waiter, int fd, void *buf, size_t len, uint64_t *gen) {
    if (len > 0x7ffff000) len = 0x7ffff000;
    cv_uring_op *op = submit_op(r, waiter, gen, IORING_OP_RECV, fd, (uintptr_t)buf, (uint32_t)len);
    // A task reads when it has handled what came before, so the socket is
    // usually empty: arm the poll first instead of a recv that fails.
    r->sqes[r->sq_tail & r->sq_mask].ioprio = IORING_RECVSEND_POLL_FIRST;
    push_sqe(r);
    return op;
}

cv_uring_op *cv_uring_recv_stamped(cv_uring *r, uintptr_t waiter, int fd, void *buf, size_t len,
                                   cv_arrival *arrival, uint64_t *gen) {
    if (len > 0x7ffff000) len = 0x7ffff000;
    struct msghdr *mh = arrival_prepare(arrival, buf, len);
    cv_uring_op *op = submit_op(r, waiter, gen, IORING_OP_RECVMSG, fd, (uintptr_t)mh, 1);
    // As cv_uring_recv: the socket is usually empty when a task reads.
    r->sqes[r->sq_tail & r->sq_mask].ioprio = IORING_RECVSEND_POLL_FIRST;
    push_sqe(r);
    return op;
}

cv_uring_op *cv_uring_accept(cv_uring *r, uintptr_t waiter, int fd, uint64_t *gen) {
    cv_uring_op *op = submit_op(r, waiter, gen, IORING_OP_ACCEPT, fd, 0, 0);
    r->sqes[r->sq_tail & r->sq_mask].accept_flags = SOCK_NONBLOCK | SOCK_CLOEXEC;
    push_sqe(r);
    return op;
}

cv_uring_op *cv_uring_poll_ready(cv_uring *r, uintptr_t waiter, int fd, int dir, uint64_t *gen) {
    cv_uring_op *op = submit_op(r, waiter, gen, IORING_OP_POLL_ADD, fd, 0, 0);
    // HUP and ERR are always reported: a closed or failed socket is "ready"
    // and the retried syscall says how.
    r->sqes[r->sq_tail & r->sq_mask].poll32_events = dir == CV_IO_READ ? POLLIN | POLLRDHUP : POLLOUT;
    push_sqe(r);
    return op;
}

cv_uring_op *cv_uring_file_rw(cv_uring *r, uintptr_t waiter, int write, int fd, void *buf, size_t len,
                              int64_t offset, uint64_t *gen) {
    if (len > 0x7ffff000) len = 0x7ffff000;
    cv_uring_op *op = submit_op(r, waiter, gen, write ? IORING_OP_WRITE : IORING_OP_READ, fd,
                                (uintptr_t)buf, (uint32_t)len);
    // -1 (all ones) reads or writes at the file position and advances it.
    r->sqes[r->sq_tail & r->sq_mask].off = (uint64_t)offset;
    push_sqe(r);
    return op;
}

cv_uring_op *cv_uring_fsync(cv_uring *r, uintptr_t waiter, int fd, int datasync, uint64_t *gen) {
    cv_uring_op *op = submit_op(r, waiter, gen, IORING_OP_FSYNC, fd, 0, 0);
    if (datasync) r->sqes[r->sq_tail & r->sq_mask].fsync_flags = IORING_FSYNC_DATASYNC;
    push_sqe(r);
    return op;
}

cv_uring_op *cv_uring_openat(cv_uring *r, uintptr_t waiter, const char *path, int flags, unsigned mode,
                             uint64_t *gen) {
    cv_uring_op *op = submit_op(r, waiter, gen, IORING_OP_OPENAT, AT_FDCWD, (uintptr_t)path, mode);
    r->sqes[r->sq_tail & r->sq_mask].open_flags = (uint32_t)flags;
    push_sqe(r);
    return op;
}

void cv_uring_cancel(cv_uring_op *op, uint64_t gen) {
    uint64_t expected = gen << 3 | OP_PENDING;
    if (!atomic_compare_exchange_strong_explicit(&op->state, &expected, gen << 3 | OP_CANCEL_REQ,
                                                 memory_order_acq_rel, memory_order_relaxed))
        return; // completed, or not this operation any more
    cv_uring *r = op->ring;
    cv_uring_op *head = atomic_load_explicit(&r->cancels, memory_order_relaxed);
    do {
        atomic_store_explicit(&op->next_cancel, head, memory_order_relaxed);
    } while (!atomic_compare_exchange_weak_explicit(&r->cancels, &head, op, memory_order_release,
                                                    memory_order_relaxed));
    cv_unpark(r->parker);
}

static inline void add_wake(cv_uring *r, uintptr_t waiter, int64_t res) {
    r->wakes[r->nwakes].waiter = waiter;
    r->wakes[r->nwakes].res = res;
    r->nwakes++;
}

static void complete(cv_uring *r, cv_uring_op *op, int64_t res) {
    uint64_t s = atomic_load_explicit(&op->state, memory_order_acquire);
    for (;;) {
        if ((s & 7) == OP_CANCEL_REQ) {
            // On the cancel list: whoever drains it resumes the waiter, so
            // the slot isn't reused while the list still names it. Only the
            // canceller's CAS from PENDING writes here otherwise.
            op->res = res;
            atomic_store_explicit(&op->state, (s & ~(uint64_t)7) | OP_DONE_DEFERRED, memory_order_release);
            return;
        }
        // PENDING or CANCEL_SENT: done. The CAS fences off a late canceller.
        uint64_t freed = ((s >> 3) + 1) << 3 | OP_FREE;
        if (atomic_compare_exchange_weak_explicit(&op->state, &s, freed, memory_order_acq_rel,
                                                  memory_order_acquire)) {
            add_wake(r, op->waiter, res);
            op->next_free = r->free;
            r->free = op;
            return;
        }
    }
}

/// Take the cancel requests: submit an ASYNC_CANCEL for each operation still
/// in flight, resume the ones that completed meanwhile.
static void drain_cancels(cv_uring *r) {
    if (!atomic_load_explicit(&r->cancels, memory_order_relaxed)) return;
    cv_uring_op *op = atomic_exchange_explicit(&r->cancels, NULL, memory_order_acquire);
    int submitted = 0;
    while (op) {
        cv_uring_op *next = atomic_load_explicit(&op->next_cancel, memory_order_relaxed);
        uint64_t s = atomic_load_explicit(&op->state, memory_order_acquire);
        if ((s & 7) == OP_DONE_DEFERRED) {
            if (r->nwakes == 2 * CV_URING_BATCH) {
                // No room this turn: back on the list for the next.
                cv_uring_op *head = atomic_load_explicit(&r->cancels, memory_order_relaxed);
                do {
                    atomic_store_explicit(&op->next_cancel, head, memory_order_relaxed);
                } while (!atomic_compare_exchange_weak_explicit(&r->cancels, &head, op,
                                                                memory_order_release,
                                                                memory_order_relaxed));
            } else {
                add_wake(r, op->waiter, op->res);
                op_free(r, op, s);
            }
        } else {
            struct io_uring_sqe *sqe = get_sqe(r);
            sqe->opcode = IORING_OP_ASYNC_CANCEL;
            sqe->fd = -1;
            sqe->addr = (uint64_t)(uintptr_t)op;
            sqe->user_data = TAG_CANCEL;
            push_sqe(r);
            atomic_store_explicit(&op->state, (s & ~(uint64_t)7) | OP_CANCEL_SENT, memory_order_relaxed);
            submitted = 1;
        }
        op = next;
    }
    // Submit now: the slot must not be reaped and reused while the cancel
    // naming it still sits in our queue.
    if (submitted) enter(r, 0, 0);
}

static int reap(cv_uring *r) {
    r->nwakes = 0;
    unsigned head = atomic_load_explicit(r->cq_khead, memory_order_relaxed);
    unsigned tail = atomic_load_explicit(r->cq_ktail, memory_order_acquire);
    unsigned seen = 0;
    while (head != tail && seen < CV_URING_BATCH) {
        struct io_uring_cqe *cqe = &r->cqes[head & r->cq_mask];
        uint64_t ud = cqe->user_data;
        int64_t res = cqe->res;
        head++;
        seen++;
        if (ud == TAG_FUTEX) {
            r->futex_armed = 0;
        } else if (ud != TAG_CANCEL) {
            complete(r, (cv_uring_op *)(uintptr_t)ud, res);
        }
    }
    atomic_store_explicit(r->cq_khead, head, memory_order_release);
    r->stats.events += seen;
    if (seen == CV_URING_BATCH) r->stats.full_batches++;
    drain_cancels(r);
    r->stats.wakes += (uint64_t)r->nwakes;
    return r->nwakes;
}

int cv_uring_poll(cv_uring *r) {
    int work = sq_pending(r) != 0 || taskrun_pending(r);
    if (!work && !cq_ready(r) && !atomic_load_explicit(&r->cancels, memory_order_relaxed)) return 0;
    if (work) enter(r, 0, 0);
    r->stats.busy_turns++;
    return reap(r);
}

static inline int has_work(cv_uring *r) {
    return cq_ready(r) || taskrun_pending(r) || atomic_load_explicit(&r->cancels, memory_order_relaxed);
}

int cv_uring_park(cv_uring *r, int64_t timeout_ns, int64_t spin_ns) {
    cv_parker *p = r->parker;
    r->stats.parked_turns++;
    // Our own submissions first: their results may be what we wait for.
    if (sq_pending(r) || taskrun_pending(r)) enter(r, 0, 0);
    if (cq_ready(r) || atomic_load_explicit(&r->cancels, memory_order_relaxed)) {
        int n = reap(r);
        if (n > 0) return n;
    }
    uint32_t expected = NOTIFIED;
    if (atomic_compare_exchange_strong(&p->state, &expected, EMPTY)) return 0; // caller rechecks
    if (timeout_ns == 0) return 0;

    if (spin_ns > 0) {
        // As cv_park_spin: an unpark now is a plain store. Completions for
        // our ring end the spin too.
        if (timeout_ns > 0 && timeout_ns < spin_ns) spin_ns = timeout_ns;
        uint64_t start = cv_now_ns();
        for (uint32_t i = 1;; i++) {
            cpu_relax();
            if (atomic_load_explicit(&p->state, memory_order_relaxed) == NOTIFIED) {
                expected = NOTIFIED;
                atomic_compare_exchange_strong(&p->state, &expected, EMPTY);
                return 0;
            }
            if (has_work(r)) {
                if (taskrun_pending(r)) enter(r, 0, 0);
                return reap(r);
            }
            if ((i & 63) == 0) {
                uint64_t spent = cv_now_ns() - start;
                if (spent >= (uint64_t)spin_ns) {
                    if (timeout_ns > 0) {
                        timeout_ns -= (int64_t)spent;
                        if (timeout_ns <= 0) return 0;
                    }
                    break;
                }
            }
        }
    }

    expected = EMPTY;
    if (!atomic_compare_exchange_strong(&p->state, &expected, PARKED)) {
        atomic_store(&p->state, EMPTY); // notified meanwhile
        return 0;
    }
    if (!r->futex_armed) {
        // Completes when cv_unpark wakes the parker's word, or at once if it
        // isn't PARKED any more by the time the kernel looks.
        struct io_uring_sqe *sqe = get_sqe(r);
        sqe->opcode = IORING_OP_FUTEX_WAIT;
        sqe->fd = FUTEX2_SIZE_U32 | FUTEX2_PRIVATE;
        sqe->addr = (uint64_t)(uintptr_t)&p->state;
        sqe->off = PARKED;
        sqe->addr3 = FUTEX_BITSET_MATCH_ANY;
        sqe->user_data = TAG_FUTEX;
        push_sqe(r);
        r->futex_armed = 1;
    }
    enter(r, 1, timeout_ns);
    // Consumes a racing notify, as cv_park does: the caller rechecks.
    atomic_store(&p->state, EMPTY);
    return reap(r);
}

cv_uring_wake *cv_uring_wakes(cv_uring *r) { return r->wakes; }

cv_driver_stats cv_uring_get_stats(cv_uring *r) { return r->stats; }

#else

int cv_uring_probe(void) { return ENOSYS; }

#endif

// Used by every driver's socket code, so outside the Linux block.
int cv_count_load(int *count) { return __atomic_load_n(count, __ATOMIC_ACQUIRE); }

cv_io *cv_uring_io_new(int fd, int *count) {
    cv_io *io = calloc(1, sizeof *io);
    if (!io) return NULL;
    io->count = count;
    __atomic_add_fetch(count, 1, __ATOMIC_RELAXED);
    io->fd = fd;
    io->refs = 1;
    return io;
}

void cv_uring_io_release(cv_io *io) {
    if (__atomic_sub_fetch(&io->refs, 1, __ATOMIC_ACQ_REL) != 0) return; // the other half has it
    int *count = io->count;
    close(io->fd);
    free(io);
    __atomic_sub_fetch(count, 1, __ATOMIC_RELEASE);
}

void cv_tcp_accepted(int fd) {
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
}

// ---- signals -------------------------------------------------------------
// Tokio's self-pipe: the handler counts the signal and writes a byte to a
// pipe, which a dispatcher thread drains (cv_signal_wait). No signal has to
// be blocked anywhere, and no driver is involved. The dispatcher unblocks the
// installed signals on its own thread, so one sent to the process lands
// somewhere even if every other thread has them blocked: on Darwin, dispatch
// threads block all signals, and threads they start inherit that mask.

#define CV_NSIG 65
static _Atomic uint64_t sig_count[CV_NSIG];
static _Atomic int sig_installed[CV_NSIG];
static int sig_pipe[2] = {-1, -1};
static pthread_mutex_t sig_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t sig_thread;
static _Atomic int sig_thread_known;

static void sig_handler(int signo) {
    int saved = errno;
    if (signo > 0 && signo < CV_NSIG) atomic_fetch_add(&sig_count[signo], 1);
    char b = 0;
    ssize_t r = write(sig_pipe[1], &b, 1); // full pipe: a wake is pending anyway
    (void)r;
    errno = saved;
}

static int sig_open_pipe(void) {
    int fds[2];
    if (pipe(fds) != 0) return errno;
    for (int i = 0; i < 2; i++) fcntl(fds[i], F_SETFD, FD_CLOEXEC);
    fcntl(fds[1], F_SETFL, fcntl(fds[1], F_GETFL) | O_NONBLOCK);
    sig_pipe[0] = fds[0];
    sig_pipe[1] = fds[1];
    return 0;
}

int cv_signal_install(int signo) {
    if (signo <= 0 || signo >= CV_NSIG || signo >= NSIG) return EINVAL;
    switch (signo) {
    case SIGILL: case SIGFPE: case SIGKILL: case SIGSEGV: case SIGSTOP:
        return EINVAL; // as Tokio: uncatchable, or no way to go on after
    default: break;
    }
    if (atomic_load(&sig_installed[signo])) return 0;
    pthread_mutex_lock(&sig_mutex);
    int rc = 0;
    if (sig_pipe[0] < 0) rc = sig_open_pipe();
    if (rc == 0 && !atomic_load(&sig_installed[signo])) {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = sig_handler;
        sa.sa_flags = SA_RESTART;
        sigemptyset(&sa.sa_mask);
        if (sigaction(signo, &sa, NULL) != 0) rc = errno;
        else {
            atomic_store(&sig_installed[signo], 1);
            char b = 0; // have the dispatcher unblock it
            ssize_t r = write(sig_pipe[1], &b, 1);
            (void)r;
        }
    }
    pthread_mutex_unlock(&sig_mutex);
    return rc;
}

uint64_t cv_signal_count(int signo) {
    return signo > 0 && signo < CV_NSIG ? atomic_load(&sig_count[signo]) : 0;
}

int cv_signal_raise(int signo) {
    while (!atomic_load(&sig_thread_known)) usleep(1000);
    return pthread_kill(sig_thread, signo);
}

void cv_signal_wait(void) {
    char buf[64];
    int fd;
    sigset_t set;
    sigemptyset(&set);
    if (!atomic_load(&sig_thread_known)) {
        sig_thread = pthread_self();
        atomic_store(&sig_thread_known, 1);
    }
    pthread_mutex_lock(&sig_mutex);
    fd = sig_pipe[0];
    for (int i = 1; i < CV_NSIG && i < NSIG; i++)
        if (atomic_load(&sig_installed[i])) sigaddset(&set, i);
    pthread_mutex_unlock(&sig_mutex);
    pthread_sigmask(SIG_UNBLOCK, &set, NULL);
#ifdef CV_TSAN
    // TSan's own handler only queues ours until this thread's next
    // intercepted call, and SA_RESTART keeps a blocked read from returning:
    // come up every 10 ms so a queued signal is handled.
    struct pollfd p = {.fd = fd, .events = POLLIN};
    if (poll(&p, 1, 10) <= 0) return;
#endif
    ssize_t r = read(fd, buf, sizeof buf); // EINTR too: the caller looks anyway
    (void)r;
}

#endif // !_WIN32

// ---- ThreadSanitizer -----------------------------------------------------

#ifdef CV_TSAN
void __tsan_acquire(void *addr);
void cv_tsan_acquire(const void *addr) { __tsan_acquire((void *)addr); }
#else
void cv_tsan_acquire(const void *addr) { (void)addr; }
#endif
