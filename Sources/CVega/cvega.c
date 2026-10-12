#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "cvega.h"

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
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#include <linux/futex.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#elif defined(__APPLE__)
#include <mach/mach_time.h>
#include <os/os_sync_wait_on_address.h>
#endif

__thread void *cv_current_tls;

uint64_t cv_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

int cv_cpu_count(void) {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? (int)n : 1;
}

// ---- parker --------------------------------------------------------------

// PARKED_IO: blocked in the I/O driver, woken through its eventfd.
enum { EMPTY = 0, PARKED = 1, NOTIFIED = 2, PARKED_IO = 3 };

struct cv_parker {
    _Atomic uint32_t state;
    int wake_fd; // the driver's eventfd, or -1
    char pad[120]; // own cache line pair: parkers are hit from other threads
};

cv_parker *cv_parker_new(void) {
    cv_parker *p = aligned_alloc(128, sizeof(cv_parker));
    if (!p) abort();
    atomic_init(&p->state, EMPTY);
    p->wake_fd = -1;
    return p;
}

void cv_parker_free(cv_parker *p) { free(p); }

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
    else {
        static mach_timebase_info_data_t tb;
        if (tb.denom == 0) mach_timebase_info(&tb); // racy but idempotent
        uint64_t ticks = (uint64_t)timeout_ns * tb.denom / tb.numer;
        os_sync_wait_on_address_with_timeout((void *)addr, expected, 4, OS_SYNC_WAIT_ON_ADDRESS_NONE,
                                             OS_CLOCK_MACH_ABSOLUTE_TIME, ticks);
    }
#else
#error "cv_park: unsupported platform"
#endif
}

static void wake_one(_Atomic uint32_t *addr) {
#if defined(__linux__)
    syscall(SYS_futex, (uint32_t *)addr, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);
#elif defined(__APPLE__)
    os_sync_wake_by_address_any((void *)addr, 4, OS_SYNC_WAKE_BY_ADDRESS_NONE);
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

void cv_unpark(cv_parker *p) {
    uint32_t old = atomic_exchange(&p->state, NOTIFIED);
    if (old == PARKED) {
        wake_one(&p->state);
    } else if (old == PARKED_IO) {
        uint64_t one = 1;
        ssize_t r = write(p->wake_fd, &one, sizeof one);
        (void)r; // EAGAIN only if the counter is saturated: a wake is pending anyway
    }
}

// ---- lock ----------------------------------------------------------------

cv_lock *cv_lock_new(void) {
    // A cache line of its own: the word is written by every locker.
    cv_lock *l = aligned_alloc(128, 128);
    if (!l) abort();
    __atomic_store_n(&l->state, 0, __ATOMIC_RELAXED);
    return l;
}

void cv_lock_free(cv_lock *l) { free(l); }

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

// ---- I/O driver ----------------------------------------------------------

#if defined(__linux__)

#define CV_MAX_EVENTS 1024 // as Tokio: fewer ready sockets left for the next poll

struct cv_driver {
    _Atomic uint32_t locked; // polled by one thread at a time
    char pad0[124];
    _Atomic int registered;
    _Atomic(cv_io *) released; // deregistered, freed by the next turn
    char pad1[112];
    int epfd;
    int wake_fd;
    // Used only by the lock holder.
    cv_driver_stats stats;
    struct epoll_event events[CV_MAX_EVENTS];
    uintptr_t wakes[2 * CV_MAX_EVENTS];
};

cv_driver *cv_driver_new(void) {
    cv_driver *d = aligned_alloc(128, (sizeof(cv_driver) + 127) & ~(size_t)127);
    if (!d) return NULL;
    memset(d, 0, sizeof *d);
    d->epfd = epoll_create1(EPOLL_CLOEXEC);
    d->wake_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (d->epfd < 0 || d->wake_fd < 0) goto fail;
    // data.ptr == NULL marks the eventfd.
    struct epoll_event ev = {.events = EPOLLIN | EPOLLET, .data.ptr = NULL};
    if (epoll_ctl(d->epfd, EPOLL_CTL_ADD, d->wake_fd, &ev) != 0) goto fail;
    return d;
fail: {
    int e = errno;
    if (d->epfd >= 0) close(d->epfd);
    if (d->wake_fd >= 0) close(d->wake_fd);
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
    close(d->epfd);
    close(d->wake_fd);
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
#ifdef SYS_epoll_pwait2
    static _Atomic int no_pwait2;
    if (!atomic_load_explicit(&no_pwait2, memory_order_relaxed)) {
        struct timespec ts, *tp = NULL;
        if (timeout_ns >= 0) {
            ts.tv_sec = (time_t)(timeout_ns / 1000000000);
            ts.tv_nsec = (long)(timeout_ns % 1000000000);
            tp = &ts;
        }
        long n = syscall(SYS_epoll_pwait2, d->epfd, d->events, CV_MAX_EVENTS, tp, NULL, 0);
        if (n >= 0 || errno != ENOSYS) return (int)n;
        atomic_store_explicit(&no_pwait2, 1, memory_order_relaxed);
    }
#endif
    // Milliseconds, rounded up so a timer is never polled for early.
    int ms = timeout_ns < 0 ? -1 : (int)((timeout_ns + 999999) / 1000000);
    return epoll_wait(d->epfd, d->events, CV_MAX_EVENTS, ms);
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
        cv_io *io = d->events[i].data.ptr;
        uint32_t e = d->events[i].events;
        if (!io) {
            uint64_t v;
            ssize_t r = read(d->wake_fd, &v, sizeof v);
            (void)r;
            continue;
        }
        uintptr_t w;
        // Before io_ready, whose CAS publishes it to the task it wakes.
        if (e & (EPOLLRDHUP | EPOLLHUP | EPOLLERR))
            __atomic_store_n(&io->read_closed, 1, __ATOMIC_RELEASE);
        if ((e & (EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR)) && (w = io_ready(io, CV_IO_READ)))
            d->wakes[woken++] = w;
        if ((e & (EPOLLOUT | EPOLLHUP | EPOLLERR)) && (w = io_ready(io, CV_IO_WRITE)))
            d->wakes[woken++] = w;
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
    struct epoll_event ev = {.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET, .data.ptr = io};
    if (epoll_ctl(d->epfd, EPOLL_CTL_ADD, fd, &ev) != 0) {
        *err = errno;
        free(io);
        return NULL;
    }
    atomic_fetch_add_explicit(&d->registered, 1, memory_order_relaxed);
    return io;
}

void cv_driver_deregister(cv_driver *d, cv_io *io) {
    if (__atomic_sub_fetch(&io->refs, 1, __ATOMIC_ACQ_REL) != 0) return; // the other half has it
    epoll_ctl(d->epfd, EPOLL_CTL_DEL, io->fd, NULL);
    close(io->fd);
    atomic_fetch_sub_explicit(&d->registered, 1, memory_order_relaxed);
    cv_io *head = atomic_load_explicit(&d->released, memory_order_relaxed);
    do {
        io->next = head;
    } while (!atomic_compare_exchange_weak_explicit(&d->released, &head, io,
                                                    memory_order_release, memory_order_relaxed));
}

#else // no driver on this platform yet (kqueue is next)

cv_driver *cv_driver_new(void) {
    errno = ENOSYS;
    return NULL;
}
void cv_driver_free(cv_driver *d) { (void)d; }

#endif

// ---- sockets -------------------------------------------------------------

static int set_nonblocking_cloexec(int fd) {
    int fl = fcntl(fd, F_GETFL);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) return -1;
    return fcntl(fd, F_SETFD, FD_CLOEXEC);
}

static int new_socket(int family, int type) {
#if defined(__linux__)
    return socket(family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
#else
    int fd = socket(family, type, 0);
    if (fd >= 0 && set_nonblocking_cloexec(fd) != 0) {
        close(fd);
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
        if (bind(fd, a->ai_addr, a->ai_addrlen) == 0 && listen(fd, backlog) == 0) {
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

int cv_tcp_connect(const char *host, int port, int *err) {
    struct addrinfo *res = resolve(host, port, 0, SOCK_STREAM, err);
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
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        if (connect(fd, a->ai_addr, a->ai_addrlen) == 0) {
            *err = 0;
            break;
        }
        if (errno == EINPROGRESS) {
            *err = EINPROGRESS;
            break;
        }
        *err = errno;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static int accept_nb(int fd, int *err) {
#if defined(__linux__)
    int c = accept4(fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
#else
    int c = accept(fd, NULL, NULL);
    if (c >= 0 && set_nonblocking_cloexec(c) != 0) {
        close(c);
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

int cv_resolve(const char *host, int port, cv_sockaddr *out) {
    int err = 0;
    struct addrinfo *res = resolve(host, port, 0, SOCK_STREAM, &err);
    if (!res) return err;
    memcpy(out->storage, res->ai_addr, res->ai_addrlen);
    out->len = (uint32_t)res->ai_addrlen;
    freeaddrinfo(res);
    return 0;
}

int cv_sockaddr_family(const cv_sockaddr *a) {
    return ((const struct sockaddr *)a->storage)->sa_family;
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

int cv_local_port(int fd) {
    cv_sockaddr a;
    return cv_local_address(fd, &a) == 0 ? cv_sockaddr_port(&a) : -1;
}

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0 // Darwin: SO_NOSIGPIPE instead (with the kqueue driver)
#endif

long cv_recv(int fd, void *buf, long len) {
    ssize_t n = recv(fd, buf, (size_t)len, 0);
    return n >= 0 ? (long)n : -(long)errno;
}

long cv_send(int fd, const void *buf, long len) {
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

int cv_udp_connect(const char *host, int port, int *err) {
    struct addrinfo *res = resolve(host, port, 0, SOCK_DGRAM, err);
    if (!res) return -1;
    int fd = -1;
    *err = EADDRNOTAVAIL;
    for (struct addrinfo *a = res; a; a = a->ai_next) {
        fd = new_socket(a->ai_family, SOCK_DGRAM);
        if (fd < 0) {
            *err = errno;
            continue;
        }
        // A datagram connect only records the peer: it never blocks.
        if (connect(fd, a->ai_addr, a->ai_addrlen) == 0) {
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

long cv_sendto(int fd, const void *buf, long len, const cv_sockaddr *to) {
    ssize_t n = sendto(fd, buf, (size_t)len, MSG_NOSIGNAL, (const struct sockaddr *)to->storage,
                       (socklen_t)to->len);
    return n >= 0 ? (long)n : -(long)errno;
}

long cv_recvfrom(int fd, void *buf, long len, cv_sockaddr *from) {
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
    if (set_nonblocking_cloexec(fds[0]) != 0 || set_nonblocking_cloexec(fds[1]) != 0) {
        int e = errno;
        close(fds[0]);
        close(fds[1]);
        return e;
    }
#endif
    return 0;
}

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
    enqueue_hook *slot = (enqueue_hook *)dlsym(RTLD_DEFAULT, "swift_task_enqueueGlobal_hook");
    if (!slot) return -1;
    enqueue_fn = fn;
    enqueue_ctx = ctx;
    __atomic_store_n(slot, enqueue_global, __ATOMIC_RELEASE);
    return 0;
}
