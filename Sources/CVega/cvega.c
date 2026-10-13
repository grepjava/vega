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
#include <sys/event.h>
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

// PARKED_IO: blocked in the I/O driver, woken through it (an eventfd write
// on Linux, an EVFILT_USER trigger on Darwin).
enum { EMPTY = 0, PARKED = 1, NOTIFIED = 2, PARKED_IO = 3 };

struct cv_parker {
    _Atomic uint32_t state;
    int wake_fd; // the driver's eventfd (Linux) or kqueue (Darwin), or -1
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
    else if (timeout_ns > 0) // the timeout is in nanoseconds; 0 is an error
        os_sync_wait_on_address_with_timeout((void *)addr, expected, 4, OS_SYNC_WAIT_ON_ADDRESS_NONE,
                                             OS_CLOCK_MACH_ABSOLUTE_TIME, (uint64_t)timeout_ns);
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

/// Interrupt a turn blocked in the driver whose wake fd is `fd`.
static void driver_wake(int fd) {
#if defined(__linux__)
    uint64_t one = 1;
    ssize_t r = write(fd, &one, sizeof one);
    (void)r; // EAGAIN only if the counter is saturated: a wake is pending anyway
#elif defined(__APPLE__)
    struct kevent ev;
    EV_SET(&ev, 0, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
    kevent(fd, &ev, 1, NULL, 0, NULL);
#else
    (void)fd;
#endif
}

void cv_unpark(cv_parker *p) {
    uint32_t old = atomic_exchange(&p->state, NOTIFIED);
    if (old == PARKED) {
        wake_one(&p->state);
    } else if (old == PARKED_IO) {
        driver_wake(p->wake_fd);
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

#else // no driver on this platform yet

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
#define MSG_NOSIGNAL 0 // Darwin: SO_NOSIGPIPE, set on every socket by prepare_fd
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
    if (prepare_fd(fds[0]) != 0 || prepare_fd(fds[1]) != 0) {
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
    case CV_OPT_REUSEADDR: case CV_OPT_REUSEPORT: case CV_OPT_BROADCAST:
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

long cv_sendv(int fd, const cv_iovec *iov, int count) {
    struct msghdr mh = {0};
    mh.msg_iov = (struct iovec *)iov;
    mh.msg_iovlen = count;
    ssize_t n = sendmsg(fd, &mh, MSG_NOSIGNAL);
    return n >= 0 ? (long)n : -(long)errno;
}

enum { CV_BATCH_CHUNK = 64 };

long cv_recv_batch(int fd, void *base, long stride, int count, cv_sockaddr *from,
                   uint32_t *lens, uint32_t *flags) {
#if defined(__linux__)
    if (count > CV_BATCH_CHUNK) count = CV_BATCH_CHUNK;
    struct mmsghdr hdrs[CV_BATCH_CHUNK];
    struct iovec iov[CV_BATCH_CHUNK];
    memset(hdrs, 0, sizeof hdrs[0] * (size_t)count);
    for (int i = 0; i < count; i++) {
        iov[i].iov_base = (char *)base + (size_t)i * (size_t)stride;
        iov[i].iov_len = (size_t)stride;
        hdrs[i].msg_hdr.msg_name = from[i].storage;
        hdrs[i].msg_hdr.msg_namelen = sizeof from[i].storage;
        hdrs[i].msg_hdr.msg_iov = &iov[i];
        hdrs[i].msg_hdr.msg_iovlen = 1;
    }
    int n = recvmmsg(fd, hdrs, (unsigned)count, 0, NULL);
    if (n < 0) return -(long)errno;
    for (int i = 0; i < n; i++) {
        from[i].len = hdrs[i].msg_hdr.msg_namelen;
        lens[i] = hdrs[i].msg_len;
        flags[i] = (hdrs[i].msg_hdr.msg_flags & MSG_TRUNC) ? CV_DGRAM_TRUNCATED : 0;
    }
    return n;
#else
    int got = 0;
    for (; got < count; got++) {
        struct iovec v = {(char *)base + (size_t)got * (size_t)stride, (size_t)stride};
        struct msghdr mh = {0};
        mh.msg_name = from[got].storage;
        mh.msg_namelen = sizeof from[got].storage;
        mh.msg_iov = &v;
        mh.msg_iovlen = 1;
        ssize_t n = recvmsg(fd, &mh, 0);
        if (n < 0) {
            if (got > 0) break;
            return -(long)errno;
        }
        from[got].len = mh.msg_namelen;
        lens[got] = (uint32_t)n;
        flags[got] = (mh.msg_flags & MSG_TRUNC) ? CV_DGRAM_TRUNCATED : 0;
    }
    return got;
#endif
}

long cv_send_batch(int fd, const void *base, long stride, const uint32_t *lens,
                   const cv_sockaddr *to, int count) {
#if defined(__linux__)
    if (count > CV_BATCH_CHUNK) count = CV_BATCH_CHUNK;
    struct mmsghdr hdrs[CV_BATCH_CHUNK];
    struct iovec iov[CV_BATCH_CHUNK];
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
    }
    int n = sendmmsg(fd, hdrs, (unsigned)count, MSG_NOSIGNAL);
    return n >= 0 ? (long)n : -(long)errno;
#else
    int sent = 0;
    for (; sent < count; sent++) {
        const char *p = (const char *)base + (size_t)sent * (size_t)stride;
        ssize_t n = to && to[sent].len
            ? sendto(fd, p, lens[sent], MSG_NOSIGNAL, (const struct sockaddr *)to[sent].storage,
                     (socklen_t)to[sent].len)
            : send(fd, p, lens[sent], MSG_NOSIGNAL);
        if (n < 0) {
            if (sent > 0) break;
            return -(long)errno;
        }
    }
    return sent;
#endif
}

long cv_send_segments_split(int fd, const void *buf, long len, int segment, const cv_sockaddr *to) {
    // The segments already lie back to back, segment bytes apart: send them
    // as a batch over the same memory, one datagram each.
    if (segment <= 0 || len <= segment) segment = len > 0 ? (int)len : 1;
    int have_to = to && to->len;
    uint32_t lens[CV_BATCH_CHUNK];
    cv_sockaddr tos[CV_BATCH_CHUNK];
    long done = 0;
    do {
        int k = 0;
        for (long off = done; k < CV_BATCH_CHUNK && (off < len || (len == 0 && k == 0)); k++) {
            long l = len - off < segment ? len - off : segment;
            lens[k] = (uint32_t)l;
            off += l;
            if (have_to) tos[k] = *to;
        }
        long n = cv_send_batch(fd, (const char *)buf + done, segment, lens, have_to ? tos : NULL, k);
        if (n < 0) return done > 0 ? done : n; // the next call reports the error
        for (long i = 0; i < n; i++) done += lens[i];
        if (n < k) break; // the socket filled up: whole segments sent so far
    } while (done < len);
    return done;
}

long cv_send_segments(int fd, const void *buf, long len, int segment, const cv_sockaddr *to) {
#if defined(__linux__)
    if (segment <= 0 || len <= segment)
        return cv_send_segments_split(fd, buf, len, segment, to);
    // Whether the kernel knows UDP_SEGMENT (4.18+): the same for every
    // socket, so asked once. An older kernel ignores the cmsg and would
    // send one large datagram instead.
    static _Atomic int gso; // 0 unknown, 1 yes, -1 no
    int known = atomic_load_explicit(&gso, memory_order_relaxed);
    if (known == 0) {
        known = cv_udp_gso_supported(fd) ? 1 : -1;
        atomic_store_explicit(&gso, known, memory_order_relaxed);
    }
    if (known < 0) return cv_send_segments_split(fd, buf, len, segment, to);

    struct iovec v = {(void *)buf, (size_t)len};
    struct msghdr mh = {0};
    if (to && to->len) {
        mh.msg_name = (void *)to->storage;
        mh.msg_namelen = to->len;
    }
    mh.msg_iov = &v;
    mh.msg_iovlen = 1;
    union {
        char buf[CMSG_SPACE(sizeof(uint16_t))];
        struct cmsghdr align;
    } control;
    memset(&control, 0, sizeof control);
    mh.msg_control = control.buf;
    mh.msg_controllen = sizeof control.buf;
    struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
    cm->cmsg_level = SOL_UDP;
    cm->cmsg_type = UDP_SEGMENT;
    cm->cmsg_len = CMSG_LEN(sizeof(uint16_t));
    uint16_t seg = (uint16_t)segment;
    memcpy(CMSG_DATA(cm), &seg, sizeof seg);
    ssize_t n = sendmsg(fd, &mh, MSG_NOSIGNAL);
    if (n >= 0) return (long)n;
    // EIO: this route can't offload the checksum (IPsec, for one).
    if (errno == EIO || errno == EOPNOTSUPP || errno == ENOPROTOOPT)
        return cv_send_segments_split(fd, buf, len, segment, to);
    return -(long)errno;
#else
    return cv_send_segments_split(fd, buf, len, segment, to);
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

long cv_recv_segments(int fd, void *buf, long len, cv_sockaddr *from, int *segment,
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

// ---- ThreadSanitizer -----------------------------------------------------

#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define CV_TSAN 1
#endif
#endif

#ifdef CV_TSAN
void __tsan_acquire(void *addr);
void cv_tsan_acquire(const void *addr) { __tsan_acquire((void *)addr); }
#else
void cv_tsan_acquire(const void *addr) { (void)addr; }
#endif
