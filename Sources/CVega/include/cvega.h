// CVega: the few things Swift can't do directly or cheaply — futex parking,
// a thread-local that inlines into Swift, named/pinned threads, a raw clock.
#ifndef CVEGA_H
#define CVEGA_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---- current worker (thread-local) -------------------------------------
// static inline so the read inlines into Swift callers: no call, one TLS load.
extern __thread void *cv_current_tls;
static inline void *cv_current_get(void) { return cv_current_tls; }
static inline void cv_current_set(void *worker) { cv_current_tls = worker; }

// ---- clock ---------------------------------------------------------------
/// CLOCK_MONOTONIC in nanoseconds (same base as Swift's ContinuousClock on Linux).
uint64_t cv_now_ns(void);
/// Online CPUs.
int cv_cpu_count(void);

// ---- parker --------------------------------------------------------------
// One per worker thread. unpark before park makes the next park return at
// once (the notification is sticky), so a wake-up is never lost.
typedef struct cv_parker cv_parker;
cv_parker *cv_parker_new(void);
void cv_parker_free(cv_parker *p);
/// Block until unparked, or until timeout_ns elapses (timeout_ns < 0: forever).
void cv_park(cv_parker *p, int64_t timeout_ns);
/// As cv_park, but first spin for up to spin_ns waiting for an unpark, so a
/// wake that comes soon costs neither side a syscall.
void cv_park_spin(cv_parker *p, int64_t timeout_ns, int64_t spin_ns);
void cv_unpark(cv_parker *p);

// ---- lock ----------------------------------------------------------------
// A futex word lock on its own cache line (the design of Rust's std Mutex):
// 0 unlocked, 1 locked, 2 locked with waiters. Locking uncontended is one
// CAS, unlocking one exchange, both inlined into Swift callers; only
// contention calls out (spin briefly, then sleep on the word). Used instead
// of Synchronization.Mutex because these atomics are compiled with the
// caller, so TSan sees them (Mutex's futex code is not instrumented), and the
// guarded state can live in raw memory with no ARC or exclusivity checks.
typedef struct cv_lock {
    uint32_t state; // only through __atomic builtins
} cv_lock;
cv_lock *cv_lock_new(void);
void cv_lock_free(cv_lock *l);
void cv_lock_lock_slow(cv_lock *l);
void cv_lock_wake(cv_lock *l);

static inline void cv_lock_lock(cv_lock *l) {
    uint32_t expected = 0;
    if (__builtin_expect(__atomic_compare_exchange_n(&l->state, &expected, 1, 0,
                                                     __ATOMIC_ACQUIRE, __ATOMIC_RELAXED), 1))
        return;
    cv_lock_lock_slow(l);
}

static inline void cv_lock_unlock(cv_lock *l) {
    if (__builtin_expect(__atomic_exchange_n(&l->state, 0, __ATOMIC_RELEASE) == 2, 0))
        cv_lock_wake(l);
}

// ---- threads -------------------------------------------------------------
typedef void (*cv_thread_fn)(void *arg);
/// Start a detached thread. cpu >= 0 pins it (Linux; ignored elsewhere).
/// Returns 0 or an errno value.
int cv_thread_spawn(cv_thread_fn fn, void *arg, const char *name, int cpu);

// ---- I/O driver (Linux: edge-triggered epoll) -----------------------------
// One per runtime, as in Tokio. Whichever parked worker owns the timers blocks
// in it; busy workers poll it with a zero timeout. A parker blocked in the
// driver is woken through the driver's eventfd instead of a futex.

/// One registered fd. Each direction has a slot: 0 idle, 1 ready (an event
/// came while nobody waited), or a waiting continuation's bits.
typedef struct cv_io {
    uintptr_t slot[2]; // only through __atomic builtins
    int fd;
    /// Set by the owning task after a short read: the socket is drained, so
    /// the next read waits for an event instead of a recv that says EAGAIN.
    int read_drained;
    /// Set for good by the driver once the peer closed or the socket failed
    /// (only through __atomic builtins). No edge follows that one, so a
    /// drained read must not wait for another: end of stream is pending.
    int read_closed;
    /// Owners: 1, or 2 once a stream is split into halves. The last one to
    /// let go unregisters (only through __atomic builtins).
    int refs;
    struct cv_io *next; // deferred-release list
} cv_io;

#define CV_IO_READ 0
#define CV_IO_WRITE 1
#define CV_IO_IDLE ((uintptr_t)0)
#define CV_IO_READY ((uintptr_t)1)

/// The task got EAGAIN and wants to wait: store `waiter` in the slot.
/// Returns 0 if armed, 1 if an event had already arrived (consumed: retry the
/// syscall instead of waiting).
static inline int cv_io_arm(cv_io *io, int dir, uintptr_t waiter) {
    uintptr_t cur = __atomic_load_n(&io->slot[dir], __ATOMIC_ACQUIRE);
    for (;;) {
        uintptr_t next = cur == CV_IO_READY ? CV_IO_IDLE : waiter;
        if (__atomic_compare_exchange_n(&io->slot[dir], &cur, next, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return next == CV_IO_IDLE;
    }
}

/// Take `waiter` back out of the slot. Returns 1 if it was still there (the
/// caller resumes it), 0 if the driver or a canceller already took it.
static inline int cv_io_disarm(cv_io *io, int dir, uintptr_t waiter) {
    return __atomic_compare_exchange_n(&io->slot[dir], &waiter, CV_IO_IDLE, 0,
                                       __ATOMIC_ACQ_REL, __ATOMIC_RELAXED);
}

/// Consume a READY left by an event that came while nobody waited.
/// Returns 1 if there was one.
static inline int cv_io_take_ready(cv_io *io, int dir) {
    uintptr_t ready = CV_IO_READY;
    return __atomic_load_n(&io->slot[dir], __ATOMIC_RELAXED) == CV_IO_READY &&
           __atomic_compare_exchange_n(&io->slot[dir], &ready, CV_IO_IDLE, 0,
                                       __ATOMIC_ACQ_REL, __ATOMIC_RELAXED);
}

/// Whether the driver has seen the read side close (see read_closed).
static inline int cv_io_read_closed(cv_io *io) {
    return __atomic_load_n(&io->read_closed, __ATOMIC_ACQUIRE);
}

/// Give the registration a second owner (a stream split into halves).
static inline void cv_io_split(cv_io *io) { __atomic_store_n(&io->refs, 2, __ATOMIC_RELAXED); }

/// Cancellation: take whatever waiter is in the slot, or 0 if none.
static inline uintptr_t cv_io_take_waiter(cv_io *io, int dir) {
    uintptr_t cur = __atomic_load_n(&io->slot[dir], __ATOMIC_ACQUIRE);
    while (cur > CV_IO_READY) {
        if (__atomic_compare_exchange_n(&io->slot[dir], &cur, CV_IO_IDLE, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return cur;
    }
    return 0;
}

typedef struct cv_driver cv_driver;
/// NULL on failure, with errno set (or where there is no driver yet).
cv_driver *cv_driver_new(void);
void cv_driver_free(cv_driver *d);
/// Route this parker's wakes through the driver while it is parked in it.
void cv_parker_attach_driver(cv_parker *p, cv_driver *d);
/// Exclusive right to poll. try_lock returns 1 on success.
int cv_driver_try_lock(cv_driver *d);
void cv_driver_lock(cv_driver *d);
void cv_driver_unlock(cv_driver *d);
/// Registered fds right now; busy workers skip polling when it is 0.
int cv_driver_registered(cv_driver *d);
/// One poll, holding the lock. With a parker, block up to timeout_ns
/// (< 0: forever) unless it is notified; without, timeout_ns is normally 0.
/// Frees registrations released before this turn. Returns how many waiters
/// became ready; their bits are in cv_driver_wakes(d)[0..<n].
int cv_driver_turn(cv_driver *d, cv_parker *p, int64_t timeout_ns);
uintptr_t *cv_driver_wakes(cv_driver *d);
/// Counters, updated by the lock holder only (read racily).
typedef struct cv_driver_stats {
    uint64_t parked_turns; // turns by a parked worker (blocking)
    uint64_t busy_turns;   // zero-timeout turns by a busy worker
    uint64_t events;       // events returned by the kernel
    uint64_t wakes;        // waiters resumed
    uint64_t full_batches; // turns that filled the whole event array
} cv_driver_stats;
cv_driver_stats cv_driver_get_stats(cv_driver *d);
/// Register a non-blocking fd for both directions. NULL with *err on failure.
cv_io *cv_driver_register(cv_driver *d, int fd, int *err);
/// Drop one owner; the last unregisters and closes the fd. The cv_io is freed
/// after the next turn, since a batch already taken from the kernel may still
/// name it.
void cv_driver_deregister(cv_driver *d, cv_io *io);

// ---- sockets -------------------------------------------------------------
// All fds are non-blocking and close-on-exec. Failures return -1 and an errno
// in *err; a non-numeric host is resolved with a blocking getaddrinfo.

/// A socket address of any family (room and alignment of sockaddr_storage).
typedef struct cv_sockaddr {
    uint64_t storage[16];
    uint32_t len;
} cv_sockaddr;
/// Resolve host and port to the first address found. 0 or an errno value.
int cv_resolve(const char *host, int port, cv_sockaddr *out);
/// The port of an IPv4/IPv6 address, or -1.
int cv_sockaddr_port(const cv_sockaddr *a);
/// The host as text (an IP address, or a Unix socket's path) into buf.
/// Returns 0, or -1 if it does not fit or the family is unknown.
int cv_sockaddr_host(const cv_sockaddr *a, char *buf, int buflen);
/// The family (AF_INET, AF_INET6, AF_UNIX).
int cv_sockaddr_family(const cv_sockaddr *a);
/// getsockname / getpeername. 0 or an errno value.
int cv_local_address(int fd, cv_sockaddr *out);
int cv_peer_address(int fd, cv_sockaddr *out);
/// A listening TCP socket (SO_REUSEADDR, and SO_REUSEPORT if reuse_port).
int cv_tcp_listen(const char *host, int port, int backlog, int reuse_port, int *err);
/// Start a TCP connect. Returns the fd; *err is 0 when connected already,
/// EINPROGRESS when the caller must wait for writability, else the failure.
int cv_tcp_connect(const char *host, int port, int *err);
/// Accept one connection (TCP_NODELAY set). -1 with *err (EAGAIN: none yet).
int cv_tcp_accept(int fd, int *err);
/// The pending error of a socket (SO_ERROR), 0 if none.
int cv_socket_error(int fd);
/// The local port a socket is bound to, or -1.
int cv_local_port(int fd);
/// recv / send (MSG_NOSIGNAL): bytes moved, or -errno.
long cv_recv(int fd, void *buf, long len);
long cv_send(int fd, const void *buf, long len);

/// A UDP socket bound to host:port (port 0: any free one).
int cv_udp_bind(const char *host, int port, int reuse_port, int *err);
/// A UDP socket on an ephemeral port, connected to host:port.
int cv_udp_connect(const char *host, int port, int *err);
/// Set the default peer of a datagram socket. 0 or an errno value.
int cv_connect_address(int fd, const cv_sockaddr *a);
/// sendto / recvfrom: bytes moved, or -errno. A datagram longer than len is
/// cut to len.
long cv_sendto(int fd, const void *buf, long len, const cv_sockaddr *to);
long cv_recvfrom(int fd, void *buf, long len, cv_sockaddr *from);

/// A listening Unix stream socket at path (which must not exist yet).
int cv_unix_listen(const char *path, int backlog, int *err);
/// Start a Unix stream connect: as cv_tcp_connect.
int cv_unix_connect(const char *path, int *err);
/// Accept one connection on a Unix listener. -1 with *err (EAGAIN: none yet).
int cv_unix_accept(int fd, int *err);
/// A connected pair of Unix stream sockets. 0 or an errno value.
int cv_unix_pair(int fds[2]);

// ---- Swift runtime hooks -------------------------------------------------
typedef void (*cv_enqueue_fn)(void *job, void *ctx);
/// Route swift_task_enqueueGlobal to fn(job, ctx) through the runtime's
/// enqueue hook. Swift's own path loads Task.defaultExecutor, an existential
/// copy that retains the executor on every enqueue; the hook skips that.
/// Returns 0, or -1 if the runtime has no such hook.
int cv_install_enqueue_global_hook(cv_enqueue_fn fn, void *ctx);

#ifdef __cplusplus
}
#endif
#endif
