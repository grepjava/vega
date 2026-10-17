// CVega: the few things Swift can't do directly or cheaply — futex parking,
// a thread-local that inlines into Swift, named/pinned threads, a raw clock.
#ifndef CVEGA_H
#define CVEGA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---- current worker (thread-local) -------------------------------------
// static inline so the read inlines into Swift callers: no call, one TLS load.
extern _Thread_local void *cv_current_tls;
static inline void *cv_current_get(void) { return cv_current_tls; }
static inline void cv_current_set(void *worker) { cv_current_tls = worker; }

// ---- clock ---------------------------------------------------------------
/// CLOCK_MONOTONIC in nanoseconds (same base as Swift's ContinuousClock on Linux).
uint64_t cv_now_ns(void);
/// A cheaper monotonic clock, to within a few ms (the scheduler tick):
/// for metrics. Not comparable with cv_now_ns.
uint64_t cv_now_coarse_ns(void);
/// CPUs this process may run on: on Linux those in its affinity mask (as
/// `taskset` or a container's cpuset leaves it), elsewhere the online ones.
int cv_cpu_count(void);
/// The CPUs in this process's affinity mask, up to `max` of them, in
/// order: how many, or -1 where there is no mask to read (not Linux).
int cv_affinity_list(int *cpus, int max);
/// The CPU the calling thread is running on now, or -1 where the platform
/// does not say.
int cv_current_cpu(void);

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

// ---- I/O driver (edge-triggered: epoll on Linux, kqueue on Darwin) ----------
// One per runtime, as in Tokio. Whichever parked worker owns the timers blocks
// in it; busy workers poll it with a zero timeout. A parker blocked in the
// driver is woken through it (an eventfd, or an EVFILT_USER event) instead of
// a futex.

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
    int *count;         // uring driver: the runtime's open sockets
} cv_io;

/// Drop one owner of an io that no driver frees (Network.framework
/// sockets): returns how many are left.
static inline int cv_io_unref(cv_io *io) { return __atomic_sub_fetch(&io->refs, 1, __ATOMIC_ACQ_REL); }
/// Add `n` owners to such an io.
static inline void cv_io_ref(cv_io *io, int n) { __atomic_add_fetch(&io->refs, n, __ATOMIC_RELAXED); }

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

/// Windows: a task armed `dir` of `io` after WSAEWOULDBLOCK; make sure an
/// AFD poll for it is in flight (readiness there is one-shot, not edge).
void cv_driver_want(cv_io *io, int dir);

#if defined(_WIN32)
/// closesocket(2) and shutdown(SD_SEND): sockets aren't CRT descriptors.
void cv_close_socket(int fd);
/// 0 or an errno value.
int cv_shutdown_write(int fd);
/// The system's DNS servers and search suffixes (adapters that are up), as
/// resolv.conf text in out. Its length, or -1.
int cv_system_dns_config(char *out, int len);

// Files on Windows, for VegaFS: Win32 handles in the int descriptor, UTF-8
// paths. Functions return 0 or an errno value unless they say otherwise.
#define CV_FILE_READ 1
#define CV_FILE_WRITE 2
#define CV_FILE_APPEND 4
#define CV_FILE_CREATE 8
#define CV_FILE_EXCL 16
#define CV_FILE_TRUNC 32
#define CV_FILE_KIND_OTHER 0
#define CV_FILE_KIND_FILE 1
#define CV_FILE_KIND_DIR 2
#define CV_FILE_KIND_LINK 3
typedef struct cv_file_stat {
    int kind;
    uint32_t mode;  // 0444 or 0666 (read-only or not), plus 0111 for a directory
    uint32_t nlink;
    uint64_t size;
    uint64_t device; // volume serial
    uint64_t inode;  // file index
    int64_t atime_s, mtime_s, ctime_s;
    int32_t atime_ns, mtime_ns, ctime_ns;
} cv_file_stat;
typedef struct cv_dir_entry {
    char *name;
    int kind;
} cv_dir_entry;
int cv_file_open(const char *path, int flags, unsigned mode, int *fd);
int cv_file_close(int fd);
int cv_file_dup(int fd, int *out);
/// At `offset`, or at the position (advancing it) when offset < 0. Bytes,
/// or -errno. An offset leaves the position alone.
intptr_t cv_file_read(int fd, void *buf, intptr_t len, int64_t offset);
intptr_t cv_file_write(int fd, const void *buf, intptr_t len, int64_t offset);
/// whence 0 start, 1 current, 2 end: the new position, or -errno.
int64_t cv_file_seek(int fd, int64_t offset, int whence);
int cv_file_sync(int fd);
int cv_file_set_length(int fd, int64_t length);
int cv_file_fstat(int fd, cv_file_stat *out);
int cv_file_stat_path(const char *path, int follow, cv_file_stat *out);
/// Only the write bits count: none makes it read-only.
int cv_file_chmod(int fd, unsigned mode);
int cv_fs_chmod(const char *path, unsigned mode);
int cv_fs_mkdir(const char *path);
int cv_fs_rmdir(const char *path);
int cv_fs_unlink(const char *path);
int cv_fs_rename(const char *from, const char *to);
int cv_fs_link(const char *existing, const char *link);
int cv_fs_symlink(const char *target, const char *link);
/// The link's target as stored, in out: its length, or -errno.
int cv_fs_readlink(const char *path, char *out, int len);
int cv_fs_realpath(const char *path, char *out, int len);
/// The names in a directory (no . or ..): free with cv_fs_list_free.
int cv_fs_list(const char *path, cv_dir_entry **entries, int *count);
void cv_fs_list_free(cv_dir_entry *entries, int count);
/// A new directory in the temp directory: its path in out.
int cv_fs_temp_dir(const char *prefix, char *out, int len);
/// Copy a file, replacing `to`: the bytes, or -errno.
int64_t cv_fs_copy(const char *from, const char *to);

// Pipes and processes on Windows, for VegaProcess. A pipe is a named pipe
// whose overlapped ends the driver runs on its completion port (as Tokio's
// mio does): cv_driver_register takes them, and reads and writes go
// through an internal buffer per direction, reporting EAGAIN while one is
// in flight and readiness when it completes.

/// A pipe; fds[0] reads, fds[1] writes. With child_end 0 or 1, that end is
/// synchronous (to hand to a child) and only the other is overlapped; with
/// -1 both are. Neither is inheritable. 0 or an errno value.
int cv_pipe_win(int fds[2], int child_end);
/// Read from a registered overlapped pipe end: bytes, 0 at end of stream,
/// or -errno (-EAGAIN: wait for CV_IO_READ).
intptr_t cv_pipe_read_io(cv_io *io, void *buf, intptr_t len);
/// Write to a registered overlapped pipe end: the bytes taken (they're
/// copied and written in the background), or -errno (-EAGAIN: wait for
/// CV_IO_WRITE; -EPIPE once the reader is gone). A failure of a background
/// write shows on the next call. Closing waits for it, not cancels it.
intptr_t cv_pipe_write_io(cv_io *io, const void *buf, intptr_t len);
/// Watch a waitable handle (a process): its signal shows as the read side
/// of the returned io, which has no fd (the watch keeps a copy of the
/// handle, so the caller's may close first). NULL
/// and *err set on failure. Release with cv_driver_unwatch_handle.
cv_io *cv_driver_watch_handle(cv_driver *d, intptr_t handle, int *err);
void cv_driver_unwatch_handle(cv_driver *d, cv_io *io);
/// CreateProcessW. cmdline is the whole command line, quoted; env a
/// CREATE_UNICODE_ENVIRONMENT block or NULL to inherit; cwd may be NULL.
/// stdio[i] is a handle for the child's stdin, stdout or stderr,
/// CV_STDIO_INHERIT or CV_STDIO_NULL; the child inherits those and nothing
/// else. 0 (with *process, a handle to close with cv_process_close, and
/// *pid) or an errno value.
int cv_spawn_win(const wchar_t *app, const wchar_t *cmdline, const wchar_t *env, const wchar_t *cwd,
                 const int stdio[3], int new_group, intptr_t *process, int *pid);
/// 1 exited (*code set), 0 still running (nohang), or -errno.
int cv_process_wait(intptr_t process, int nohang, uint32_t *code);
/// TerminateProcess with exit code 1; 0 if it has exited already.
int cv_process_kill(intptr_t process);
void cv_process_close(intptr_t process);
/// A Win32 error as an errno value.
int cv_win_errno(unsigned long error);
#endif

// ---- sockets -------------------------------------------------------------
// All fds are non-blocking and close-on-exec, and never raise SIGPIPE
// (MSG_NOSIGNAL on Linux, SO_NOSIGPIPE on Darwin). Failures return -1 and an errno
// in *err. Functions taking a host name resolve it with a blocking getaddrinfo.

/// A socket address of any family (room and alignment of sockaddr_storage).
typedef struct cv_sockaddr {
    uint64_t storage[16];
    uint32_t len;
} cv_sockaddr;
/// Resolve host and port into out[0..<max]; *count gets how many. 0, or an
/// errno value. With numeric_only, a host that is a name (not an address)
/// returns -1 instead of being looked up: getaddrinfo may block on DNS, so
/// names go through the blocking pool.
int cv_resolve_all(const char *host, int port, int numeric_only, cv_sockaddr *out, int max,
                   int *count);
/// The port of an IPv4/IPv6 address, or -1.
int cv_sockaddr_port(const cv_sockaddr *a);
/// The host as text (an IP address, or a Unix socket's path) into buf.
/// Returns 0, or -1 if it does not fit or the family is unknown.
int cv_sockaddr_host(const cv_sockaddr *a, char *buf, int buflen);
/// The family (AF_INET, AF_INET6, AF_UNIX).
int cv_sockaddr_family(const cv_sockaddr *a);
/// An IPv4 (len 4) or IPv6 (len 16) address in network order, with a port.
/// 0, or -1 for any other length.
int cv_sockaddr_ip(cv_sockaddr *out, const uint8_t *ip, int len, int port);
/// The raw address bytes of an IPv4/IPv6 address into ip (room for 16): 4,
/// 16, or -1 for another family.
int cv_sockaddr_ip_bytes(const cv_sockaddr *a, uint8_t *ip);
/// n bytes from the system's CSPRNG (getrandom, arc4random_buf).
void cv_random_bytes(void *buf, intptr_t n);
/// Read a small regular file whole into buf: its length, or -1 if it is
/// missing, not a regular file (a fifo would block), longer than max, or
/// unreadable.
intptr_t cv_read_small_file(const char *path, void *buf, intptr_t max);
/// Copy everything from in's position to out's: the bytes copied, or
/// -errno. Uses copy_file_range on Linux where it can.
long long cv_copy_fd(int in, int out);

/// pipe(2) with both ends close-on-exec. 0 or an errno value.
int cv_pipe(int fds[2]);
/// Make a pipe end the parent keeps non-blocking and close-on-exec (and,
/// on Darwin, free of SIGPIPE). 0 or an errno value.
int cv_pipe_prepare(int fd);
/// read(2): bytes, or -errno.
intptr_t cv_fd_read(int fd, void *buf, intptr_t len);
/// write(2) to a pipe without SIGPIPE: bytes, or -errno (-EPIPE once the
/// reader is gone).
intptr_t cv_pipe_write(int fd, const void *buf, intptr_t len);

#define CV_STDIO_INHERIT (-1)
#define CV_STDIO_NULL (-2)
/// posix_spawn `path`. stdio[i] is an fd to give the child as fd i,
/// CV_STDIO_INHERIT or CV_STDIO_NULL. cwd may be NULL; pgroup < 0 keeps the
/// parent's process group. The child's signal mask is cleared and SIGPIPE
/// reset. 0 (with *pid) or an errno value.
int cv_spawn(const char *path, char *const argv[], char *const envp[], const char *cwd,
             const int stdio[3], int pgroup, int *pid);
/// The process environment.
char **cv_environ(void);
/// pidfd_open(2) (Linux 5.3+): the fd, or -errno (-ENOSYS elsewhere).
int cv_pidfd_open(int pid);
/// pidfd_send_signal(2): 0 or an errno value.
int cv_pidfd_signal(int pidfd, int sig);
/// waitpid, retrying EINTR: 1 reaped (*status set), 0 still running
/// (nohang), or -errno.
int cv_waitpid(int pid, int nohang, int *status);

/// The shard supervisor's signals (SIGCHLD, SIGTERM, SIGINT, SIGQUIT,
/// SIGHUP): from
/// now on they're taken by cv_supervisor_next, not delivered. Call before
/// any thread starts. 0 or an errno value.
int cv_supervisor_init(void);
/// fork(2) a shard: in the child, signals as they were before
/// cv_supervisor_init, and (Linux) SIGTERM when the supervisor dies.
/// The pid, 0 in the child, or -errno.
int cv_supervisor_fork(void);
/// Wait up to timeout_ns (< 0: forever): 1 when a child ended (*pid,
/// *status as waitpid gives it), 2 for SIGTERM, SIGINT, SIGQUIT or SIGHUP (*status
/// = the signal), 0 on timeout, or -errno.
int cv_supervisor_next(int64_t timeout_ns, int *pid, int *status);
/// Exec mode: start a shard as a new run of `path`, with listener fds[i]
/// at targets[i] in the child, the signal mask from before
/// cv_supervisor_init, and the supervisor's signals at their defaults.
/// Returns 0 or an errno value.
int cv_shard_spawn(const char *path, char *const argv[], char *const envp[],
                   const int *fds, const int *targets, int count, int *pid);
/// In an exec'd shard: end with the supervisor `parent` (SIGTERM, as a
/// forked shard). -1 if it is gone already.
int cv_shard_adopt(int parent);
/// exec(2) `path` in place of the supervisor, its signals still taken rather
/// than delivered, so none is lost before the new image takes them; fds
/// without FD_CLOEXEC carry over. Returns only on failure: an errno value.
int cv_supervisor_exec(const char *path, char *const argv[]);
/// In a supervisor exec'd by cv_supervisor_exec, after cv_supervisor_init:
/// the mask shards start with leaves out the signals the previous image
/// blocked.
void cv_supervisor_restarted(void);
/// This process's executable path. Returns 0 or an errno value.
int cv_self_exe(char *buf, int len);
/// A new shared-memory object of `size` zeroed bytes with no name left in
/// the file system (memfd on Linux, an unlinked shm object elsewhere): its
/// fd (close-on-exec), or -1 with *err set.
int cv_shared_memory(intptr_t size, int *err);
/// Threads in this process, or -1 where unknown (non-Linux).
int cv_thread_count(void);
/// getsockname / getpeername. 0 or an errno value.
int cv_local_address(int fd, cv_sockaddr *out);
int cv_peer_address(int fd, cv_sockaddr *out);
/// Whether a read on the socket would return at once -- bytes, end of
/// stream or an error -- without reading or waiting: 1, else 0.
int cv_input_waiting(int fd);
/// A listening TCP socket (SO_REUSEADDR, and SO_REUSEPORT if reuse_port).
/// backlog < 0 binds without listening (to hold a port for SO_REUSEPORT
/// listeners elsewhere).
int cv_tcp_listen(const char *host, int port, int backlog, int reuse_port, int *err);
/// Start a connect to one address on a new socket of `type` (SOCK_STREAM gets
/// TCP_NODELAY). Returns the fd; *err is 0 when connected already,
/// EINPROGRESS when the caller must wait for writability, else the failure
/// (and -1). A datagram connect only records the peer and never waits.
int cv_connect_new(const cv_sockaddr *addr, int type, int *err);
/// Accept one connection (TCP_NODELAY set). -1 with *err (EAGAIN: none yet).
int cv_tcp_accept(int fd, int *err);
/// The pending error of a socket (SO_ERROR), 0 if none.
int cv_socket_error(int fd);
/// The local port a socket is bound to, or -1.
int cv_local_port(int fd);
/// recv / send (MSG_NOSIGNAL): bytes moved, or -errno.
intptr_t cv_recv(int fd, void *buf, intptr_t len);
/// What a read would find, without taking it: 1 input, 0 end of stream,
/// -errno otherwise (-EAGAIN: nothing yet).
intptr_t cv_peek(int fd);

/// A read that says when its bytes arrived: with CV_OPT_TIMESTAMP on the
/// socket, the kernel stamps what it receives and recvmsg hands the stamp
/// over with the bytes. `space` holds the message header, its one buffer
/// and the control space the kernel fills, all of which must stay where
/// they are while a read on a ring waits; `micros` is then the arrival in
/// wall-clock microseconds since the epoch, 0 when there was no stamp.
typedef struct cv_arrival {
    uint64_t micros;
    uint64_t space[16];
} cv_arrival;
/// recv into buf through `arrival`, which then says when the bytes arrived.
/// Bytes read, or -errno.
intptr_t cv_recv_stamped(int fd, void *buf, intptr_t len, cv_arrival *arrival);
/// After a ring's cv_uring_recv_stamped has completed: read the stamp out
/// of `arrival`'s control space into `micros`.
void cv_arrival_settle(cv_arrival *arrival);
intptr_t cv_send(int fd, const void *buf, intptr_t len);

/// A UDP socket bound to host:port (port 0: any free one).
int cv_udp_bind(const char *host, int port, int reuse_port, int *err);
/// Set the default peer of a datagram socket. 0 or an errno value.
int cv_connect_address(int fd, const cv_sockaddr *a);
/// sendto / recvfrom: bytes moved, or -errno. A datagram longer than len is
/// cut to len.
intptr_t cv_sendto(int fd, const void *buf, intptr_t len, const cv_sockaddr *to);
intptr_t cv_recvfrom(int fd, void *buf, intptr_t len, cv_sockaddr *from);

/// A listening Unix stream socket at path (which must not exist yet).
int cv_unix_listen(const char *path, int backlog, int *err);
/// Start a Unix stream connect: as cv_connect_new.
int cv_unix_connect(const char *path, int *err);
/// Accept one connection on a Unix listener. -1 with *err (EAGAIN: none yet).
int cv_unix_accept(int fd, int *err);
/// A connected pair of Unix stream sockets. 0 or an errno value.
int cv_unix_pair(int fds[2]);
/// A Unix datagram socket bound to path, or unbound for a NULL path. -1
/// with *err on failure.
int cv_unix_dgram_bind(const char *path, int *err);
/// A connected pair of Unix datagram sockets. 0 or an errno value.
int cv_unix_dgram_pair(int fds[2]);
/// A Unix socket address for path. 0, or an errno value (ENAMETOOLONG).
int cv_unix_sockaddr(const char *path, cv_sockaddr *out);

// ---- socket options ------------------------------------------------------
// Portable option ids, mapped to each platform's level and name in cvega.c.
// An option the platform lacks fails with ENOPROTOOPT.
enum {
    CV_OPT_TCP_NODELAY,
    CV_OPT_KEEPALIVE,
    CV_OPT_TCP_KEEPIDLE,   // seconds idle before the first probe
    CV_OPT_TCP_KEEPINTVL,  // seconds between probes
    CV_OPT_TCP_KEEPCNT,    // unanswered probes before the connection drops
    CV_OPT_TCP_USER_TIMEOUT, // ms unacknowledged data may wait (Linux)
    CV_OPT_TCP_QUICKACK,
    CV_OPT_TCP_FASTOPEN,   // listener: queue length for TFO requests
    CV_OPT_RCVBUF,
    CV_OPT_SNDBUF,
    CV_OPT_REUSEADDR,
    CV_OPT_REUSEPORT,
    CV_OPT_BROADCAST,
    CV_OPT_IPV6_V6ONLY,
    CV_OPT_IP_TTL,
    CV_OPT_IP_TOS,
    CV_OPT_IPV6_UNICAST_HOPS,
    CV_OPT_IPV6_TCLASS,
    CV_OPT_IP_MULTICAST_TTL,
    CV_OPT_IP_MULTICAST_LOOP,
    CV_OPT_IPV6_MULTICAST_HOPS,
    CV_OPT_IPV6_MULTICAST_LOOP,
    CV_OPT_UDP_GRO,        // receive coalesced datagrams (Linux)
    CV_OPT_LINGER,         // seconds; -1 is off
    CV_OPT_TIMESTAMP,      // SO_TIMESTAMP: reads can say when their bytes arrived
};
/// 0 or an errno value.
int cv_sockopt_set(int fd, int opt, int value);
int cv_sockopt_get(int fd, int opt, int *value);
/// Join (join != 0) or leave an IPv4/IPv6 multicast group on an interface
/// index (0: the kernel's choice). 0 or an errno value.
int cv_multicast(int fd, const cv_sockaddr *group, unsigned interface, int join);

// ---- vectored and batched I/O --------------------------------------------

/// Layout of struct iovec.
typedef struct cv_iovec {
    const void *base;
    size_t len;
} cv_iovec;
/// sendmsg of count buffers (MSG_NOSIGNAL): bytes sent, or -errno.
intptr_t cv_sendv(int fd, const cv_iovec *iov, int count);
/// Up to `count` bytes of `file` from `offset` sent on socket `fd` by the
/// kernel: the bytes sent, or -errno (-ENOSYS where there is no sendfile).
intptr_t cv_sendfile(int fd, int file, int64_t offset, intptr_t count);
/// `relative` opened for reading beneath the directory `root` by the kernel,
/// which refuses any resolution that leaves it (Linux's openat2 with
/// RESOLVE_BENEATH): the descriptor, or -errno. -ENOSYS where the kernel
/// cannot, and -EXDEV for a path it will not decide (an absolute symlink):
/// the caller decides those another way.
int cv_open_beneath(const char *root, const char *relative);

#define CV_DGRAM_TRUNCATED 1u
/// The path a datagram took on this host: the local address it arrived on
/// (len 0 when unknown) and the ECN bits of its IP header (0 Not-ECT,
/// 1 ECT(1), 2 ECT(0), 3 CE). On a send, the source address to use (len 0:
/// the kernel's choice) and the ECN bits to set.
typedef struct cv_dgram_path {
    cv_sockaddr local;
    uint32_t ecn;
} cv_dgram_path;
/// Receive up to count (at most 64) datagrams, datagram i into
/// base + i * stride, with recvmmsg where there is one. Fills from[i],
/// lens[i] and flags[i] (CV_DGRAM_TRUNCATED), and paths[i] if paths is not
/// NULL (local addresses and ECN arrive once cv_udp_path_info is on).
/// Datagrams received, or -errno.
intptr_t cv_recv_batch(int fd, void *base, intptr_t stride, int count, cv_sockaddr *from,
                   uint32_t *lens, uint32_t *flags, cv_dgram_path *paths);
/// Send up to count (at most 64) datagrams laid out as for cv_recv_batch,
/// each to to[i] (NULL, or len 0: the connected peer), and from paths[i] if
/// paths is not NULL. Datagrams sent, or -errno.
intptr_t cv_send_batch(int fd, const void *base, intptr_t stride, const uint32_t *lens,
                   const cv_sockaddr *to, int count, const cv_dgram_path *paths);
/// Report each datagram's local address and ECN bits to cv_recv_batch
/// (IP_PKTINFO, IPV6_RECVPKTINFO, IP_RECVTOS, IPV6_RECVTCLASS: whichever
/// apply to this socket). 0 or an errno value.
int cv_udp_path_info(int fd, int on);
/// Set the IP don't-fragment bit on every datagram (IP_PMTUDISC_DO and its
/// IPv6 twin, or IP_DONTFRAG): one too large for the path fails or is
/// dropped instead of being split. 0 or an errno value.
int cv_udp_dont_fragment(int fd, int on);
/// Send len bytes as datagrams of segment bytes each (the last may be
/// shorter): one sendmsg that the kernel cuts up (UDP GSO) where it can, else
/// cv_send_segments_split (Darwin, Linux before 4.18, a route that can't
/// offload: EIO). to may be NULL for the connected peer. Bytes sent: a split
/// send that fills the socket returns the whole segments sent so far.
/// Or -errno.
/// path, if not NULL, gives every segment's source address and ECN bits.
intptr_t cv_send_segments(int fd, const void *buf, intptr_t len, int segment, const cv_sockaddr *to,
                          const cv_dgram_path *path);
/// cv_send_segments without GSO: the segments as one datagram each, through
/// cv_send_batch over the same memory.
intptr_t cv_send_segments_split(int fd, const void *buf, intptr_t len, int segment, const cv_sockaddr *to,
                                const cv_dgram_path *path);
/// Whether the kernel takes cv_send_segments with a segment size.
int cv_udp_gso_supported(int fd);
/// recvmsg that also reports UDP GRO: with CV_OPT_UDP_GRO on, several
/// datagrams from one sender may arrive in one buffer, each *segment bytes
/// (the last may be shorter); *segment is 0 for a single datagram. *flags
/// gets CV_DGRAM_TRUNCATED if what arrived was longer than len (its tail is
/// lost). from may be NULL. Bytes received, or -errno.
intptr_t cv_recv_segments(int fd, void *buf, intptr_t len, cv_sockaddr *from, int *segment,
                      uint32_t *flags);

// ---- io_uring driver (Linux) ---------------------------------------------
// The completion driver: one ring per worker (SINGLE_ISSUER, DEFER_TASKRUN),
// used only from that worker's thread. A task submits on the ring of the
// worker running it, and the same worker reaps the completion and resumes
// the task. Sockets aren't registered anywhere: a cv_io only carries the fd
// and its owners. A parked worker blocks in its ring, with a FUTEX_WAIT armed
// on its parker, so cv_unpark wakes it with no change to the wake path.
//
// An operation lives in a slot of the ring's slab until its completion is
// reaped, so a task always waits for the kernel to let go of its buffer,
// cancelled or not. Cancelling from another thread marks the slot (if its
// generation still matches) and queues it; the owner submits ASYNC_CANCEL.

typedef struct cv_uring cv_uring;
typedef struct cv_uring_op cv_uring_op;

/// 0 if this kernel runs the uring driver (6.7+: FUTEX_WAIT, EXT_ARG,
/// DEFER_TASKRUN), else an errno value (ENOSYS, EPERM under seccomp or
/// io_uring_disabled, EOPNOTSUPP for a missing opcode).
int cv_uring_probe(void);
/// A ring for the worker parking on p, created disabled: the worker enables
/// it from its own thread (the single issuer). NULL with errno on failure.
cv_uring *cv_uring_new(cv_parker *p);
/// On the owning thread, before any other call. 0 or an errno value.
int cv_uring_enable(cv_uring *r);
/// The worker is done: release the kernel ring now. The slots stay valid
/// for a late canceller until cv_uring_free.
void cv_uring_close(cv_uring *r);
void cv_uring_free(cv_uring *r);

/// Owner thread: queue an operation for continuation bits `waiter`.
/// Returns its slot; *gen gets the generation that cv_uring_cancel checks.
/// The result is the syscall's (>= 0) or -errno, -ECANCELED once cancelled.
cv_uring_op *cv_uring_recv(cv_uring *r, uintptr_t waiter, int fd, void *buf, size_t len, uint64_t *gen);
/// cv_uring_recv as a recvmsg through `arrival`, which stays put until
/// completion; then cv_arrival_settle says when the bytes arrived.
cv_uring_op *cv_uring_recv_stamped(cv_uring *r, uintptr_t waiter, int fd, void *buf, size_t len,
                                   cv_arrival *arrival, uint64_t *gen);
/// Result: the accepted fd (non-blocking, close-on-exec).
cv_uring_op *cv_uring_accept(cv_uring *r, uintptr_t waiter, int fd, uint64_t *gen);
/// One-shot readiness of direction dir (CV_IO_READ / CV_IO_WRITE). Result:
/// the poll mask.
cv_uring_op *cv_uring_poll_ready(cv_uring *r, uintptr_t waiter, int fd, int dir, uint64_t *gen);
/// File I/O: pread (write != 0: pwrite) of up to len bytes at offset, or at
/// the file position (advancing it) when offset is -1. Result: the bytes.
cv_uring_op *cv_uring_file_rw(cv_uring *r, uintptr_t waiter, int write, int fd, void *buf, size_t len,
                              int64_t offset, uint64_t *gen);
/// fsync, or fdatasync when datasync != 0. Result: 0.
cv_uring_op *cv_uring_fsync(cv_uring *r, uintptr_t waiter, int fd, int datasync, uint64_t *gen);
/// openat(AT_FDCWD, path, flags, mode); path stays valid until completion.
/// Result: the fd.
cv_uring_op *cv_uring_openat(cv_uring *r, uintptr_t waiter, const char *path, int flags, unsigned mode,
                             uint64_t *gen);
/// Any thread: cancel op if it is still generation gen and pending. Wakes
/// the owner, which submits the cancel; the waiter is resumed as usual.
void cv_uring_cancel(cv_uring_op *op, uint64_t gen);

/// Owner thread, busy: submit what is queued and reap without waiting.
/// Returns how many waiters to resume (cv_uring_wakes(r)[0..<n]).
int cv_uring_poll(cv_uring *r);
/// Owner thread, nothing to run: submit, spin up to spin_ns, then block in
/// the ring until a completion, an unpark or timeout_ns (< 0: forever).
/// Consumes a pending unpark, as cv_park does. Returns waiters to resume.
int cv_uring_park(cv_uring *r, int64_t timeout_ns, int64_t spin_ns);
typedef struct cv_uring_wake {
    uintptr_t waiter;
    int64_t res;
} cv_uring_wake;
cv_uring_wake *cv_uring_wakes(cv_uring *r);
cv_driver_stats cv_uring_get_stats(cv_uring *r);

/// A cv_io for an fd of a uring runtime (no registration), counted in
/// *count until freed. NULL on ENOMEM.
cv_io *cv_uring_io_new(int fd, int *count);
/// Read such a count.
int cv_count_load(int *count);
/// Add `delta` to a runtime's open-socket count (Network.framework sockets).
static inline void cv_count_add(int *count, int delta) { __atomic_add_fetch(count, delta, __ATOMIC_RELEASE); }
/// Drop one owner; the last closes the fd and frees the cv_io.
void cv_uring_io_release(cv_io *io);
/// TCP_NODELAY on an accepted TCP connection, as cv_tcp_accept sets it.
void cv_tcp_accepted(int fd);

// ---- Swift runtime hooks -------------------------------------------------
typedef void (*cv_enqueue_fn)(void *job, void *ctx);
/// Route swift_task_enqueueGlobal to fn(job, ctx) through the runtime's
/// enqueue hook. Swift's own path loads Task.defaultExecutor, an existential
/// copy that retains the executor on every enqueue; the hook skips that.
/// Returns 0, or -1 if the runtime has no such hook.
int cv_install_enqueue_global_hook(cv_enqueue_fn fn, void *ctx);

// The running task, and cancelling a task, as plain pointers: no ARC, unlike
// UnsafeCurrentTask. Both are Swift-convention runtime entry points.
extern void *swift_task_getCurrent(void) __attribute__((swiftcall));
extern void swift_task_cancel(void *task) __attribute__((swiftcall));
static inline void *cv_task_current(void) { return swift_task_getCurrent(); }
/// The running task's binding of the task-local whose TaskLocal object is
/// `key`: a pointer to the bound value, or NULL. What TaskLocal.get calls,
/// without its generic copy of the value.
extern void *swift_task_localValueGet(const void *key) __attribute__((swiftcall));
static inline void *cv_task_local_get(const void *key) { return swift_task_localValueGet(key); }
static inline void cv_task_cancel(void *task) { swift_task_cancel(task); }
/// Run `job` on the generic executor with no task executor: how Swift's own
/// global executor runs a job. `swift_job_run` takes a SerialExecutorRef,
/// its identity and implementation words; both 0 is the generic executor.
extern void swift_job_run(void *job, const void *identity, uintptr_t implementation) __attribute__((swiftcall));
static inline void cv_job_run_generic(void *job) { swift_job_run(job, 0, 0); }

// Retain and release a task (or any native Swift object). Unmanaged<AnyObject>
// would go through objc_retain on Darwin, which can't handle a task.
extern void *swift_retain(void *object);
extern void swift_release(void *object);
static inline void cv_task_retain(const void *task) { swift_retain((void *)task); }
static inline void cv_task_release(const void *task) { swift_release((void *)task); }

#if !defined(__linux__)
/// kqueue only: watch child `pid` for its exit (EVFILT_PROC, NOTE_EXIT). The
/// exit shows as the read side of the returned io, which has no fd. NULL and
/// *err set on failure (ESRCH: it has exited already). Release it with
/// cv_driver_unwatch_exit.
cv_io *cv_driver_watch_exit(cv_driver *d, int pid, int *err);
void cv_driver_unwatch_exit(cv_driver *d, cv_io *io, int pid);
#endif

// ---- signals -------------------------------------------------------------
/// Install Vega's handler for `signo` (once; it stays for the process).
/// Returns 0 or an errno value: EINVAL for SIGILL, SIGFPE, SIGKILL, SIGSEGV,
/// SIGSTOP and numbers out of range.
int cv_signal_install(int signo);
/// How many times `signo` has arrived since its handler went in.
uint64_t cv_signal_count(int signo);
/// Block until some installed signal may have arrived. Call only after a
/// successful cv_signal_install.
void cv_signal_wait(void);
/// Send `signo` to the dispatcher thread (once it runs), for tests: under
/// TSan a handler runs only when its thread makes an intercepted call, which
/// a thread parked elsewhere may never do. Returns 0 or an errno value.
int cv_signal_raise(int signo);

/// Tell ThreadSanitizer that whatever another thread did before releasing
/// `addr` happens before the caller's next steps; a no-op without TSan.
/// Swift's swift_continuation_await skips its acquire when a continuation was
/// resumed before the task got there; the resumer released the task pointer,
/// so acquiring `cv_task_current()` after the await restores the edge.
void cv_tsan_acquire(const void *addr);
/// 1 in a build with ThreadSanitizer, for tests that must do less under it.
int cv_tsan_enabled(void);

#ifdef __cplusplus
}
#endif
#endif
