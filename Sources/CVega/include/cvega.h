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
