#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "cvega.h"

#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#include <linux/futex.h>
#include <sched.h>
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

enum { EMPTY = 0, PARKED = 1, NOTIFIED = 2 };

struct cv_parker {
    _Atomic uint32_t state;
    char pad[124]; // own cache line pair: parkers are hit from other threads
};

cv_parker *cv_parker_new(void) {
    cv_parker *p = aligned_alloc(128, sizeof(cv_parker));
    if (!p) abort();
    atomic_init(&p->state, EMPTY);
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
    if (atomic_exchange(&p->state, NOTIFIED) == PARKED) wake_one(&p->state);
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
