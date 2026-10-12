# Benchmarks

All runs are on the bench box (`192.168.100.100`: i5-8250U, 4 cores / 8 threads, Ubuntu 26.04, kernel 7.0), never on the dev machine. Each figure is the median of 9 runs, in nanoseconds per operation; lower is better.

- `Benchmarks/run-on-box.sh` runs Vega, plus Swift's default executor for comparison.
- `Benchmarks/tokio-on-box.sh` runs Tokio 1.x, with `lto = "fat"`.

## Scheduler (Phase 1 baseline, 2026-10-12, commit 9de766c)

8 workers.

| Bench | Vega (preference) | Vega (global) | Swift default | Tokio |
|---|---|---|---|---|
| spawn_many (100k empty tasks from one task) | 2,981 | 2,647 | 4,727 | **474** |
| chained_spawn (each task spawns the next) | 1,431 | 1,440 | 6,722 | **921** |
| ping_pong (two tasks hand off a token) | 619 | 618 | 2,790 | **369** |
| yield_many (200 tasks × 500 yields) | 145 | 140 | 2,511 | **34** |

**Against Swift's default executor:** Vega is 1.6× to 17× faster.

**Against Tokio:** Vega is 1.6× to 6.3× slower. The gaps to close next:

1. **spawn_many.**
   - Each spawn is a Swift `Task` allocation, which is heavier than Tokio's task cell.
   - A spawn burst also keeps waking parked workers, and each wake is a futex syscall.
   - Next steps: profile with `perf`, batch the notifications, look at the cost of Swift's task allocator.
2. **yield_many.** `Task.yield` goes through Swift's generic enqueue path; measure how much of the 145 ns that path accounts for.
3. **ping_pong.** The comparison is not like-for-like. Tokio's version uses `Notify`, while Vega's uses a mutex-guarded continuation slot. Vega needs its own `Notify` (Phase 1 sync primitives) for a fair comparison.

## Option 1 round (2026-10-12): spin-park, `TaskPool`, `Runtime.yield`, `Notify`

8 workers, executor preference, median of 9 runs, in ns/op. "Before" is the Phase 1 baseline above.

| Bench | Before | Now | Tokio |
|---|---|---|---|
| spawn_many (Swift `Task` per spawn) | 2,981 | 2,221 | 474 |
| **pool_spawn** (`TaskPool`, 100k closures) | — | **863** | 474 |
| chained_spawn | 1,431 | 1,426 | 921 |
| ping_pong (mutex + continuation slot) | 619 | 611 | 369 |
| ping_pong_notify (`Notify`, cancellable) | — | 1,748 | 369 |
| ping_pong_notify_nc (`notifiedIgnoringCancellation`) | — | 880 | 369 |
| yield_many (`Task.yield`) | 145 | 131 | 34 |
| **yield_vega** (`Runtime.yield`) | — | **84** | 34 |
| yield_many, global mode | 140* | 296 | — |
| yield_vega, global mode | — | 134 | — |

\* The baseline passed an executor preference in global mode too. Without a preference, `Task.yield` takes an extra job hop in Swift's runtime.

**What changed:**
- **Spin before park.** An idle worker spins up to 50 µs (`VEGA_SPIN_NS`) before the futex wait, so most wakes during a burst cost a plain store instead of a syscall on each side. This alone took spawn_many from 3,670 to 2,210.
- **`TaskPool`.** A spawn is a queue push into a long-lived task instead of creating and destroying a Swift task: 2.6× faster than spawn_many.
- **`Runtime.yield`.** The yielding task's continuation is parked on the worker and resumed when its job returns. This skips `Task.currentExecutor` (a retain of the shared executor on every call) and, in global mode, a whole extra job.

**Where the rest goes (perf on the box):** Vega's own code is under 10% of the profile. The rest is Swift's concurrency runtime:
- **Task creation** costs two mallocs (the task, plus a slab for the preference record). Freeing a task on another worker hits the glibc arena lock, because tasks are too big for the per-thread cache. jemalloc or `GLIBC_TUNABLES=glibc.malloc.tcache_max=4096` cut spawn_many by about 20%.
- **Executor retains.** Swift retains and releases the executor object on every yield, spawn and global enqueue, from every worker, so its refcount line bounces between cores. `_swift_stdlib_immortalize` does not help: in 6.3 a release still decrements an immortal object, so immortality decays.
- **Status records.** Every resume walks the task's status records under a per-task mutex (`getPreferredTaskExecutor`). `withTaskCancellationHandler` adds and removes a record under the same lock, which is about 850 ns of the 1,748 ns per `Notify` round trip.
- **`TaskGroup.removeChildTask` is linear.** With one worker and 100k outstanding children, spawn_many costs 13.7 µs per task.

These are the targets for the patched Linux/Windows runtime (option 2).

**Bugs found on the way, both present since Phase 1:**
- **A job could run twice.** A batch from the inject queue was sized by "queue looks empty" instead of `remaining_slots` from the steal head. While a thief was still copying, the batch overwrote its slots. `QueueModelTests` reproduces it without Swift tasks.
- **A worker could sleep with a runnable task.** A worker that fired timers while searching left the woken sleeper in its LIFO slot and parked.
- **Timers fired together ran newest first,** through the LIFO slot. They now resume in deadline order.
