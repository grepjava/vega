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

## Option 2 round (2026-10-12): patched Swift runtime, enqueue hook

The patched runtime is Swift 6.3.3's `libswift_Concurrency` with the four patches in `runtime/patches` (see `runtime/README.md`). Both libraries were built the same way (`runtime/build-linux.sh` with and without `--stock`) and run against the same `vega-bench` binary, alternating, two rounds. 8 workers, median of 5 runs, ns/op; the table shows round 2 (round 1 agrees within a few percent).

| Bench | Stock pref | Patched pref | Stock global | Patched global | Tokio |
|---|---|---|---|---|---|
| spawn_many | 2,624 | **1,625** | 2,201 | **1,666** | 474 |
| spawn_discard | 2,299 | **1,844** | 2,234 | **1,730** | — |
| pool_spawn | 870 | 846 | 862 | 835 | 474 |
| chained_spawn | 1,341 | 1,318 | 1,309 | 1,289 | 921 |
| ping_pong | 572 | **427** | 577 | **427** | 369 |
| ping_pong_notify | 1,651 | **1,048** | 1,650 | **1,076** | 369 |
| ping_pong_notify_nc | 828 | **536** | 836 | **540** | 369 |
| yield_many (`Task.yield`) | 137 | **66** | 130 | **66** | 34 |
| yield_vega (`Runtime.yield`) | 78 | **57** | 79 | **57** | 34 |

**Patches and what they bought:**
- **Lock-free executor-preference read.** This took the status-record mutex off every resume:
  - ping_pong is now 427 against 572;
  - ping_pong_notify_nc is now 536 against 828.
- **Lockless cancellation-handler removal.** `withTaskCancellationHandler` now costs about 500 ns per round trip instead of about 820 ns.
- **Task and first slab in one malloc.** spawn_many is now 1,625 against 2,624.
- **`Task.yield` without the existential.** It no longer retains the executor, so it's twice as fast. It now beats the stock runtime's `Runtime.yield`.

**Vega-side, any runtime: the global enqueue hook.** In global mode Vega now installs `swift_task_enqueueGlobal_hook`, the hook NIO also uses. Global enqueues then skip `Task.defaultExecutor`, an existential copy that retains the scheduler on every enqueue. Before this, on the stock runtime, global yield_many was 296 and yield_vega 134; both now match preference mode.

**Checks with the patched library:**
- Vega's suite: 8 release runs and 5 debug runs, all passing.
- `vega-global-check`, run 15 times, all passing. It covers tasks, sleeps, groups, actors, async let, and a cancel-while-notifying stress for patch 0002.
- The ABI gate in the build script: every export of the toolchain's library is still present.

**What's left in the runtime:**
- Task creation is still about 1.6 µs. It goes through the task-creation options, the group and status-record attach under the parent's mutex, and the task's malloc and free on different threads.
- In discarding groups, a finishing child detaches itself under the parent's status-record mutex, by scanning the child list, which is O(n).
