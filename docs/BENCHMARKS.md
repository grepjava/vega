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

## Round 3 (2026-10-12): 16-byte atomic loads, lock-free resume, word lock, static linking

Same box, 8 workers, preference mode, median of 5 runs, ns/op. "Stock" is Vega on the unpatched runtime, so its numbers include the Vega-side changes. Each value is the range over two rounds.

| Bench | Stock | Patched (.so) | Patched static | Tokio | Static vs Tokio |
|---|---|---|---|---|---|
| ping_pong | 575–588 | 298–299 | **261** | 369 | **29% faster** |
| ping_pong_notify_nc | 840 | 390–391 | **331–333** | 369 | **10% faster** |
| ping_pong_notify | 1,599–1,641 | 779–785 | **667–709** | 369 | 1.8–1.9× |
| pool_spawn | 613–617 | 537–547 | 548–572 | 474 | 1.2× |
| spawn_many | 2,181–2,341 | 1,484–1,535 | 1,481–1,845 | 474 | 3.1–3.9× |
| chained_spawn | 1,351–1,357 | 1,185–1,202 | 1,168–1,220 | 921 | 1.3× |
| yield_many | 137–139 | 54 | **47** | 34 | 1.4× |
| yield_vega | 78 | 46.5–46.7 | **39.4–39.8** | 34 | 1.16× |

**What changed:**
- **Patch 0005, 16-byte atomic loads.** On x86-64 every load of a task's status was `lock cmpxchg16b`. Profiling showed one such instruction was 76% of `getPreferredTaskExecutor`. With an aligned `movdqa` (atomic on AVX CPUs), ping_pong went from 427 to 358.
- **Patch 0006, resume without the status-record lock.** A task woken from a continuation onto the generic executor now changes its status bits with one CAS. ping_pong went from 358 to 298.
- **Vega's `RawLock` is now a futex word lock.** Lock is one inlined CAS and unlock one exchange; the slow path spins, then waits on the futex. It replaces the pthread mutex. pool_spawn went from 830 to 540, and every user of the lock benefits.
- **`Notify` has a Tokio-style state word.** Storing and taking a permit are single CASes, and the lock is only for queueing waiters.
- **Static linking** (`-static-stdlib` with the patched archive). The runtime's thread-local variables stop going through `__tls_get_addr`.

**Correction to the option 2 round.** The shared libraries measured there were missing their metadata-registration constructor (`swiftrt.o`). Concurrency types could not be looked up by mangled name, and the toolchain's own SwiftPM crashed on them. Vega's tests and benchmarks never do such lookups, so they passed. The rebuilt libraries give the same numbers. `build-linux.sh` now links the object and refuses a library that SwiftPM can't run on.

**Where Tokio is still ahead, and why:**
- **Creating a Swift task (spawn_many).** A Swift task is a refcounted runtime object with status records and group bookkeeping under the parent's lock. A Tokio task is one allocation holding a header and the future. `TaskPool` is the route for hot spawns.
- **Cancellable waits (ping_pong_notify).** Every wait has to register a cancellation record and remove it again; Tokio's waits cancel by being dropped.

### Patch 0007: task memory pool

Static, patched, ns/op; each value is the range over three rounds.

| Bench | Before 0007 | With 0007 | Tokio |
|---|---|---|---|
| spawn_discard | 1,740�1,850 | **1,222�1,273** | 474 |
| chained_spawn | 1,168�1,220 | **973�1,158** | 921 |
| spawn_many | 1,481�1,845 | 1,515�1,694 | 474 |

**Why spawn_many didn't move.** Its regular task group keeps every finished child alive until the parent collects the result, so all 100k tasks, about 100 MB, are live at once. No allocator can recycle those, and the spawning thread's time goes to fresh memory: page faults and `_int_malloc`. Tokio's equivalent bench drops each task as it finishes. The like-for-like comparison is spawn_discard, whose children are freed on completion: about 2.6� Tokio.
