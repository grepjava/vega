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
| spawn_discard | 1,740–1,850 | **1,222–1,273** | 474 |
| chained_spawn | 1,168–1,220 | **973–1,158** | 921 |
| spawn_many | 1,481–1,845 | 1,515–1,694 | 474 |

**Why spawn_many didn't move.** Its regular task group keeps every finished child alive until the parent collects the result, so all 100k tasks, about 100 MB, are live at once. No allocator can recycle those, and the spawning thread's time goes to fresh memory: page faults and `_int_malloc`. Tokio's equivalent bench drops each task as it finishes. The like-for-like comparison is spawn_discard, whose children are freed on completion: about 2.6× Tokio.

## Phase 2, first slice (2026-10-12): epoll driver, TCP echo

The first I/O driver: one edge-triggered epoll instance per runtime (Tokio's shape), `TCPListener` and `TCPStream`, and per-operation cancellation. Benchmarked as a TCP echo server against SwiftNIO and Tokio.

**Setup.** Each server runs 4 workers on physical cores 0–1 (CPUs 0, 1, 4, 5). The same closed-loop client (`tokio-bench`'s `echo-load`, 4 threads) runs on cores 2–3 and drives all of them. Each connection sends 64 bytes, waits for the echo, and repeats. Each run is 10 s after a 2 s warm-up. All servers use the stock Swift 6.3.3 runtime unless marked patched. Run with `Benchmarks/echo-on-box.sh`.

- **Vega:** `vega-echo`, one task per connection, 4 KiB `IOBuffer`.
- **SwiftNIO:** `nio-echo`, a classic `ChannelInboundHandler` that writes each read and flushes on `channelReadComplete`, with NIO 2.x `MultiThreadedEventLoopGroup`. This is NIO's fastest path.
- **Tokio:** `echo-server`, `tokio::spawn` per connection, 4 KiB buffer.

Requests per second, with p99 round-trip latency:

| Connections | Vega | Vega, patched runtime | SwiftNIO | Tokio |
|---|---|---|---|---|
| 64 | **299,011** (337 µs) | 272,180 (395 µs) | 220,604 (538 µs) | 267,724 (404 µs) |
| 256 | **296,824** (1.39 ms) | 271,104 (1.59 ms) | 224,107 (2.21 ms) | 271,914 (1.59 ms) |
| 1,024 | 227,451 (6.9 ms) | 249,173 (7.9 ms) | 205,226 (5.4 ms) | **253,352** (7.7 ms) |

- **Against Tokio:** 11% and 9% more requests at 64 and 256 connections, with lower p99. At 1,024 connections Vega does 10% fewer requests (see below).
- **Against SwiftNIO:** 1.36× and 1.32× the throughput at 64 and 256 connections, 1.11× at 1,024, with 37% lower p99 at 64 and 256.

**How the driver works.**
- The parked worker that owns the timers also owns the driver: it blocks in `epoll_pwait2`, with the next timer deadline as the timeout.
- Busy workers poll the driver with a zero timeout every 61 ticks.
- A worker blocked in the driver is woken through an eventfd. Its parker has a fourth state, "parked in I/O", so every existing wake path (`cv_unpark`) works unchanged.
- Each fd has a read slot and a write slot: idle, ready, or a waiting continuation. Arming, readiness and cancellation are each one CAS, so cancelling one read leaves the socket usable.
- A closed fd's registration is freed only after the driver's next turn, because a batch already taken from the kernel may still name it.

**Three findings from tuning:**
1. **Short reads.** When a read returns fewer bytes than the buffer holds, the socket is drained. The next read waits for an event instead of making a `recv` that only returns `EAGAIN`. Tokio does the same. This took 64 connections from about 280k to 299k requests/s and 256 connections from 269k to 297k, since syscalls are 78% of the server's CPU.
2. **Fairness under load.**
   - *The problem.* At 1,024 connections, p99 was 20–25 ms against Tokio's 7–8 ms.
   - *The cause.* A busy worker's poll returns about 190 ready tasks, while it runs 61 jobs between polls. Its local queue overflowed, and overflow sends the oldest half to the inject queue, which each worker served one job per 31 ticks. Newly woken connections kept being served first, while the overflowed ones waited.
   - *The fix.*
     - A busy worker's poll fills only its local queue's free room, and the rest goes to the inject queue in event order.
     - Every 31 ticks a worker takes a fair batch from the inject queue instead of one job.
   - *The result.* p99 fell to about 6.5 ms, below Tokio's.
   - *The cost.* Throughput at 1,024 connections. In a closed loop, throughput is connections divided by mean latency, and fair FIFO order raised p50 from 2.4 to 4.5 ms.
3. **Batch size.** The driver takes up to 1,024 events per poll, as Tokio does. With 256, ready sockets were left for the next poll.

**Where the time goes at 1,024 connections (perf):**
- 78% kernel: TCP, syscall entry and exit, conntrack, AppArmor.
- 11% Swift's concurrency runtime, mostly the status-record lock taken by `withTaskCancellationHandler` and by `getPreferredTaskExecutor` on each resume.
- 6% Vega.

**Open question.** The patched runtime is slower than stock at 64 and 256 connections and faster at 1,024. In the scheduler benchmarks it is faster everywhere. This needs a per-patch bisect.

## io_uring driver (2026-10-13)

The completion driver: one io_uring per worker, created with `SINGLE_ISSUER | DEFER_TASKRUN`, and chosen with `Runtime(io: .ioUring)` or `VEGA_DRIVER=uring`. It needs Linux 6.7+ for `FUTEX_WAIT`. Same echo setup as above, on kernel 7.0.

Requests per second, with p99 round-trip latency (epoll, SwiftNIO and Tokio rerun the same day):

| Connections | Vega, epoll | Vega, io_uring | SwiftNIO | Tokio |
|---|---|---|---|---|
| 64 | **308,302** (327 µs) | 308,220 (348 µs) | 226,125 (533 µs) | 268,284 (403 µs) |
| 256 | **295,347** (1.42 ms) | 288,843 (1.54 ms) | 223,970 (2.22 ms) | 270,295 (1.60 ms) |
| 1,024 | 222,146 (6.8 ms) | 241,321 (7.9 ms) | 206,207 (5.4 ms) | **254,966** (7.7 ms) |

io_uring matches epoll at 64 connections, is 2% behind at 256, and is 9% ahead at 1,024, closing half the gap to Tokio there. With the UDP results below (20–25% ahead with one flow), it became the default on 2026-10-13, where the kernel can run it. `VEGA_DRIVER=epoll` opts out.

**How it works.**
- A task submits on the ring of the worker running it. That worker reaps the completion and resumes the task, so the task's next step runs where its data is hot.
- Submissions are flushed, and completions reaped, when the worker runs out of local work, every 61 ticks while busy, and when it parks.
- A parked worker blocks in its own ring with an `IORING_OP_FUTEX_WAIT` armed on its parker word. The existing `cv_unpark` futex wake therefore wakes the ring, and no wake path changed.
- **Operations.** Reads and accepts are native. Everything else (connect, datagram batches, writes that found the socket full) waits on a one-shot `POLL_ADD`, then retries the syscall.
- **Cancellation.**
  - Each operation lives in a slot of the ring's slab with a generation number, until its completion is reaped.
  - A canceller on another thread marks the slot only if the generation still matches, queues it, and wakes the owner. The owner submits `ASYNC_CANCEL`.
  - The task always waits for the cancelled completion, so the kernel never writes into a buffer that is gone.

**Two findings from tuning:**
1. **Writes go through the syscall first.** Sending through the ring suspends the task until the completion, which is one more trip through the scheduler per request: each worker ran twice as many jobs. At 64 connections that cost 16% (263k against 312k). The socket almost always has room, so a write tries `send` directly and waits on the ring only on `EAGAIN`.
2. **Poll first on reads.** A task reads after handling the previous request, so the socket is usually empty. A plain `IORING_OP_RECV` first tries the receive inline, fails, then arms a poll. `IORING_RECVSEND_POLL_FIRST` skips that attempt. This took 64 connections from 269k to 308k and 1,024 connections from 227k to 241k.

**Tried and dropped: multishot receive.** One `IORING_RECV_MULTISHOT` per connection, with a ring of 512 provided 4 KiB buffers per worker. Arrived data was queued on the socket, and reads copied it out. It measured 265k / 257k / 240k requests/s, against single-shot's 308k / 289k / 241k:
- **Why it lost.** A receive armed once stays on the ring of the worker where the connection was first read, which is mostly the worker running the accept loop. Every completion then wakes its task on that worker, even after another worker has stolen the task. Steals per interval ranged from 129 to 1,091 across workers.
- **Why single-shot doesn't.** It resubmits on whichever worker the task runs on, so it follows the task.
- **Moving the receive** to the reader's ring needs a cross-ring cancel, which made the bookkeeping fragile.
- **Conclusion.** With a ring per worker and work stealing, single-shot with POLL_FIRST is the better fit. The attempt is kept out of the tree.

**Next:** `SEND_ZC` for large writes, and deciding whether io_uring becomes the default.

## UDP echo (2026-10-13)

Datagrams per second through a UDP echo server, measured with `Benchmarks/udp-on-box.sh`.

**Setup.** Each server runs 4 workers on physical cores 0–1 and has one socket per worker, on consecutive ports. Client flow *i* goes to port + *i* mod 4, so flows land the same way on every server. A first run used one SO_REUSEPORT port instead, and the kernel's hash put two of four flows on one socket differently from run to run, so it couldn't compare servers at 4 flows.

The client, `tokio-bench`'s `udp-load`, runs on cores 2–3. Each flow has its own connected socket and thread, keeps 256 datagrams in flight, and sends and receives through `sendmmsg` / `recvmmsg`. That way the client isn't the limit. No run lost datagrams.

- **single:** a `receiveFrom` and a `send(to:)` per datagram, the same shape as Tokio's `recv_from` / `send_to`.
- **batch:** `DatagramBatch`, up to 64 datagrams per `recvmmsg`, sent back with one `sendmmsg`.
- **gso:** a GRO receive and a GSO send.

Datagrams per second:

| Server | 1 flow, 64 B | 1 flow, 1,200 B | 4 flows, 64 B | 4 flows, 1,200 B |
|---|---|---|---|---|
| Vega single, epoll | 157,973 | 148,014 | 480,675 | 406,330 |
| Vega single, io_uring | 194,722 | 196,258 | 454,599 | 417,296 |
| Vega batch, epoll | 275,995 | 263,333 | 694,944 | 644,404 |
| Vega batch, io_uring | **340,513** | **320,240** | **738,710** | **664,296** |
| Vega gso, epoll | 142,003 | 143,733 | 363,386 | 354,952 |
| Tokio (`recv_from` / `send_to`) | 195,122 | 182,762 | 462,687 | 439,971 |

- **Batching** gives 1.75× Tokio's datagrams per second with one flow and 1.5–1.6× with four, on io_uring. Most of that comes from cutting syscalls from two per datagram to two per batch. Tokio has no batched UDP API; quinn-udp adds one.
- **Single datagrams** match Tokio on io_uring.
  - On epoll, a single flow is 19% behind (158k against 195k), and four flows are level.
  - It isn't the wait path: under `strace`, no `recvfrom` failed, and Vega made the same syscalls per datagram as Tokio. Each made one `recvfrom`, one `sendto`, and about two epoll waits (the parked owner of the edge-triggered driver wakes for each arriving datagram).
  - It isn't the idle workers' spin before parking either. On the hyperthread siblings it shows as 7% of cycles, but `VEGA_SPIN_NS=0` measured 153k against 156k.
  - What's left is on the kernel side of the epoll registration, and io_uring (no registration, workers parked in their own rings) doesn't have it. io_uring is now the default.
- **GSO/GRO** gains nothing here and costs a little: GRO's control message on each receive. Loopback coalesces only datagrams that were sent with GSO, and the client sends with `sendmmsg`. The GSO path pays off for bulk senders (QUIC, media) on real NICs, and it needs a GSO client to measure.

## macOS (kqueue), indicative (2026-10-13)

The TCP and UDP echo runs above, repeated on a laptop to catch kqueue-specific regressions: **not the bench box, and not comparable with its numbers.** Apple M1 (4 performance + 4 efficiency cores, 16 GB), macOS 26.6.2, Swift 6.4 (Xcode 26.6), Tokio 1.x. macOS can't pin threads, so the 4-worker server and the 4-thread load share all 8 cores, and run-to-run noise is several percent. Two runs of `Benchmarks/macos-local.sh`, 10 s each after a 2 s warm-up; the second started with a load average of 6.6 from other work. Each cell gives run 1 / run 2.

On macOS, `udp-load` sends and receives one datagram per call (no `sendmmsg` / `recvmmsg`). There is no GSO or GRO either, so `vega-udp --mode gso` measures the fallback: one datagram per receive, and each echo sent through `cv_send_segments_split`.

TCP echo, requests per second (p99 from run 1):

| Connections | Vega (kqueue) | Tokio |
|---|---|---|
| 64 | 182,149 / 183,169 (672 µs) | **201,419 / 197,731** (593 µs) |
| 256 | 193,476 / 194,687 (2.68 ms) | 196,444 / 195,990 (2.56 ms) |
| 1,024 | **197,627 / 195,487** (12.3 ms) | 194,855 / 193,750 (11.5 ms) |

UDP echo, datagrams per second:

| Server | 1 flow, 64 B | 1 flow, 1,200 B | 4 flows, 64 B | 4 flows, 1,200 B |
|---|---|---|---|---|
| Vega single | 176,155 / 165,973 | 170,387 / 160,486 | 291,536 / 281,432 | 284,568 / 267,746 |
| Vega batch | **230,592 / 207,979** | **220,780 / 200,676** | **305,750 / 295,346** | **293,062 / 281,550** |
| Vega gso (fallback) | 166,110 / 157,451 | 159,181 / 153,218 | 278,521 / 274,336 | 270,604 / 264,600 |
| Tokio (`recv_from` / `send_to`) | 185,753 / 181,599 | 179,615 / 174,954 | 288,672 / 283,115 | 277,675 / 271,902 |

- **No kqueue-specific regression.** The shape matches epoll on the box: batching leads (1.2× Tokio with one flow), single datagrams are level with Tokio at four flows and a few percent behind with one, and TCP is level at 256 and 1,024 connections.
- **The 64-connection gap is the park spin, not kqueue.** At 64 connections Vega is about 8% behind Tokio here, where on the box it leads by 11%. Profiles (`sample`, 3 s under load) show the same time in `kevent`, `recvfrom` and `sendto` for both servers. Vega's extra CPU is `cv_park_spin` and the clock reads it makes, about 1,300 samples, plus about 250 of Swift concurrency's signpost tracing (Darwin only). A worker spins 50 µs before it parks (`VEGA_SPIN_NS`). On the box the load runs on other cores, so that is free; here server and load share cores, and the spin takes time from the load generator. The gap is not about core type: it stays at 7% with 2 workers, widens to 13% with 8, and to 20% with the load forced onto the efficiency cores (`taskpolicy -c utility`).

  `VEGA_SPIN_NS` at 64 connections, two runs each:

  | Spin | 0 | 5 µs | 20 µs | 50 µs (default) | Tokio |
  |---|---|---|---|---|---|
  | req/s | 198,020 / 195,963 | 193,551 / 190,017 | 187,374 / 184,479 | 184,358 / 181,422 | 201,549 / 196,915 |

  With spin 0, Vega is also ahead of the default at 256 connections (198.6k against 196.3k, Tokio 196.0k) and at 1,024 (198.2k against 195.7k, Tokio 193.7k), and with 8 workers it does 189k against 170k (Tokio 193k). On `vega-bench` (8 workers, median of 5 runs), spin 0 is level on ping-pong, faster on `spawn_many` (863 against 1,071 ns), `pool_spawn` (495 against 801), `mpsc_fan_in` (337 against 618) and `sleep_cancel` (1,733 against 1,986), and slower on `sleep_many` (3,117 against 2,585 ns). Since then **Darwin defaults to spin 0** (`Worker.spinNanos`; `VEGA_SPIN_NS` still overrides it). At the new default, 64 connections measure 197,330 / 197,374 against Tokio's 201,845 / 201,184, with p99 598 µs against 592 µs. Linux keeps 50 µs: there server and load have their own cores, and on the box the spin is what took `spawn_many` from 3,670 to 2,210 ns. The tables above were run at the old 50 µs default.
- Batch at 4 flows needed 1–3 window refills per run (a few datagrams dropped on loopback); no other run lost any.

## macOS scheduler microbenchmarks, indicative (2026-10-13, commit e9c26a6)

`vega-bench` and `tokio-bench` on the same Apple M1 laptop as the section above: **not the bench box, and not comparable with its numbers.** 8 workers, median of 9 runs, in ns per operation; two rounds, given as round 1 / round 2. Other work on the machine kept the load average around 5 throughout. Vega runs through executor preference only: `--global` needs the executor SPI, which the macOS SDK hides. "Swift default" here is Dispatch's cooperative pool, a stronger baseline than Swift's default executor on Linux. Workers don't spin before parking (the Darwin default).

| Bench | Vega | Swift default (Dispatch) | Tokio |
|---|---|---|---|
| spawn_many | 781 / 781 | 803 / 804 | **219 / 215** |
| spawn_discard | 1,009 / 1,055 | **673 / 667** | |
| pool_spawn | 485 / 496 | 480 / 488 | |
| chained_spawn | 1,118 / 1,106 | 1,893 / 1,890 | **279 / 272** |
| ping_pong | 884 / 886 | 1,558 / 1,565 | **192 / 191** |
| ping_pong_notify | 1,383 / 1,385 | 2,320 / 2,354 | |
| yield_many | 255 / 246 | 341 / 337 | **41 / 38** |
| yield_vega | 86 / 88 | 377 / 365 | |
| mpsc_ping_pong | 1,983 / 1,993 | 3,287 / 3,219 | **223 / 221** |
| mpsc_fan_in | 342 / 342 | 323 / 325 | **120 / 120** |
| semaphore | 381 / 378 | 1,082 / 1,092 | **298 / 296** |
| sleep_cancel | 1,518 / 1,411 | 1,689 / 1,645 | |
| sleep_many | 3,104 / 3,197 | **1,742 / 1,744** | |
| timeout_ok | 2,382 / 2,489 | 3,588 / 3,702 | |

- **Against Dispatch:**
  - Vega is 1.6–1.8× faster on hand-offs (ping-pong, mpsc ping-pong, chained spawn), 2.5–2.9× on the semaphore and 4× on `yield_vega`.
  - It is level on `spawn_many`, `pool_spawn` and `mpsc_fan_in`.
  - It is slower on `spawn_discard` (0.6–0.7×) and `sleep_many` (0.5–0.6×). `sleep_many` is the bench that spin 0 slowed down in the spin analysis above (2,585 ns at 50 µs).
- **Against Tokio:** Vega is 1.3× slower on the semaphore, 2.8× on fan-in, 3.6–4.6× on spawning and ping-pong, 6.4× on `yield_many` (2.2× with `Runtime.yield`) and 9× on mpsc ping-pong. Most of that is the Swift task and continuation machinery. On the box, Vega beats Tokio on ping-pong and the semaphore and is 2× behind on mpsc ping-pong, but there it runs on the patched Swift runtime (the Option 2 and Round 3 sections); macOS runs Apple's stock runtime. `spawn_many` is about 3.5× behind on both.

### Why `sleep_many` trails Dispatch on macOS

`sleep_many` (10,000 children of one task group, each sleeping 1 ms) costs Vega about 3.1 µs per sleep against Dispatch's 1.7 µs. Profiles (`sample`, 5 s) put the cost here:

- **Not kqueue, and not the timer wheel's own work.** `kevent` shows only as idle parking, and `Runtime.sleep` with the wheel takes 2–3% of busy samples.
- **Mostly the order in which the children finish.**
  - `swift::TaskGroup::removeChildTask` is the top busy frame at 18%. It does not appear in Dispatch's profile, where 45% is Dispatch's own spin-yield (`syscall_thread_switch`).
  - The runtime unlinks a finished child by walking the group's list from its oldest child, so the cost of a completion is its distance from the oldest unfinished child. A scratch test with 10,000 children shows the effect: completed oldest first, the group takes 19 ms; newest first, 315 ms (35 ms against 1,258 ms at 20,000).
  - Dispatch fires its timers from one heap in deadline order and runs them nearly FIFO. Vega does three things that shuffle the order:
    - It fires the per-worker timer shards one after another.
    - A worker whose local queue overflows sends the oldest half to the inject queue.
    - Idle workers steal batches.
- **Spin 0 costs about 0.5 µs of it.** With `VEGA_SPIN_NS=50000`, the figure is 2,682 against 3,199 ns.

Experiments, two rounds each:

- **Firing timers through the inject queue**, as the I/O driver does for large batches: `sleep_many` 3,087 / 3,010 → 2,811 / 2,807 ns, `timeout_ok` 2,259 / 2,210 → 2,336 / 2,356, and `sleep_cancel` noisy (1,624 / 1,604 → 1,617 / 2,000).
- **Putting every sleep on one shard** as well: 2,391 ns, but `sleep_cancel` rises to 1,983 ns from contention on the one shard lock. Even then `removeChildTask` keeps 14%, because workers running children in parallel finish them out of order.

Neither change is in. The remaining cost is the runtime's linear unlink, which only bites a group whose children all finish at once; a doubly linked child list in the patched runtime would remove it on Linux.

## Network.framework backend, indicative (2026-10-13)

TCP echo on the same M1 laptop as the macOS sections above, measuring what `IOBackend.network` costs against kqueue: `vega-echo` with 4 workers, driven by `echo-load` with 64-byte requests, 4 load threads, 10 s after a 2 s warm-up. The two backends ran in alternating rounds with a load average of about 4. "Pure Network.framework" is a 20-line server with no Vega, echoing on each connection's own dispatch queue. That server was measured in a single round of 8 s runs.

| Connections | Vega, kqueue | Vega, Network.framework | Pure Network.framework |
|---|---|---|---|
| 1, req/s (p50) | 49,400 / 49,612 (20 µs) | 19,078 / 19,202 (51 µs) | 28,563 (35 µs) |
| 64, req/s (p99) | 196,324 / 197,366 (600 µs) | 82,539 / 81,620 (1.23 ms) | 70,113 (1.14 ms) |
| 256, req/s (p99) | 197,711 / 198,331 (2.5 ms) | 86,892 / 84,128 (3.9–4.6 ms) | 68,874 (4.4 ms) |

- **The ceiling is Network.framework itself.**
  - On its own, Network.framework echoes about 70k requests per second, a third of what Vega does over kqueue.
  - A profile of Vega on Network.framework at 64 connections (`sample`, 4 s) puts 24% of busy samples in dispatch thread start-up (`start_wqthread`), 27% in the kernel (`sendmsg`, `recvmsg`, wakes), and 17% in Objective-C retain and release and malloc.
  - Vega's own code, bridging included, is 3.9%.
- **The bridge costs about 16 µs of latency.**
  - With one connection, a round trip takes 51 µs against 35 µs for the pure server.
  - That is the hop from Network.framework's callback queue to a Vega worker and back, twice per request.
- **Under load the bridge pays for itself.** At 64 and 256 connections Vega over Network.framework is 16–26% ahead of the pure server, because Vega's workers run connection tasks in parallel while Network.framework only delivers callbacks.
- **Routing the callbacks through fewer queues didn't help.** Giving every connection one of 4 serial target queues instead of one concurrent queue measured 77,620 req/s at 64 connections. That is slightly worse, so it was not kept.
- **No cost to kqueue.** Every stream operation now checks whether the socket is a Network.framework one. Through that branch, kqueue measures 196,324 / 197,366 req/s at 64 connections, against 197,330 / 197,374 before.

So on macOS, kqueue stays the default for servers. `.network` is for iOS, tvOS, watchOS and visionOS, and for clients that need what only Network.framework provides: cellular and VPN bring-up, interface choice, system proxies, and the system's own name resolution and Happy Eyeballs. In this test, Vega served 16–26% more than callback-style Network.framework code under load; the iOS simulator runs the network suites but wasn't benchmarked.

## Sync primitives (2026-10-12)

8 workers, executor preference, median of 9 runs, in ns/op. Tokio's numbers come from the same benchmarks in `tokio-bench`.

- **mpsc_ping_pong:** one value bounced through two capacity-1 channels, 100k round trips.
- **mpsc_fan_in:** 8 producers × 12,500 sends into one channel bounded at 1,024, with one consumer.
- **semaphore:** 200 tasks × 500 acquire/release on 2 permits.

| Bench | Swift default | Vega, stock runtime | Vega, patched runtime | Tokio |
|---|---|---|---|---|
| mpsc_ping_pong | 10,094 | 2,418 | 987 | **492** |
| mpsc_fan_in | 3,459 | 784 | 473 | **227** |
| semaphore | 3,684 | 548 | **348** | 463 |

**Specialization.** At first `Channel` and `Oneshot` were ordinary generic code. Called from another module they ran unspecialized, through value witnesses for every push and pop. That made mpsc_ping_pong 2,160 ns and mpsc_fan_in 1,090 ns on the patched runtime. Building with `-cross-module-optimization` cut those to 892 and 456, which showed that missed specialization was nearly all of the cost. Apps shouldn't need an unsafe flag to get that speed, so the channel types, their cores, `RawRing` and `RawLock` are now `@inlinable`/`@usableFromInline`. A plain release build matches the CMO numbers.

**What is left against Tokio:**
- **mpsc_ping_pong.** Every operation parks one side and wakes the other. It costs about what two `Notify` round trips cost (ping_pong_notify: 776 ns), so the time is in park and wake, not in the channel. The status record from `withTaskCancellationHandler` is the largest part.
- **mpsc_fan_in.** Nine threads share one lock. Tokio's senders reserve a slot with one atomic add on a lock-free block list. Vega would need the same structure to close this gap.
- **semaphore.** On the patched runtime, Vega is ahead of Tokio. With nobody waiting, acquire and release are single CASes.

### Non-cancellable waits (stock runtime)

`Sender.sendIgnoringCancellation`, `Receiver.receiveIgnoringCancellation` and `Semaphore.acquireIgnoringCancellation` park without `withTaskCancellationHandler`, so the runtime adds no status record per wait. They are opt-in, for loops that are never cancelled mid-wait, the same trade as `Notify.notifiedIgnoringCancellation`. 8 workers, stock 6.3.3 runtime, median of 9 runs, ns/op.

| Bench | Cancellable | Non-cancellable | Change |
|---|---|---|---|
| mpsc_ping_pong | 2,275 | 1,651 | −27% |
| semaphore | 565 | 491 | −13% |
| mpsc_fan_in | 673 | 750 | +11% |

- **mpsc_ping_pong and semaphore.** Both park on most operations, so skipping the status record pays off.
- **mpsc_fan_in.** The receiver rarely parks, so the status record costs little there. It got slower in both modes, and the cause isn't known yet.

## Hummingbird and Vapor on VegaNIO, and native VegaHTTP1 (2026-10-13/14)

Requests per second against [the-benchmarker/web-frameworks](https://github.com/the-benchmarker/web-frameworks)' HTTP contract, run with `~/wl/benchmarks/frameworks.sh` on the box. The servers:

- **Hummingbird 2 and Vapor 4,** built from `VegaNIO/Examples`, each on NIOPosix (`MultiThreadedEventLoopGroup`) and on VegaNIO (`VegaEventLoopGroup`), with the same binary for both. See [HUMMINGBIRD2.md](HUMMINGBIRD2.md) and [VAPOR.md](VAPOR.md).
- **Native Vega:** `Benchmarks/Sources/vega-http`, `HTTP1Server` from VegaHTTP1 with one task per connection. It has no NIO, no framework and no router, and it adds no `date` or `server` header.
- **Native NIO:** `Benchmarks/nio-http`, the same contract on NIOPosix and NIOHTTP1 with no framework (sweep 4 only).

**Load.**
- **Ramp** is the-benchmarker's own load: `zrk -R1000:500000`, an open-loop ramp from 1,000 to 500,000 requests a second over 15 s, after a 5 s warm-up. The figure is zrk's achieved rate. Every server is overloaded by the end of the ramp, so its latencies are mostly queueing, not service time.
- **Closed** is `oha -c N` for 15 s, which measures capacity instead.
- The server and the load generator run unpinned on the same 8 threads, so a faster server leaves the load generator less CPU.

Arms rotate their position each round. No run had errors. Compare ratios within one sweep: Hummingbird on NIOPosix measured 59k at 512 connections in the first two sweeps and 65k in the third, with the same binary.

**VegaNIO against NIOPosix, sweep 1** (319d29e, flush through the writer task), median of 5 rounds, req/s:

| Server | 64 conns | 256 conns | 512 conns |
|---|---|---|---|
| Hummingbird, NIOPosix, ramp | 59,578 | 60,804 | 58,937 |
| Hummingbird, VegaNIO, ramp | 56,341 (0.95×) | 60,362 (0.99×) | 58,841 (1.00×) |
| Vapor, NIOPosix, ramp | 48,438 | 48,564 | 48,143 |
| Vapor, VegaNIO, ramp | 46,212 (0.95×) | 45,710 (0.94×) | 45,102 (0.94×) |
| Hummingbird, NIOPosix, closed | 53,855 | 57,273 | 56,732 |
| Hummingbird, VegaNIO, closed | 50,871 (0.94×) | 56,075 (0.98×) | 55,485 (0.98×) |
| Vapor, NIOPosix, closed | 41,877 | 42,003 | 41,587 |
| Vapor, VegaNIO, closed | 40,174 (0.96×) | 39,598 (0.94×) | 39,438 (0.95×) |

Closed-loop p50 at 512 connections was 8.5 ms for Hummingbird on both groups, and 11.6 ms against 12.7 ms for Vapor.

**Sweep 2** (be9997e, `flush` writes inline as NIO's does, and only what the socket doesn't take goes to the writer task), ramp, 2 rounds. Vapor on VegaNIO moved to 0.97–0.99× of NIOPosix (from 0.94–0.95×). Hummingbird stayed level at 256 and 512 connections; its 64-connection ratio is noise at 2 rounds (one NIOPosix round measured 65.6k, the other 58.8k).

**Native VegaHTTP1, sweep 3** (be9997e), ramp, 512 connections, 2 rounds, req/s:

| Server | Round 1 | Round 2 | p50 |
|---|---|---|---|
| Hummingbird, NIOPosix | 65,495 | 65,487 | 2.6–2.7 s |
| Hummingbird, VegaNIO | 62,069 | 63,090 | 2.7–2.8 s |
| Vapor, NIOPosix | 55,433 | 48,263 | 2.8–2.9 s |
| Vapor, VegaNIO | 47,267 | 46,779 | 2.6–2.7 s |
| **Native Vega (VegaHTTP1)** | **158,388** | **169,734** | **0.6 s** |

- **VegaNIO is at parity with NIOPosix, not faster.** NIO's pipeline, its `EventLoopFuture`s, its HTTP/1 codec and the framework above them all stay, and they cost more than the event loop underneath. Swapping the event loop moves throughput by about 5% either way.
- **Native Vega does 2.4–2.6× Hummingbird and about 3.3× Vapor.** Most of that gap is the framework, not NIO: see sweep 4.
- **Vapor on NIOPosix in sweep 3** is noisy: 55.4k then 48.3k. Sweeps 1 and 2 had it near 48k, so the first round is probably the outlier.

**NIOPosix against Vega without a framework, sweep 4** (e8fb356), 512 connections, 2 rounds, req/s. `Benchmarks/nio-http` is the counterpart of `vega-http`: NIOPosix with NIO's own HTTP/1 handlers (`configureHTTPServerPipeline`) and one handler that answers the same three routes with the same headers (only `content-length`). Both use 8 threads and TCP_NODELAY.

| Server | Ramp r1 | Ramp r2 | Closed r1 | Closed r2 | Closed p50 / p99 |
|---|---|---|---|---|---|
| Hummingbird, NIOPosix | 65,423 | 65,916 | 57,292 | 56,786 | 8.4 / 19.3 ms |
| nio-http (NIOPosix + NIOHTTP1) | 141,944 | 143,655 | 112,248 | 111,937 | 4.6 / 11.1 ms |
| **vega-http (VegaHTTP1)** | **195,524** | **178,104** | **128,825** | **129,529** | **3.7 / 10.8 ms** |

- **Vega against NIO is 1.24–1.38× under the ramp and 1.15× closed-loop,** with a 20% lower closed-loop median latency and the same p99.
- **Hummingbird's own layers halve NIO's throughput:** nio-http does 2.0× (closed) to 2.2× (ramp) Hummingbird on the same NIOPosix. So of native Vega's 2.5–2.9× over Hummingbird, about 2× is the framework and 1.15–1.3× is NIO against Vega.
- **The load generator is likely the limit for both bare servers,** more so closed-loop: oha costs more CPU per request than zrk, and it shares the 8 threads with the server. The closed-loop ratio is the one most likely understated. The plan's target is 1.5× NIO on HTTP/1. Measuring it properly needs the load generator on other cores (`PIN=`) or another machine.

**Pinned, with drivers and profiles, sweep 5** (e8fb356). The server runs with `--workers 4` on physical cores 0–1 (CPUs 0,1,4,5), and oha runs closed-loop on cores 2–3 (CPUs 2,3,6,7), so the two no longer compete for CPU. 512 connections, 15 s, 2 rounds alternated, no errors. System calls are counted by `perf stat -e raw_syscalls:sys_enter` on the server.

| Server | req/s | p50 | p99 | Syscalls per request |
|---|---|---|---|---|
| vega-http, io_uring (default) | 126,511 / 122,043 | 4.0–4.2 ms | **5.4–5.9 ms** | **1.0** |
| vega-http, epoll (`VEGA_DRIVER=epoll`) | 135,821 / 123,027 | 3.7–4.1 ms | 7.7–8.5 ms | 2.0 |
| nio-http (NIOPosix, epoll) | 100,568 / 98,532 | 5.1 ms | 9.9 ms | 2.0 |

- **Vega is 1.22–1.35× NIO on either driver.** On epoll it makes the same two syscalls per request as NIO (a `read` and a `send`), so the gain is in user space, not in io_uring.
- **io_uring buys tail latency, not throughput, here.** Multishot receive leaves one syscall per request, the `send`, and p99 is 30–45% lower than on epoll. Throughput is level within the noise between rounds.
- **Where vega-http's time goes** (`perf record` on the server, io_uring):
  - The kernel takes 48%. `send` alone is 38%, because on loopback the sender's syscall also runs the receiver's TCP path in softirq. That part would leave the server on a real NIC.
  - vega-http's own code takes 23%: HTTP parsing (`parseFields`, `findHeadEnd`, the request decoder), `HTTPFields` lookups and the scheduler.
  - libswiftCore takes 14%: String and Array allocation; retain and release are only about 2%.
  - libswift_Concurrency takes 9.5%: task switches at each `await`, namely `withStatusRecordLock`, the task allocator and `getPreferredTaskExecutor`.
- **NIO's profile, for comparison:** kernel 41%, libswiftCore 27% (`swift_retain` and `swift_release` alone are 12.8%), plus `tryCast` and exclusivity checks (`swift_beginAccess`).
- **Next for Vega's HTTP/1 path:** header names as bytes and allocation-free lookups of `content-length` and `connection`; fewer String allocations per response; and sending through io_uring, or coalescing pipelined responses.

## Measurement notes

- **Wi-Fi can't drive the HTTP benchmarks.** A load generator on the dev machine reaches the box only over Wi-Fi, with a 7–80 ms round trip. Over Wi-Fi at 512 connections, vega-http and nio-http both measured 15–21k req/s, with no consistent order between rounds, and both measured about 6.4k at 64 connections: the round trip sets the rate. A second machine needs a wired gigabit link.

- **`sleep_many` is bimodal on the box.** A run lands near 2.8 µs per op or near 5.8 µs, with nothing in between. A bisect over eight commits, from bebf35b to 87d7874, run alternately on 2026-10-13, showed both modes at every commit. So `sleep_many` can't confirm a regression from a single run. The likely causes are the 1 ms timer tick against each run's start time, and the box's `powersave` governor, which leaves idle cores at 400 MHz. Compare `sleep_many` only A/B and alternated, across several rounds.
- **Compare commits A/B on the box,** with both binaries in the same session and alternated. Absolute numbers drift between sessions with the CPU frequency.
