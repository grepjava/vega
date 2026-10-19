# Vega's architecture

How Vega is built, for someone about to change it or wanting to know why it
performs as it does. [README.md](README.md) says what Vega is for,
[RELEASE.md](RELEASE.md) what each release changed, and
[docs/PLAN.md](docs/PLAN.md) holds the original plan, the parity matrix and
the measurements behind several choices below.

```
Supervisor process (optional, POSIX)            Runtime.sharded
 └─ Shard process × K, each with its own runtime and listeners
     └─ Runtime
         ├─ Worker × T          one thread each: LIFO slot, local queue (256),
         │                      timer shard, and (io_uring) its own ring
         ├─ Inject queue        jobs from outside the workers, and overflow
         ├─ Idle set            who is parked, how many are searching
         ├─ I/O driver          epoll / kqueue / IOCP per runtime, or a ring per worker
         └─ Blocking pool       threads for work that blocks
```

## Three ideas

1. **Tokio's scheduler, run as a Swift executor.** Swift has no runtime of
   its own to speak of: tasks are jobs handed to an executor. Vega's
   `Scheduler` is a `TaskExecutor` that does what Tokio's multi-threaded
   scheduler does: per-worker queues, work stealing, a LIFO slot, a
   cooperative budget, and workers that park in the I/O driver.
2. **Nothing on the hot path pays for ARC or allocation.** Streams are
   `~Copyable`, so a socket has one owner and closes when dropped. Buffers,
   timer entries and waiters are raw memory or intrusive nodes. Where a class
   is unavoidable, the hot path holds it unowned. The effect is checked in the
   disassembly, not assumed.
3. **Sans-I/O protocols.** HTTP/2, HTTP/3, WebSocket and QUIC are state
   machines in their `Core` modules: bytes in, bytes and events out, no clock
   and no sockets. The networked modules drive them on Vega's sockets; a
   server with its own I/O, such as Garuda, drives them directly.

## The runtime

A `Runtime` owns the worker threads, the I/O driver, the timers and the
blocking pool. `Runtime(configuration:)` sets it up, and `spawn` and `block`
run tasks on it. Swift drops the executor preference for an unstructured
`Task {}`, so code reaches Vega either through `spawn`, or by making the
runtime the process's global executor (`installGlobal`, and a shard's
runtime on Linux). Apple's SDKs leave out the SPI that replaces the global
executor, so there only global enqueues come to Vega.

Vega is built with `NonisolatedNonsendingByDefault`: an async function runs
on its caller's executor, so returning from `read` or `write` is no hop.

### Workers and queues

Each worker runs jobs in this order, as Tokio's do:

- **The LIFO slot.** A task woken by the job running now goes in the slot and
  runs next, which keeps a request and its reply on one warm core. After 3 in
  a row from the slot, its job goes to the back of the queue instead, so two
  tasks waking each other can't starve the rest (`Worker.lifoLimit`).
- **The local queue.** A 256-slot ring of jobs (`LocalQueue`). The owner
  pushes without a compare-and-swap. A thief takes half through one packed
  atomic holding the steal head and the real head. When it overflows, half
  moves to the inject queue.
- **The inject queue.** Jobs enqueued from threads that aren't workers, and
  overflow. A growable ring behind a lock, with a count so workers skip the
  lock when it is empty. Every 31 ticks a worker checks it first, so outside
  work isn't starved by a busy local queue.
- **Stealing.** A worker with nothing local tries a random victim. At most
  half the workers search at once (`Idle`). An enqueue wakes a sleeper only
  if nobody is searching, and the last searcher to stop wakes one more if work
  is still pending.
- **Parking.** A worker that finds nothing spins briefly (50 µs on Linux by
  default: `idleSpin`, `VEGA_SPIN_NS`), then sleeps. The worker that owns the
  timers sleeps in the I/O driver with the next deadline as its timeout. Busy
  workers poll the driver and timers every 61 ticks.

### The cooperative budget

Swift can't preempt a task, so a task that never waits would hold its worker
forever. Each poll gets a budget of 128 (Tokio's figure). Vega's primitives
spend from it, and a task that runs out yields at its next Vega call
(`Runtime.consumeBudget`). Metrics count the forced yields.

### Timers

Each worker has a timer shard: a hierarchical wheel of 6 levels × 64 slots
at 1 ms per level-0 slot, behind its own lock, so workers adding timers don't
contend (`TimerWheel`, after Tokio's). Entries are raw memory from the
shard's free list, linked into slots, so inserting and cancelling allocate
nothing and cost O(1). A timer cascades down at most 5 times on its way to
firing. An entry fires one of four things: a job Swift handed over
(`Task.sleep`), a parked `Runtime.sleep`, a cancellation (`Runtime.timeout`'s
child task), or a `withIOTimeout` deadline.

`Runtime.timeout(for:)` runs its operation as a child task and cancels that
child on time. `Runtime.withIOTimeout(for:)` is cheaper (about 0.5 µs against
3 µs): it bounds only the I/O waits inside it, in the calling task, and a
wait still pending at the deadline throws `IOError.timedOut`. Servers use it
around each read and write.

### The blocking pool

Work that blocks a thread — `getaddrinfo`, file I/O off io_uring, foreign
code — runs on the blocking pool, Tokio's `spawn_blocking`. Threads start on
demand up to a limit, and exit after sitting idle. `Runtime.blocking` always
waits its turn; `Runtime.tryBlocking` returns nil when the queue is full, so
a server can answer 503 instead of falling further behind.
`Runtime.blockInPlace` hands the worker's queue to another thread and blocks
where it is.

## I/O

The public API is completion-shaped: `read(into: &buffer)` and
`write(buffer)` take the caller's `IOBuffer` and return when the operation is
done. That is the native model of io_uring, IOCP and Network.framework. The
readiness backends emulate it: try the system call, and on `EAGAIN` wait for
readiness and try again.

| Backend | Where | Shape |
|---|---|---|
| io_uring (`.ioUring`) | Linux 6.7 and later, the default there | one ring per worker (`SINGLE_ISSUER`, `DEFER_TASKRUN`), submitted and completed on that worker's ring, resumed on any thread; system calls made directly, no liburing |
| readiness (`.readiness`) | Linux fallback, macOS | one edge-triggered epoll or kqueue per runtime |
| IOCP (`.iocp`) | Windows, the default there | one completion port per runtime; every operation that would wait is an overlapped request, tried first as a non-blocking call |
| AFD readiness | Windows (`VEGA_DRIVER=afd`) | readiness polls through `\Device\Afd`, as Tokio's mio does |
| Network.framework (`.network`) | iOS, tvOS, watchOS, visionOS; opt-in on macOS | `NWConnection` and `NWListener` for TCP, with its TLS; kqueue for the rest |

The backend is chosen once per runtime (`IOBackend.automatic` picks the best
the platform can run, and `VEGA_DRIVER` overrides), and is a closed set
switched over in `@inlinable` code, never an existential. An operation in
flight keeps its buffer alive until the kernel's completion arrives, even
after cancellation. Cancellation is the task's: cancelling it cancels the
operation (`ASYNC_CANCEL`, `CancelIoEx`), and the wait throws
`IOError.cancelled`.

What the Windows backends do in detail, and the loopback numbers that chose
between them, are in [docs/PLAN.md](docs/PLAN.md#drivers-one-completion-shaped-api-five-backends).

### Buffers

`IOBuffer` is `~Copyable`: the bytes have one owner, and a read fills it in
place. Its `count` is read-only outside Vega, so safe code can't read past
what was written. VegaWire's `ByteBuffer` is the protocol layer's buffer:
three words and a pointer, freed by hand at one place, so a connection table
can hold thousands without ARC.

### Sockets and streams

TCP, UDP (with batched sends and receives, GSO and GRO), Unix stream and
datagram sockets, raw sockets, vsock and pipes are all `~Copyable`, and the
stream ones are `AsyncReader` and `AsyncWriter`. `split()` gives a read half
and a write half (`StreamHalves`) that two tasks use at once; dropping the
write half sends end-of-stream. `TCPServer` and `TCPClient` (Happy
Eyeballs v2) are the bootstraps. DNS runs `getaddrinfo` on the blocking pool,
or Vega's own UDP resolver.

## Synchronisation

`Notify`, `Semaphore`, `Barrier`, `OnceCell`, `AsyncMutex`, `AsyncRWLock`,
`MPSCChannel`, `Broadcast`, `Watch` and `Oneshot` park waiters as intrusive
nodes inside the waiting task's continuation frame (`WaitList`), so a wait
allocates nothing. Locks are short and held only to link and unlink.
Package code locks with `Locked` (a `RawLock`) rather than
`Synchronization.Mutex` where ThreadSanitizer must see the lock, since it
doesn't see `Mutex` on Linux. Shared atomics are padded to 128 bytes.

One rule for cancellation runs through all of it: a wait with its own error
type throws that type's `.cancelled`; a wait without one throws
`CancellationError`; something handing out a sequence returns nil.

## Sharding

`Runtime.sharded` runs a server as K processes, each with its own runtime
pinned to its share of the CPUs, the shape Garuda had before Vega. A
supervisor forks the shards before any thread starts, gives each its
listeners (one shared socket, or one per shard with `SO_REUSEPORT`), maps
the memory they share, and restarts a shard that dies. A trap then takes
down one shard's connections, not the server's. K defaults to one per
last-level-cache domain. It needs `fork`, so it is POSIX only.
[docs/SHARDING.md](docs/SHARDING.md) covers it.

## Protocols

| Module | What |
|---|---|
| `VegaIO` | `FrameDecoder`, `FrameEncoder`, `FramedRead`, `FramedWrite`, buffered readers and writers, `copy`, length-delimited and line codecs |
| `VegaTLS` | `TLSStream` over any stream, on OpenSSL 3 or vendored BoringSSL through Vega's own BIO; kernel TLS offload on Linux |
| `VegaCrypto` | hashes, HMAC, HKDF, PBKDF2, AEADs, key exchange, signatures and certificate checks, on the same library; QUIC's TLS 1.3 is built on it |
| `VegaHTTP` | the HTTP types the three versions share |
| `VegaHTTP1`, `VegaHTTP2`, `VegaHTTP3` | servers and clients with whole bodies; each server takes a `ShutdownToken` and drains |
| `VegaWebSocket` | connections and permessage-deflate |
| `VegaQUIC` | `QUICEndpoint`, `QUICConnection` and `QUICStream` on Vega's UDP sockets: one endpoint task per socket owns the state machines, and the application's tasks hand it work |
| `Vega*Core` | each protocol's state machine, sans I/O: HPACK and frame headers, QPACK and HTTP/3 frames, WebSocket frames, and QUIC v1 and v2 (packets and their protection, loss recovery, congestion control, streams, path validation, both sides of the TLS 1.3 handshake) |

### Access tiers

The public API is the vocabulary, frozen at 1.0. What only Garuda needs, such
as the QUIC state machine and HPACK, is `@_spi(Garuda)`; what Vega's modules
share among themselves is `package`. A type that will grow is a struct with
static members rather than an enum, and every error is a struct with a
`code`, so adding a kind breaks nobody.

## Testing

The same suite runs on every backend (`VEGA_DRIVER`) and on Linux, macOS, the
iOS simulator and Windows; ThreadSanitizer runs on Linux. `VegaTest` provides
`Runtime.seeded` (a reproducible schedule), `MockClock` (paused time),
in-memory `duplex()` streams and `FaultyStream` (short reads, split writes,
delays, resets). CI is local rather than hosted: `ci/run.ps1` sends the
working tree to a Linux box, where `ci/linux.sh` runs io_uring, epoll,
BoringSSL and ThreadSanitizer in Docker; `ci/macos.sh` runs macOS
and the iOS simulator, and `ci/windows.ps1` Windows.

## Packages around Vega

Vega itself has no dependencies. `Benchmarks/` is a package of its own.
[vega-nio](https://github.com/grepjava/vega-nio) is a repository of its own: VegaNIO (SwiftNIO's
`EventLoopGroup`, `Channel` and bootstraps on Vega, which Hummingbird and
Vapor run on), and VegaSwiftMetrics and VegaLogging, which report
`Runtime.metrics` and slow polls through swift-metrics and swift-log.
