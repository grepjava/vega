# Vega: a high-speed Swift I/O engine with Tokio and SwiftNIO feature parity

## Context

You want a Swift networking engine that **fully replaces SwiftNIO**, has **feature parity with Tokio and SwiftNIO**, and is faster than both on Swift. It should be built on Swift 6.2+ concurrency and a Tokio-style work-stealing scheduler, with no backward-compatibility burden. Later it will be Garuda's engine.

**Starting point.** Garuda doesn't use SwiftNIO. It runs on **aviancore** (`D:\code\aviancore`, 0.7.3, 25k lines, zero dependencies, vendored BoringSSL). aviancore runs one level-triggered epoll/kqueue loop per forked process, through `Poller.swift`, `LoopExecutor.swift` and `BufferPool.swift`. Garuda's `ARCHITECTURE.md:291-364` records where that model falls short:
- Under skewed load it served 20k quick req/s against Tokio/axum's 49k.
- TLS, HTTP/2 and requests already in progress can never be rebalanced.

**Decisions made:**
1. **Fault model: hybrid** (shard processes × work-stealing threads). Single-process modes remain available, as in Tokio.
2. **Location:** Vega is its own repo, `D:\code\vega` (github.com/grepjava/vega). It absorbs aviancore's lower layers (C syscall shims, `ByteBuffer`, TLS, the HTTP and QUIC codecs) as it needs them, and becomes the successor to aviancore 1.0.
3. **I/O backends:** readiness and completion are both first-class.
4. **First milestone (v0.1):** runtime, TCP/UDP and timers.
5. **API:** its own native async API with full feature parity. **It is also swappable with SwiftNIO** through `VegaNIO`, a separate package that depends on swift-nio's `NIOCore`.
   - It provides `VegaEventLoopGroup` and `VegaEventLoop` (serial executors pinned to Vega workers) and Vega-backed `MPSCChannel`s and bootstraps. These channels use NIO's own `ChannelPipeline`, the same way NIOTransportServices does.
   - Vapor, Hummingbird, AsyncHTTPClient and grpc-swift then run on Vega just by swapping the `EventLoopGroup`.
   - VegaNIO is an API adapter, not a second engine: Vega does the I/O underneath.
   - NIO promises that a channel's handlers always run on one thread (lock-free handler state, `assertInEventLoop`, `EventLoopFuture` callbacks), so **pipeline handlers stay pinned**.
   - With Vega installed as the global executor, apps' `async` route handlers and business logic run as ordinary Swift tasks and **are stolen**.
   - Idle connections are moved between loops between requests (Garuda-style rebalancing).
   - Native Vega code gets full stealing everywhere.
6. **Platforms:** Linux (epoll + io_uring), macOS (kqueue), Windows (IOCP), and iOS/Apple clients (Network.framework).

### Why it beats SwiftNIO
| SwiftNIO | Vega |
|---|---|
| Each channel is pinned to one EventLoop, so there is no stealing | Tasks are stolen at any `await`, so TLS, HTTP/2 and in-flight work all rebalance |
| `ChannelPipeline` calls handlers through existentials, and every `EventLoopFuture` allocates | Plain `async` code plus generic, specialised `Codec`s, with no futures |
| `ByteBuffer` is a copy-on-write class, so every buffer is refcounted | Owned `~Copyable` `IOBuffer`, pooled per worker |
| `NIOAsyncChannel` bridges callbacks to async | Drivers resume continuations directly |
| Readiness I/O only, and keeps Swift 5 compatibility | io_uring (multishot, provided buffers, `SEND_ZC`) and IOCP; Swift 6.2+ only (typed throws, `~Copyable`, `Span`) |

## Feature-parity matrix (what "done" means for 1.0)

| Area | Tokio / SwiftNIO feature | Vega module |
|---|---|---|
| **Runtime** | multi-thread and current-thread runtimes, `LocalSet`, `block_on`, builder, `EventLoopGroup` | `Vega` — `Runtime.multiThread / .currentThread / .sharded(K)`, `LocalExecutor` (`!Send` work: an actor whose jobs run only on one worker), `Runtime.block(on:)` |
| **Tasks** | `spawn`, `JoinHandle`, `JoinSet`, `abort`, task-locals, `yield_now`, `spawn_blocking`, `block_in_place` | `Runtime.spawn`, `JoinSet` (unscoped, results in completion order, cancelled when dropped), `TaskPool`, `Runtime.blocking`, `Runtime.blockInPlace`, `Runtime.yield`; task-locals are Swift's `@TaskLocal`, inherited by all of these but `TaskPool` |
| **Scheduling** | work stealing, LIFO slot, coop budget, runtime metrics | `Vega/Scheduler` |
| **Time** | sleep, interval, timeout, paused/mock clock | `Vega/Time` + `VegaTest.MockClock` |
| **Net** | TCP, UDP (incl. multicast), Unix stream/datagram, `socket2`-style options, `NIOPipeBootstrap`, raw sockets, vsock | `Vega/Net`: `RawSocket` (SOCK_RAW and the unprivileged ICMP ping socket; Linux, Darwin), `VsockListener`/`VsockStream` (Linux) |
| **Bootstrap** | `ServerBootstrap`, `ClientBootstrap`, `DatagramBootstrap`, happy eyeballs | `TCPServer`, `TCPClient` (Happy Eyeballs v2) in `Vega` |
| **DNS** | `lookup_host`, NIO resolver | `Resolver` (blocking-pool getaddrinfo, plus an async UDP resolver; reuse Garuda's `Resolver`) |
| **IO traits/codecs** | `AsyncRead/Write`, `BufReader/Writer`, `copy`, `split`, `Framed`, `LengthDelimited`, `Lines`, `ByteToMessageDecoder`, `MessageToByteEncoder`, `NIOExtras` (line-based, length-field, JSON-RPC framing, PCAP, write-coalescing) | `VegaIO`: `AsyncReader/Writer` protocols, `FramedRead/FramedWrite`, `BufferedReader/Writer`, `copy`, `copyBidirectional`, lines, length-delimited and Content-Length (JSON-RPC) codecs |
| **Sync** | `Mutex`, `RwLock`, `Semaphore`, `Notify`, `Barrier`, `oneshot`, `mpsc`, `broadcast`, `watch`, `OnceCell` | `Vega/Sync` |
| **Process / signal / fs** | `tokio::process`, `tokio::signal`, `tokio::fs`, `NIOFileSystem`, `NIOFileHandle` | `VegaProcess`, `VegaFS` (io_uring/IOCP native; blocking pool on other drivers); signals are `Runtime.signals` in `Vega` itself (a self-pipe and one thread, no driver involved), not a module of their own |
| **Streams** | `tokio-stream`, `AsyncSequence` bridging, backpressure | `AsyncSequence` adapters (`FramedRead.items()`, `MPSCChannel.Receiver.values()`); a bounded `MPSCChannel` is the `NIOAsyncSequenceProducer` equivalent |
| **TLS** | `tokio-rustls`, `swift-nio-ssl`, ALPN, SNI, mTLS, session resumption, kTLS | `VegaTLS` (OpenSSL 3, or vendored BoringSSL); on Apple's `IOBackend.network`, `NetworkTLS`: Network.framework's own TLS for clients and servers (`TCPStream.connect(host:port:tls:)`, `TCPListener.bind(...tls:)`, ALPN, SNI, system or anchored trust, mutual TLS), as NIOTransportServices' `tlsOptions`. kTLS: `TLSConfiguration.kernelOffload` (`.transmit` / `.transmitAndReceive`) hands records to Linux's kernel TLS after the handshake, with OpenSSL or BoringSSL. Keys come from the key log (TLS 1.3) or the master secret (TLS 1.2), since both libraries run over Vega's own BIO. `sendFile` over TLS uses sendfile(2). close_notify and KeyUpdate are sent as typed records; on receive, alerts, tickets and KeyUpdate are handled, with rekey on Linux 6.14+. Falls back to userspace silently |
| **HTTP** | `swift-nio-http2`, `NIOHTTP1`, `NIOWebSocket`, `hyper` (h1/h2), `h3` | `VegaHTTP1`, `VegaHTTP2`, `VegaHTTP3`, `VegaWebSocket` over `VegaQUIC` (UDP endpoint); each protocol's sans-I/O logic in its `Core` module (`VegaHTTP2Core`, `VegaHTTP3Core`, `VegaWebSocketCore`, `VegaQUICCore`) |
| **Extras** | `NIOExtras` (quiescing, debug handlers), SOCKS, HTTP proxy, compression | `Quiesce` (graceful shutdown) in `Vega`; `VegaProxy` (SOCKS5, CONNECT); `VegaCompression` (gzip, deflate, brotli, zstd) |
| **Testing** | `EmbeddedChannel`, `NIOAsyncTestingChannel`, `tokio::test`, `loom`-style checks, paused time | `VegaTest`: `Runtime.seeded` and `Simulation` (seeded schedules, replayable), `MockClock`, in-memory duplex streams, `FaultyStream` (short reads, split writes, delays, resets) |
| **Observability** | `tracing`, `tokio-console`, runtime metrics, swift-log/metrics | `Runtime.metrics` (lock-free per-worker counters, poll histograms), `Runtime.onSlowPoll`, `VegaMetrics` (sampling, Prometheus text); the `Adapters` package: `VegaSwiftMetrics` (`reportMetrics`) and `VegaLogging` (`logSlowPolls`) |
| **Platforms** | Linux, macOS, Windows, iOS (NIOTS) | the drivers below |

## Architecture

```
Supervisor (existing av_fork_worker machinery: reload, signals) — POSIX servers only
 └─ Shard process × K   (Runtime.sharded; K=1 ⇒ plain Tokio-style multiThread)
     └─ Runtime: T worker threads, pinned to the shard's cores
         ├─ Worker i: LIFO slot + local queue(256) + Driver i + TimerWheel i
         ├─ Inject queue (MPSC) + Idle set (searching/parked)
         └─ Blocking pool
```

- **Runtime flavours.** `.currentThread` (tests, clients, iOS), `.multiThread(T)` (the default, as in Tokio), and `.sharded(K, T)` (Garuda: K defaults to the L3/NUMA domains). With K = cores and T = 1 it reproduces Garuda's current model exactly.
- **Sharding order.** Fork all shards before spawning any thread, and give each shard its own `SO_REUSEPORT` listener. A Swift trap then kills only 1/K of the connections. Sharding needs `fork`, so it is POSIX only; Windows and iOS use `.multiThread`.

### Scheduler (follows Tokio's multi-threaded scheduler)
- **Executor integration.**
  - Vega implements `TaskExecutor`.
  - Spawned tasks use `Task(executorPreference:)`.
  - Wherever the toolchain allows replacing the global executor, Vega installs itself there too. Phase 0 confirms which hooks Swift 6.2/6.3 offers.
  - `nonisolated(nonsending)` keeps called code on the caller's executor.
- **Local queue.**
  - A 256-slot ring of `UnownedJob` per worker.
  - The owner pushes without CAS.
  - Thieves take half the queue through one packed `Atomic<UInt64>` holding (steal head, real head).
  - On overflow, half the queue moves to the inject queue.
- **Ordering and stealing.**
  - The LIFO slot is capped at 3 consecutive uses.
  - Every 61 ticks the worker polls its driver; every 31 ticks it checks the inject queue first.
  - Victims are picked at random.
  - At most ⌈T/2⌉ workers search at once.
- **Parking.**
  - A worker with nothing to do blocks in its own driver, with the next timer as the timeout.
  - Wakes from other threads use eventfd, `EVFILT_USER`, `IORING_OP_MSG_RING` or `PostQueuedCompletionStatus`.
- **Cooperative budget.**
  - Every Vega primitive spends from a per-task budget of 128 and yields when it runs out, because Swift cannot preempt tasks.
- **Allocation-free hot path.** `TaskPool` reuses long-lived tasks, the pattern from Garuda's `HandlerTasks.swift`.

### Drivers: one completion-shaped API, five backends
The public I/O API passes **owned buffers** in and returns them out. That is the native model of io_uring, IOCP and Network.framework, and the readiness backends emulate it with try-the-syscall, `EAGAIN`, wait, retry.

```swift
public struct IOBuffer: ~Copyable { /* owned bytes; the kernel may own them mid-operation */ }
public struct TCPStream: ~Copyable, Sendable {
  public func read(into buf: consuming IOBuffer) async throws(IOError) -> IOBuffer
  public func write(_ buf: consuming IOBuffer) async throws(IOError) -> IOBuffer
  public func writev(_ bufs: consuming IOBufferChain) async throws(IOError) -> IOBufferChain
  public func sendfile(_ file: borrowing File, offset: Int, count: Int) async throws(IOError) -> Int
  public consuming func split() -> (ReadHalf, WriteHalf)
}
public protocol Codec { associatedtype Item; mutating func decode(_ buf: inout IOBuffer) throws -> Item?; mutating func encode(_ item: Item, into: inout IOBuffer) throws }
public struct Framed<C: Codec>: ~Copyable { /* AsyncSequence of C.Item + send(_:) */ }
```

| Driver | Platform | Key features |
|---|---|---|
| `uring` | Linux 6.1 or later (picked by a start-up probe) | one ring per worker (`SINGLE_ISSUER`, `DEFER_TASKRUN`); `ASYNC_CANCEL`. No liburing: `CVega` makes the system calls itself. Not yet, after 1.0: registered files, multishot accept and recv with provided-buffer rings, `SEND_ZC`, linked timeouts, `MSG_RING` |
| `epoll` | Linux fallback (seccomp, old kernels, `VEGA_DRIVER=epoll`) | `EPOLLET`; `ScheduledIO` per fd (atomic readiness + tick + intrusive waiters) |
| `kqueue` | macOS and BSD servers | `EV_CLEAR`, `EVFILT_USER` |
| `iocp` | Windows | one completion port per runtime; every socket and file operation that would wait is an overlapped request (`AcceptEx`, `ConnectEx`, zero-byte `WSARecv`, `WSASend`, `WSARecvFrom`, `WSASendTo`, `TransmitFile`, `ReadFile`/`WriteFile`), the default (`IOBackend.iocp`); AFD readiness polls, as Tokio's mio does, for the waits with no request (`readable()`, pipes' and batches') and as the whole of `IOBackend.readiness` (`VEGA_DRIVER=afd`); overlapped pipe reads and writes for processes |
| `network` | iOS, tvOS, watchOS, visionOS, and optionally macOS clients | `NWConnection` and `NWListener`, with TLS handled by Network.framework; current-thread or multi-thread runtime, no shards |

**The `iocp` driver, as built.** One I/O completion port per runtime, and two ways onto it.

- **Overlapped requests (`IOBackend.iocp`, the default).** Each operation is first tried as a plain non-blocking call; only one that would wait becomes a request, whose completion resumes the task with its result. Accepts are `AcceptEx` (TCP and AF_UNIX listeners, with `SO_UPDATE_ACCEPT_CONTEXT`), connects `ConnectEx` (on a socket bound to the wildcard address with `SO_REUSE_UNICASTPORT`, so the port is still chosen at connect and an explicit bind can't run the ephemeral ports out under churn; then `SO_UPDATE_CONNECT_CONTEXT`), writes a gathered `WSASend` of the rest (it completes once Winsock has taken all of it; under `withWriteStallTimeout`, in 64 KiB slices each given the limit), datagrams `WSARecvFrom` and `WSASendTo` (a datagram longer than the buffer is cut to it, as recvfrom does: Winsock reports it as `WSAEMSGSIZE`, a warning whose completion is still posted, so the request waits for it), and `sendFile` `TransmitFile`. A socket is associated with the port on its first request, with `FILE_SKIP_COMPLETION_PORT_ON_SUCCESS` unless a layered provider sits on it, so one that finishes at once is taken there and then.
- **Stream reads wait with a zero-byte `WSARecv`**, then `recv` takes what came, as libuv does. A receive into the buffer itself would lock the buffer's pages while it waits, for every idle connection (WSAENOBUFS with many), and locking them costs each request: bulk transfers measured 12% slower that way, and small messages no faster.
- **Files.** VegaFS reads and writes are overlapped `ReadFile` and `WriteFile`. A file keeps its synchronous handle, since it may be handed to a child process whose C runtime can't use an overlapped one; requests go through a second handle to the same file (`ReOpenFile` with `FILE_FLAG_OVERLAPPED`), made on the first request and associated with that runtime's port, closed with the file. Requests name their offset; one at "the position" reads the first handle's and moves it on by the bytes done. A read the cache holds finishes at once, without the port. A file another runtime's port has, or one that is no disk file, goes to the blocking pool.
- **AFD readiness** (`IOBackend.readiness`, `VEGA_DRIVER=afd`, and the waits with no request to make under iocp: `readable()`, `writable()`, pipes', datagram batches'). A task that gets `WSAEWOULDBLOCK` arms a one-shot `IOCTL_AFD_POLL` on the socket's base handle through the runtime's own `\Device\Afd` handle, and the completion resumes it as an epoll event would. Under `.readiness` only `sendFile` is a request.

Cancellation is `CancelIoEx`. For a send that aborts the connection (Winsock can't say how much went), so a write or `sendFile` cancelled or timed out while its request is in flight leaves the stream unusable, on Windows only. A runtime's request counts by kind are in `cv_driver_ovl_count`, which `IOCPTests` uses to check that each path really is a request. The full suite passes on both backends, and CI runs both.

Loopback on the development machine (24 threads, Windows 11, release build), client and server runtimes of 4 workers each in one process, both on the backend measured; 7 alternating runs of 3 s each, medians with min–max:

| | AFD readiness | overlapped (iocp) |
|---|---|---|
| 32-byte ping-pong, 1 connection (round trips/s) | 23,686 (23,228–24,483) | 24,165 (23,570–24,504) |
| 32-byte ping-pong, 32 connections | 105,947 (103,425–107,424) | 109,269 (107,615–109,656) |
| connect, 1 byte each way, close; 8 clients (connections/s) | 9,473 (9,329–9,605) | 9,520 (7,750–9,575) |
| the same, 32 clients | 9,776 (8,426–9,921) | 9,469 (8,056–9,811) |
| 64 KiB writes, 1 connection (MB/s) | 2,327 (2,244–2,374) | 2,344 (2,291–2,538) |
| the same, 8 connections | 7,466 (7,401–7,632) | 7,672 (7,431–7,892) |

Overlapped matches readiness or does a little better (3% on ping-pong over 32 connections and on bulk over 8), the connection rates within their spread. With reads into the buffer itself in place of the zero-byte wait, bulk over 8 connections was 6,583 MB/s (12% behind); the earlier opt-in mode (accepts and reads only, reads into the buffer) measured no better than readiness, which is why readiness was the default until every operation had its request.

Not on Windows: `Runtime.sharded` (it needs `fork`); brotli and zstd (gzip and deflate are on zlib 1.3.1, vendored as `CVegaZlib` because the Windows SDK has none); Unix datagram sockets (Windows' Unix sockets are streams only); raw sockets and vsock; arrival timestamps on reads.

**The `network` driver, as built (v0.3).** TCP only. In a runtime with `IOBackend.network`, `TCPStream` and `TCPListener` run over `NWConnection` and `NWListener`, and kqueue stays for UDP, Unix sockets, pipes and processes. Measured costs are in [BENCHMARKS.md](BENCHMARKS.md). The gaps:

- **UDP.** `UDPSocket` stays on kqueue, which works on every Apple platform but doesn't get Network.framework's cellular and VPN bring-up or interface choice.
  - `NWConnection` over UDP is connected, one peer per connection. An unconnected `UDPSocket` (`send(to:)` / `receive(from:)`) would need `NWConnectionGroup`, or an `NWListener` for UDP plus one connection per peer.
  - Raw UDP isn't what Apple clients need from it. QUIC and HTTP/3 are (v0.5), and there `NWProtocolQUIC`, Network.framework's own QUIC with its own UDP, is likely the better route than Vega's QUIC over raw Network.framework datagrams.
  - So UDP waits for that decision rather than getting an adapter that would be replaced.
- **Socket options** are fixed when Network.framework makes a connection. `TCPClient.options` and `TCPServer.connectionOptions` are applied then. Setting an option on an open socket throws `.unsupported`, unless it already has that value.
- **One listener per port.** Several `TCPServer` accept loops share one `NWListener`.
- **No processes and no shards** on iOS, tvOS, watchOS or visionOS. Apps there may not fork or spawn. `Command.spawn` throws `ENOTSUP`, and `Runtime.sharded` and its types are unavailable at compile time.

- **Selection.** The driver is a closed `enum`, switched in `@inlinable` code, never an existential.
- **The io_uring rule:** submit on the local ring, complete on the local ring, resume on any thread.
- **In-flight operations.** Each lives in an `OpSlab` slot that keeps its buffer alive until the kernel's completion arrives, including after cancellation.
- **Cancellation.** `withTaskCancellationHandler` triggers the driver's cancel.

### Timers, sync, memory
- **Timers.** Each worker has a hierarchical timing wheel (6 levels × 64 slots at 1 ms) with intrusive entries, so cancelling is O(1).
- **Sync primitives.**
  - Waiters are intrusive nodes inside `withUnsafeContinuation` frames, so a wait allocates nothing.
  - They are guarded by `Synchronization.Mutex`, with `Atomic` for counters.
  - Shared atomics are padded to 128 bytes.
- **Memory.** `IOBuffer` (`~Copyable`) owns its bytes; the kernel may own them while an operation is in flight.

## Package layout (`D:\code\vega`)
- **`Package.swift`.**
  - Tools 6.2, Swift 6 language mode, nonisolated-nonsending by default.
  - Platforms: macOS and iOS 26.4 (the custom-executor runtime), plus Linux and Windows.
  - No external dependencies. The TLS library is a trait: `OpenSSL` (the system's, the default) or `BoringSSL` (vendored).
- **C layer:**
  - `CVega`: the drivers' system calls (futex and `__ulock`, eventfd, affinity, topology, io_uring through its raw system calls, epoll, kqueue, IOCP/AFD and Winsock).
  - `CVegaTLS` over OpenSSL or `CVegaBoringSSL`; `CVegaCompress`, with `CVegaZlib` vendored for Windows.
- **Swift modules.** A protocol's networked module has its plain name; its logic, sans I/O, is in its `Core` module, for servers that bring their own I/O.
  - `Vega`: runtime, scheduler, drivers, time, net, sync, signals, `NetworkTLS`.
  - `VegaIO` (codecs, framing, buffered I/O), `VegaFS`, `VegaProcess`, `VegaMetrics`.
  - `VegaTLS`; `VegaCrypto` (hashes, AEADs, key exchange, signatures, certificate checks, and `Digest` on every platform).
  - `VegaHTTP` (the shared HTTP types); `VegaHTTP1`, `VegaHTTP2`, `VegaHTTP3`, `VegaWebSocket` and `VegaQUIC`, each over its `Core` module; `VegaWire` (varints and frames).
  - `VegaCompression`, `VegaProxy`, `VegaTest`.
- **Access tiers.** The public API is the vocabulary. What Garuda alone needs is `@_spi(Garuda)`; what the modules share is `package`.
- **Separate packages:** `Benchmarks/`; `Adapters/` (swift-log and swift-metrics); `VegaNIO/` (SwiftNIO's API over Vega). Adapters and VegaNIO move to repositories of their own for 1.0.
- **Docs:** `docs/MIGRATING-FROM-NIO.md`, `docs/SHARDING.md`, `docs/BENCHMARKS.md`, and the Hummingbird and Vapor notes.

## Phase 0 findings (2026-10-12, Swift 6.3.3)
Spike: `scratchpad/spike` (built in WSL, run on the bench box 192.168.100.100: i5-8250U, 8 CPUs, kernel 7.0).
- **Public `TaskExecutor` preference** keeps these on Vega:
  - structured code;
  - a resume from a foreign thread;
  - default actors;
  - `nonisolated` async functions;
  - child tasks;
  - `Task.sleep`.
  `Task.sleep` goes through `SchedulingExecutor.enqueue(at:)`, which is an SPI.
- **Unstructured `Task {}` and `Task.detached` drop the preference.**
- **Replacing the global executor works on Linux** via `@_spi(ExperimentalCustomExecutors) _createExecutors(factory:)`. It must be called before the first task exists. With it, every task, sleep and `Task.defaultExecutor` lands on Vega. The `DefaultExecutorFactory` typealias alone does nothing.
- **Darwin (checked 2026-10-13, macOS 26.6, Xcode 26.6 / Swift 6.4, MacOSX27.0 SDK): the global executor can't be replaced.** The SDK ships `_Concurrency` as a public interface only, so `ExecutorFactory`, `MainExecutor`, `SchedulingExecutor` and the `@_spi` imports are invisible. `_createExecutors` is not in the OS runtime either, though the protocol descriptors are. `Runtime.installGlobal` therefore installs only the runtime's enqueue-global hook there: `Task {}` and `Task.detached` land on Vega, but `Task.defaultExecutor` stays Dispatch's.
  - `Task.sleep` stays on Dispatch's timers. It asks `Task.currentSchedulableExecutor`, which falls through to `defaultExecutor.asSchedulable`, and `DispatchGlobalTaskExecutor.enqueue(at:)` calls `_dispatchEnqueueWithDeadline` inside the same image. So neither the runtime's `enqueueGlobalWithDelay`/`WithDeadline` hooks nor symbol rebinding can catch it; installing the hooks was tried and got no calls.
  - The resume still comes back to Vega, through the enqueue-global hook: one Dispatch timer and one foreign enqueue per sleep. `Runtime.sleep` and `Runtime.timeout` use Vega's own timer wheel.
- **Public types cannot conform to SPI protocols.** Vega's executor conforms to `SchedulingExecutor` and `MainExecutor` through an `@_spi(Vega)` or internal type. Public API exposes `Runtime`, never the executor class.
- **API consequence:** `Runtime.run { }` calls `_createExecutors` where it is available, and otherwise falls back to executor preference. `Vega.spawn` always passes the preference explicitly.
- **Baseline on the box, per op:**

  | Executor | Spawn | Ping-pong |
  |---|---|---|
  | Dispatch global | 4.6 µs | 2.75 µs |
  | Naive locked FIFO pool | 3.1–3.9 µs | 6.0 µs |

- **Vega v0.1 scheduler targets:**
  - spawn ≤ 1 µs, though Swift's own task allocation may set the floor;
  - ping-pong ≤ 300 ns (the LIFO slot, no cross-thread wake).
- **Remaining Phase 0 items:**
  - io_uring probe in CI and in Docker;
  - IOCP/AFD prototype;
  - `NWConnection` bridging cost;
  - measuring how far a custom task allocator (`ExecutorJob.allocator` SPI) cuts spawn cost.

## Phases and milestones
| Milestone | Contents | aviancore tag |
|---|---|---|
| **0. Spikes** | executor hooks in Swift 6.2/6.3; cost of a `Task` allocation and an enqueue; io_uring in CI (Docker's seccomp profile blocks it); IOCP/AFD prototype; `NWConnection` bridging cost | — |
| **v0.1** | scheduler (all flavours except sharded), blocking pool, timers, epoll/kqueue/uring drivers, TCP/UDP/Unix, cancellation, core sync primitives, `VegaTest` basics, benchmarks against NIO and Tokio | 0.8.0 |
| **v0.2** | sharded runtime and topology; `VegaIO` codecs and `Framed`; `Resolver`; Happy Eyeballs; bootstraps; `VegaFS`, `VegaProcess`, `VegaSignal`; metrics | 0.9.0 |
| **v0.3** | IOCP driver (Windows CI); Network.framework driver (iOS simulator CI) | 0.10.0 |
| **v0.4** | `VegaTLS`; `VegaHTTP1/2`; `VegaWebSocket`; `VegaExtras` (quiesce, proxy, SOCKS, compression) | 0.11.0 |
| **v0.4b** | `VegaNIO` (separate package): `EventLoopGroup`/`EventLoop`/`MPSCChannel`/bootstraps over Vega; runs swift-nio's own channel test suite plus Hummingbird and Vapor hello-world against it | VegaNIO 0.1 |
| **v0.5** | `VegaHTTP3`/QUIC on Vega; Garuda's `Worker` migrated to Vega behind a flag | 0.12.0 |
| **1.0** | parity matrix all green; Garuda on Vega by default; API frozen | 1.0.0 |

## Verification
- **Tests** (swift-testing, `swift test`):
  - queue push/pop/steal invariants;
  - timer wheel cascading and cancellation;
  - cancellation returns the buffer.
  - The **same test suite runs against every driver**, selected by `VEGA_DRIVER=epoll|uring|kqueue|iocp|network`.
- **Concurrency:**
  - `--sanitize=thread`;
  - steal and wake stress loops (millions of cross-worker ping-pong rounds);
  - the deterministic seeded runtime in `VegaTest` for reproducing failures;
  - a fault-injecting driver (`EAGAIN`, short writes, `ECONNRESET`, slow completions).
- **CI matrix:** Linux on kernels 6.1 and 6.8+ (uring and epoll), macOS (kqueue), Windows (IOCP), iOS simulator (network).
  - Local, not hosted: `ci/run.ps1` sends the working tree to the Linux box and runs `ci/linux.sh` there in Docker (io_uring and epoll on OpenSSL, io_uring on BoringSSL, ThreadSanitizer), and `ci/windows.ps1` here. `ci/macos.sh` runs on the Mac (kqueue, and Network.framework on the iOS simulator).
  - The box runs kernel 7.0; 6.1 needs a VM.
- **Parity:** one conformance test per row of the matrix, ported from the equivalent Tokio or SwiftNIO tests (NIO's `EmbeddedChannel` tests become `VegaTest` duplex tests). Also h2spec, Autobahn for WebSocket, and Garuda's existing `garuda-conformance` once integrated.
- **Benchmarks** (separate `Benchmarks/` package), Vega against SwiftNIO 2.x (`MultiThreadedEventLoopGroup` + `NIOAsyncChannel`) and Tokio:
  - spawn throughput;
  - yield ping-pong;
  - chained spawn;
  - TCP echo req/s with p50/p99 at 64, 256 and 1,024 connections;
  - UDP pps;
  - TLS handshakes per second;
  - HTTP/1 and HTTP/2 hello.
- **Targets:**
  - At least 1.5× SwiftNIO throughput on echo and HTTP/1, with lower p99.
  - Level with Tokio (within 10%).
  - On Garuda's skewed-load test, ~49k quick req/s (Tokio's figure, against Garuda's 20k today), while keeping uniform-load median latency within 10% of Garuda's single-thread loop.
- **Fault containment:** a trap in one shard kills only that shard, and the others keep serving under load.
