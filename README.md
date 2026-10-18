<p align="center">
  <img src="assets/vega.png" alt="Vega, a high-speed I/O engine for Swift" width="720">
</p>

# Vega

A high-speed I/O engine for Swift, and an alternative to SwiftNIO for code
written with Swift concurrency. It provides a Tokio-style work-stealing
scheduler, completion-based I/O on io_uring and IOCP, and readiness-based I/O on
epoll and kqueue. It targets Swift 6.2 and newer, and is tuned for Swift 6.3.

[Garuda 2](https://github.com/grepjava/garuda) is built on it, and Hummingbird
and Vapor can run on it through [VegaNIO](VegaNIO/README.md), which keeps
their SwiftNIO code as it is and hands Vega the scheduling and the socket I/O.

**Status:** 0.5. Young, used in production by one framework so far, and
measured more than it has been battle-tested. The API may still change between
minor versions. See [docs/PLAN.md](docs/PLAN.md) for the design and the parity
matrix, [docs/BENCHMARKS.md](docs/BENCHMARKS.md) for measurements against
SwiftNIO and Tokio, [docs/MIGRATING-FROM-NIO.md](docs/MIGRATING-FROM-NIO.md) for
moving SwiftNIO code over, and [docs/SHARDING.md](docs/SHARDING.md) for running
a server as supervised shard processes.

## Why Vega

SwiftNIO is the foundation most server-side Swift stands on, and Vega owes a
great deal to it. NIO was designed before Swift had async/await: its unit of
work is a `Channel` bound to one event loop thread for life, and its API is
`EventLoopFuture` and the channel pipeline, with async bridges added later.
Tokio, on the Rust side, showed another shape: tasks that any worker thread may
run, with idle threads stealing work from busy ones.

Vega began as the question of what that shape would look like in Swift, now
that the language can host it:

- **Bring a work-stealing scheduler to Swift.** Per-worker run queues with a
  LIFO slot, stealing, a shared inject queue and cooperative budgets, as in
  Tokio. A connection is a task, and a busy one never holds up others pinned
  to the same loop, because nothing is pinned.
- **Build on Swift 6.3's executor hooks, not around them.** Swift 6.3 lets a
  library install the process's global executor and give tasks an executor
  preference, so plain `Task {}`, `async let` and task groups run on Vega's
  workers with no wrapper types. Vega's hot paths are written for that runtime:
  no reference counting on the per-request path where it can be avoided,
  `~Copyable` buffers, and allocation-free I/O deadlines.
- **Use the kernel's completion I/O where it exists.** io_uring is the default
  on Linux, a ring per worker, and overlapped requests on an I/O completion
  port on Windows; epoll, kqueue and AFD readiness stay as fallbacks.
- **Fix what belongs upstream, upstream.** Where the Swift runtime was the
  bottleneck, the fix is offered to swiftlang/swift rather than kept in a
  private fork, and Vega runs on the stock toolchain.
- **Scale out with processes as well as threads.** `Runtime.sharded` runs a
  supervised process per cache domain, each with its own runtime, sharing a
  listening socket and memory regions.

## Vega, SwiftNIO and Tokio

How the three compare, as fairly as we can put it. SwiftNIO and Tokio are
mature, widely deployed and far more proven than Vega.

| | Vega | SwiftNIO | Tokio |
|---|---|---|---|
| Language | Swift 6.2+ (tuned for 6.3) | Swift | Rust |
| Programming model | Swift concurrency: tasks, `async`/`await`, structured concurrency | `Channel`, `ChannelPipeline` and `EventLoopFuture`; async bridges (`NIOAsyncChannel`) | `async`/`await` on Rust futures |
| Scheduling | work stealing across worker threads; current-thread runtime | an event loop per thread; a channel stays on its loop | work stealing (multi-thread runtime); current-thread runtime |
| Multi-process | `Runtime.sharded`: supervised shard processes | none built in | none built in |
| Linux I/O | io_uring (default), epoll | epoll | epoll (io_uring through `tokio-uring`) |
| Apple I/O | kqueue, Network.framework | kqueue, Network.framework (NIOTransportServices) | kqueue |
| Windows | IOCP: overlapped `AcceptEx`, `ConnectEx`, `WSARecv`, `WSASend`, `WSARecvFrom`, `WSASendTo`, `TransmitFile`, file reads and writes (default); AFD readiness | in progress upstream | IOCP (AFD readiness) |
| Blocking work | `Runtime.blocking` | `NIOThreadPool` | `spawn_blocking` |
| Timers and tests | timer wheel; `MockClock` paused time, in-memory `duplex()` streams | `EmbeddedEventLoop`, `NIOAsyncTestingChannel` | timer wheel; `time::pause`, `tokio-test` |
| TLS | VegaTLS on OpenSSL 3 or vendored BoringSSL; kernel TLS offload on Linux; Network.framework's TLS on Apple (`NetworkTLS`) | swift-nio-ssl (BoringSSL) | rustls or native-tls, separate crates |
| HTTP | VegaHTTP1, VegaHTTP2, VegaWebSocket | NIOHTTP1, swift-nio-http2, NIOWebSocket | hyper, tungstenite, separate crates |
| QUIC and HTTP/3 | VegaQUIC (sans-I/O, client and server), VegaQUICNet (on Vega's UDP sockets), VegaHTTP3 (frames, QPACK), VegaHTTP3Net (server and client) | not in SwiftNIO itself; on Apple platforms, Network.framework's QUIC | quinn, h3, separate crates |
| Maturity | 0.5, since 2026 | since 2018, the base of Vapor, Hummingbird, gRPC Swift and more | since 2016, the base of most async Rust |

**What has been measured** ([docs/BENCHMARKS.md](docs/BENCHMARKS.md), one
i5-8250U, Linux 7.0, Swift 6.3.3):

- **TCP echo, 64-byte messages, four workers each:** at 64 connections Vega
  served 308k requests a second, SwiftNIO 226k and Tokio 268k; at 1,024
  connections Tokio led with 255k, against Vega's 241k and SwiftNIO's 206k.
- **Scheduler microbenchmarks:** Vega is 1.6 to 17 times faster than Swift's
  default executor. On the stock Swift runtime it is still 1.3 to 4.9 times
  slower than Tokio at spawning, yielding and handing a value between two
  tasks: a Swift task costs more to create and to resume than a Tokio task.
  Runtime patches, offered upstream, close most of that and put Vega ahead on
  hand-offs, but Vega does not depend on them.
- **Hummingbird and Vapor on VegaNIO** run within a few per cent of the same
  servers on NIOPosix, not faster: the pipeline above the transport is the
  same.

These are one machine's figures, for workloads chosen to stress the engine.
Measure your own.

## Layout

| Path | What |
|---|---|
| `Sources/Vega` | runtime, scheduler, I/O drivers, sockets, DNS resolver, timers, sync primitives, the sharded runtime |
| `Sources/VegaIO` | stream protocols, `Framed`, codecs (length-delimited, lines, bytes) |
| `Sources/VegaFS` | files and paths: `File` (io_uring-native reads, writes, syncs and opens; the blocking pool elsewhere), `FileSystem` |
| `Sources/VegaProcess` | child processes: `Command`, `Child` (exit watched through a pidfd on Linux), `Output`; pipes (`makePipe()`) live in Vega |
| `Sources/VegaMetrics` | `metricsSamples(every:)` (periodic deltas of `Runtime.metrics`), Prometheus text export |
| `Sources/VegaTLS` | `TLSStream` over any stream, `TLSConfiguration`, `TLSContext`; ALPN, SNI, mutual TLS, session resumption, Linux kernel TLS (kTLS) offload |
| `Sources/VegaCrypto` | over the same library: `Hash`, `HMAC`, `PBKDF2`, `HKDF`, `AEAD`, QUIC `HeaderProtection`, `KeyExchange`, JWS/TLS `SigningKey` and `PublicKey`, `CertificateKey`, `SecureRandom` |
| `Sources/VegaWire` | wire formats, sans I/O: `ByteBuffer`, HPACK, HTTP/2 frame headers, WebSocket frames, permessage-deflate negotiation |
| `Sources/VegaHTTP1`, `Sources/VegaHTTP2` | HTTP/1.1 parsing, codecs and connections; HTTP/2 connections |
| `Sources/VegaWebSocket` | WebSocket connections and permessage-deflate compression |
| `Sources/VegaQUIC` | QUIC v1 and v2 as a sans-I/O state machine: packets and their protection, loss recovery and congestion control, streams, path validation, Retry, and both sides of the TLS 1.3 handshake. Datagrams in, datagrams out, no clock |
| `Sources/VegaQUICNet` | QUIC on Vega's UDP sockets: `QUICEndpoint` (listen, connect), `QUICConnectionHandle`, and `QUICStreamHandle`, an `AsyncReader` and `AsyncWriter` |
| `Sources/VegaHTTP3` | HTTP/3 frames and QPACK |
| `Sources/VegaHTTP3Net` | `HTTP3Server` and `HTTP3Client`, with whole bodies, as VegaHTTP2's |
| `Sources/VegaExtras` | HTTP content codings (gzip, deflate, brotli, zstd) and SOCKS and HTTP proxy handshakes |
| `Sources/VegaTest` | test support: `MockClock` (paused time), `duplex()` (in-memory byte streams) |
| `Sources/CVega` | C shim: parking, threads, the epoll/kqueue/io_uring/IOCP drivers, sockets |
| `Sources/CVegaTLS`, `Sources/CVegaCompress` | C shims for the TLS library and for compression |
| `Sources/CVegaBoringSSL` | vendored BoringSSL, used only with the `BoringSSL` trait (see its `VENDORING.md`) |
| `VegaNIO` | separate package: SwiftNIO's `EventLoopGroup` and bootstraps on Vega |
| `Tests/VegaTests`, `Tests/VegaWireTests`, `Tests/VegaQUICTests` | swift-testing suites; `Tests/QUICTestPeer` is the QUIC tests' own client |
| `Benchmarks/` | separate package, so Vega itself keeps zero dependencies |
| `Spikes/` | the Phase 0 probes: which Swift 6.3 executor hooks reach a custom executor, and which io_uring features a host has |

## Build

Linux is the primary target; macOS 26.4 and newer and Windows (x64, Swift
6.3.3) are supported. On Windows the whole test suite runs natively
(`ci/windows.ps1`, once per backend): sockets and files on an I/O completion
port, where each operation that would wait is an overlapped request whose
completion resumes the task (`IOBackend.iocp`, the default), or with AFD
readiness polls as Tokio's mio does (`.readiness`, `VEGA_DRIVER=afd`);
`sendFile` by `TransmitFile`, processes, TLS, HTTP/1, HTTP/2, HTTP/3 and QUIC,
WebSocket with permessage-deflate, and gzip and deflate on a vendored zlib.
What Windows lacks: `Runtime.sharded` (it needs `fork`), brotli and zstd,
Unix datagram sockets (Windows has none), raw sockets, vsock, and arrival
timestamps on reads. A write or `sendFile` cancelled or timed out while its
request is in flight aborts the connection there, since Winsock can't say how
much of a cancelled send went. See docs/PLAN.md for the driver. Linux builds
also work through WSL:

```sh
swift build --scratch-path ~/.cache/vega-build
swift test  --scratch-path ~/.cache/vega-build
```

Under ThreadSanitizer, use the suppression file: it covers a Swift runtime gap (see the file for details).

```sh
swift build --build-tests --sanitize=thread --scratch-path ~/.cache/vega-build-tsan
TSAN_OPTIONS=suppressions=$PWD/Tests/tsan.supp VEGA_MODEL_N=50000 \
  swift test --skip-build --sanitize=thread --scratch-path ~/.cache/vega-build-tsan
```

## TLS library

VegaTLS runs on the system's OpenSSL 3 by default (`libssl-dev` on Linux, Homebrew's `openssl@3` on macOS). The `BoringSSL` package trait builds it on a vendored BoringSSL instead, with no system OpenSSL needed:

```swift
.package(url: "https://github.com/grepjava/vega.git", from: "0.5.0", traits: ["BoringSSL"])
```

or, building Vega itself, `swift build --traits BoringSSL`.

In vega-https on the bench box, BoringSSL completed 1.35× OpenSSL 3.5's handshakes on the same key exchange, at 20% less server CPU per connection, and used 3–11% less CPU per request on kept-alive connections ([docs/BENCHMARKS.md](docs/BENCHMARKS.md)). Most worth it for servers with many short connections.

There are costs:
- Vega, not the operating system, ships BoringSSL's security fixes.
- The binary is about 11 MB larger.
- OpenSSL 3.5 negotiates the post-quantum X25519MLKEM768 key exchange by default, and this BoringSSL negotiates X25519.

### Kernel TLS

On Linux, `TLSConfiguration.kernelOffload` gives a connection's records to the
kernel's TLS (kTLS) once the handshake is done, for a `TLSStream` over a
`TCPStream`:

```swift
var config = TLSConfiguration.server(identity: identity)
config.kernelOffload = .transmit            // or .transmitAndReceive
let tls = try await TLSStream.accept(conn, context: TLSContext(config))
_ = try await tls.sendFile(fd, count: size) // sendfile(2), encrypted by the kernel
```

With `.transmit` the kernel encrypts: writes go to the socket as they are,
and `sendFile` sends a file without copying it through the process. With
`.transmitAndReceive` it decrypts too. It works with OpenSSL and BoringSSL
alike, for AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305 under TLS 1.2 and
1.3. It is off by default, and a connection the kernel can't take (no `tls`
module, a cipher it lacks, any other transport) stays in userspace without
error: `tls.kernelOffload` says what the kernel has. With receive offload,
TLS 1.3 session tickets that come after the switch are dropped. A client
reads one record itself first, so it keeps the first ticket. A peer's
KeyUpdate needs Linux 6.14 or later.
