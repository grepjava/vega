# Vega

A high-speed I/O engine for Swift, meant to fully replace SwiftNIO. It provides a Tokio-style work-stealing scheduler, completion-based I/O on io_uring and IOCP, and readiness-based I/O on epoll and kqueue. It targets Swift 6.2+ and modern Swift concurrency, with no backward-compatibility layer.

Vega aims for feature parity with Tokio and SwiftNIO. It can be swapped in for SwiftNIO through the `VegaNIO` package, and it will become the engine under [Garuda](https://github.com/grepjava/garuda), succeeding [aviancore](https://github.com/grepjava/aviancore).

**Status:** pre-alpha. v0.1 is feature-complete: the work-stealing and current-thread runtimes, the blocking pool, timers and paused time, io_uring (the Linux default), epoll and kqueue drivers, TCP/UDP/Unix sockets, and the sync primitives. v0.2 is feature-complete too: VegaIO codecs and framing, Happy Eyeballs, an async DNS resolver, in-memory test streams, server and client bootstraps, VegaFS file I/O, VegaProcess child processes and pipes, Unix signals, runtime metrics, and the sharded runtime (`Runtime.sharded`: supervised shard processes, one per cache domain). See [docs/PLAN.md](docs/PLAN.md) for the design, the parity matrix and the milestones, [docs/BENCHMARKS.md](docs/BENCHMARKS.md) for measurements against SwiftNIO and Tokio, [docs/MIGRATING-FROM-NIO.md](docs/MIGRATING-FROM-NIO.md) for moving SwiftNIO code to Vega, and [docs/SHARDING.md](docs/SHARDING.md) for running a server as supervised shard processes.

## Layout

| Path | What |
|---|---|
| `Sources/Vega` | runtime, scheduler, I/O drivers, sockets, DNS resolver, timers, sync primitives |
| `Sources/VegaIO` | stream protocols, `Framed`, codecs (length-delimited, lines, bytes) |
| `Sources/VegaFS` | files and paths: `File` (io_uring-native reads, writes, syncs and opens; the blocking pool elsewhere), `FileSystem` |
| `Sources/VegaProcess` | child processes: `Command`, `Child` (exit watched through a pidfd on Linux), `Output`; pipes (`makePipe()`) live in Vega |
| `Sources/VegaMetrics` | `metricsSamples(every:)` (periodic deltas of `Runtime.metrics`), Prometheus text export |
| `Sources/VegaTest` | test support: `MockClock` (paused time), `duplex()` (in-memory byte streams) |
| `Sources/CVega` | C shim: parking, threads, the epoll/kqueue/io_uring drivers, sockets |
| `Sources/VegaTLS` | `TLSStream` over any stream, `TLSConfiguration`, `TLSContext` |
| `Sources/VegaCrypto` | over the same library: `Hash`, `HMAC`, `PBKDF2`, `HKDF`, `AEAD`, QUIC `HeaderProtection`, `KeyExchange`, JWS/TLS `SigningKey` and `PublicKey`, `CertificateKey`, `SecureRandom` |
| `Sources/CVegaTLS` | C shim between VegaTLS, VegaCrypto and the TLS library |
| `Sources/CVegaBoringSSL` | vendored BoringSSL, used only with the `BoringSSL` trait (see its `VENDORING.md`) |
| `Tests/VegaTests` | swift-testing suite |
| `Benchmarks/` | separate package, so Vega itself keeps zero dependencies |
| `Spikes/executor` | Phase 0: which Swift 6.3 executor hooks reach a custom executor |
| `Spikes/uring-probe` | Phase 0: io_uring features available on a host or in a container |

## Build

Linux is the primary target. Building through WSL works:

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
.package(url: "https://github.com/grepjava/vega.git", from: "0.1.0", traits: ["BoringSSL"])
```

or, building Vega itself, `swift build --traits BoringSSL`.

In vega-https on the bench box, BoringSSL completed 1.35× OpenSSL 3.5's handshakes on the same key exchange, at 20% less server CPU per connection, and used 3–11% less CPU per request on kept-alive connections ([docs/BENCHMARKS.md](docs/BENCHMARKS.md)). Most worth it for servers with many short connections.

There are costs:
- Vega, not the operating system, ships BoringSSL's security fixes.
- The binary is about 11 MB larger.
- OpenSSL 3.5 negotiates the post-quantum X25519MLKEM768 key exchange by default, and this BoringSSL negotiates X25519.
