# Vega

A high-speed I/O engine for Swift, meant to fully replace SwiftNIO. It provides a Tokio-style work-stealing scheduler, completion-based I/O on io_uring and IOCP, and readiness-based I/O on epoll and kqueue. It targets Swift 6.2+ and modern Swift concurrency, with no backward-compatibility layer.

Vega aims for feature parity with Tokio and SwiftNIO. It can be swapped in for SwiftNIO through the `VegaNIO` package, and it will become the engine under [Garuda](https://github.com/grepjava/garuda), succeeding [aviancore](https://github.com/grepjava/aviancore).

**Status:** pre-alpha. v0.1 is feature-complete: the work-stealing and current-thread runtimes, the blocking pool, timers and paused time, io_uring (the Linux default), epoll and kqueue drivers, TCP/UDP/Unix sockets, and the sync primitives. v0.2 is in progress (VegaIO codecs and framing, Happy Eyeballs, an async DNS resolver, in-memory test streams). See [docs/PLAN.md](docs/PLAN.md) for the design, the parity matrix and the milestones, and [docs/BENCHMARKS.md](docs/BENCHMARKS.md) for measurements against SwiftNIO and Tokio.

## Layout

| Path | What |
|---|---|
| `Sources/Vega` | runtime, scheduler, I/O drivers, sockets, DNS resolver, timers, sync primitives |
| `Sources/VegaIO` | stream protocols, `Framed`, codecs (length-delimited, lines, bytes) |
| `Sources/VegaTest` | test support: `MockClock` (paused time), `duplex()` (in-memory byte streams) |
| `Sources/CVega` | C shim: parking, threads, the epoll/kqueue/io_uring drivers, sockets |
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
