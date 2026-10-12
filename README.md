# Vega

A high-speed I/O engine for Swift, meant to fully replace SwiftNIO. It provides a Tokio-style work-stealing scheduler, completion-based I/O on io_uring and IOCP, and readiness-based I/O on epoll and kqueue. It targets Swift 6.2+ and modern Swift concurrency, with no backward-compatibility layer.

Vega aims for feature parity with Tokio and SwiftNIO. It can be swapped in for SwiftNIO through the `VegaNIO` package, and it will become the engine under [Garuda](https://github.com/grepjava/garuda), succeeding [aviancore](https://github.com/grepjava/aviancore).

**Status:** pre-alpha. Phase 0 spikes are done, and Phase 1 (the scheduler) is in progress. See [docs/PLAN.md](docs/PLAN.md) for the design, the parity matrix and the milestones.

## Layout

| Path | What |
|---|---|
| `Sources/Vega` | runtime and scheduler (Phase 1) |
| `Sources/CVega` | C shim: futex parking, threads, thread-local, clock |
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
