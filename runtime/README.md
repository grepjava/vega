# Patched Swift concurrency runtime

Vega's scheduler runs underneath Swift's concurrency runtime
(`libswift_Concurrency`), and some per-task costs sit in that runtime, where
Vega can't reach them. These patches against the Swift release fix the worst
of them. Apps link and run unchanged: the patched library exports the same ABI
and replaces the toolchain's copy at load time.

| Patch | Fixes |
|---|---|
| 0001 | `getPreferredTaskExecutor` took the task's status-record mutex and made two CASes on the status word, on every enqueue and executor switch of a task with an executor preference. It now does one acquire load. |
| 0002 | Ending `withTaskCancellationHandler` took the same lock to pop a record that is always the innermost one. It is now one CAS, and it still waits for a canceller that is running the handler. |
| 0003 | Each task made two mallocs: the task itself, then its allocator's first slab on the first `swift_task_alloc`. They are now one malloc, as async-let tasks already do. |
| 0004 | `Task.yield` copied `Task.currentExecutor`, an existential, which retains and releases the executor on every yield from every thread. It now enqueues through executor refs, with the same order of preference. |
| 0005 | On x86-64, every 16-byte atomic load (task status, default-actor state) was `lock cmpxchg16b`, which costs as much as a store. On CPUs with AVX, an aligned `movdqa` is guaranteed atomic, so the load uses that. |
| 0006 | Waking a task from a continuation updated its escalation dependency record under the status-record lock. When the task goes to the generic executor, escalation through that record is a no-op both before and after, so one CAS on the status bits replaces the lock. |

These are the costs in the runtime itself. Vega already avoids the ones it
can avoid without a patch:
- `Runtime.yield`, `Notify`, `TaskPool` and the coop budget.
- In global mode, the `swift_task_enqueueGlobal_hook`.

## Platforms

| Platform | How the patched runtime gets in |
|---|---|
| Linux | Ship `libswift_Concurrency.so` next to the app and point the rpath or `LD_LIBRARY_PATH` at it. For a `-static-stdlib` build, link the `.a` instead (`--static`). |
| Windows | Put `swift_Concurrency.dll` in the executable's directory. Windows searches there before `PATH`. |
| macOS | Only for command-line servers that use no Apple Swift frameworks: such an app can carry the runtime under its rpath. Apps that link system frameworks get the OS copy in `/usr/lib/swift`. |
| iOS | Not possible: the runtime is part of the OS. |

## Building

The build uses the installed toolchain, which must be the same release as the
patches (6.3.3), and Swift's standalone `Runtimes/Core` CMake project, so no
compiler is built.

```sh
runtime/build-linux.sh            # patched .so -> runtime/out/patched-shared
runtime/build-linux.sh --stock    # unpatched, for benchmark baselines
runtime/build-linux.sh --static   # patched .a, for -static-stdlib
runtime/make-toolchain-linux.sh   # toolchain copy carrying both
```

The simplest way to use the patches is a patched toolchain. `make-toolchain-linux.sh` makes a hard-linked copy of the installed toolchain and replaces only the two runtime libraries. Build with it and `-static-stdlib`:

```sh
~/.local/share/vega-swift-6.3.3/usr/bin/swift build -c release -Xswiftc -static-stdlib
```

The binary then carries the patched runtime, and nothing else has to ship with it. Static linking is also the fastest option: the runtime's thread-local variables become direct accesses instead of `__tls_get_addr` calls. On the bench box that takes ping_pong from 298 to 261 ns and yield_vega from 46 to 40 ns.

Test targets can't link statically, because swift-testing is only built for dynamic linking. Run them against the shared library (`LD_LIBRARY_PATH`).

```powershell
runtime\build-windows.ps1         # untested so far; see the header
```

Before copying anything out, the Linux script checks three things. The Windows script does the first and builds in the registration step, but has never run:
- **Exports.** Every symbol the toolchain's library exports must still be exported.
- **Metadata registration.** The library must register its metadata, which comes from linking the project's own `swiftrt` object; the CMake project's clang++ link leaves it out. Without it, every by-name lookup of a concurrency type returns nil.
- **SwiftPM.** The toolchain's own SwiftPM has to build a small package with a dependency on the new library. SwiftPM is a large concurrent program, and this check is what caught the missing registration.

## Checking

- `Benchmarks/vega-global-check` runs Swift concurrency with Vega as the
  global executor: tasks, sleeps, groups, actors, async let, cancellation,
  yields.
- Run it, Vega's test suite and `vega-bench` with the patched library first
  on the library path.
