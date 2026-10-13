# Upstream pull requests

The Swift runtime fixes Vega sends upstream. Vega targets the **stock** Swift runtime. `runtime/patches` is an opt-in for servers that ship their own runtime, and each patch there should end up as a PR here.

Update the table whenever a PR changes state: opened, reviewed, CI run, merged, or released in a Swift version.

## Open

| PR | Title | Vega patch | Opened | Status |
|---|---|---|---|---|
| [swiftlang/swift#93174](https://github.com/swiftlang/swift/pull/93174) | Concurrency: remove cancellation handlers without taking the status record lock | 0002 | 2026-10-12 | ktoso replied positively and started CI (Linux, Windows, macOS); pending on 2026-10-12 |
| [swiftlang/swift#93173](https://github.com/swiftlang/swift/pull/93173) | Runtime: load 16-byte atomics with one aligned vector load on x86-64 | 0005 | 2026-10-12 | Reviewed 2026-10-12: mikeash suggested a three-state byte in place of the guarded static, rjmccall suggested skipping CPUID when built for `__AVX__`. Both done in 8df8d30, pushed 2026-10-13 (lit on Linux x86-64: 378 passed, 166 unsupported, unchanged). Reply posted 2026-10-13; awaiting re-review |
| [swiftlang/swift#93179](https://github.com/swiftlang/swift/pull/93179) | Concurrency: tell TSan when a continuation is resumed before its await | — (found while testing Vega's sync primitives) | 2026-10-12 | Awaiting review |
| [swiftlang/swift#93180](https://github.com/swiftlang/swift/pull/93180) | Concurrency: Task.yield enqueues without copying the current executor | 0004 | 2026-10-12 | Awaiting review. Measured −35% per yield on a custom task executor (8 threads); no change on the default Dispatch executor |

## Merged

None yet.

## Not yet proposed

From `runtime/patches` (see `runtime/README.md` for details). Each one needs a branch off `swiftlang/swift` `main`, a measurement, and a lit run, as #93174 had.

| Patch | Fixes |
|---|---|
| 0001 | `getPreferredTaskExecutor` takes the status-record lock and does two CASes on every enqueue. The patch makes it one acquire load. **Not upstreamable as is:** on `main`, stale `AsyncTaskStealer` and direct jobs call it (`Actor.cpp`, `fromTaskExecutorPreference`) while the task may be running on another thread, so a lock-free walk of the record chain can race the task pushing and popping records. Needs a different design, e.g. a separately published preference. |
| 0003 | Each task costs two mallocs, the task itself plus its allocator's first slab. The patch makes it one. **Held back: every size tried loses somewhere** (branch `up-0003`, not pushed; measured 2026-10-12 on the box, glibc). With a 512-byte inline slab (the patch as is), spawning onto other threads gets 22–30% faster, but tasks needing 480–1,000 bytes of task memory still take a second slab and get 3–7% slower (Vega `chained_spawn`). Filling the block to 1 KiB keeps that case level but cuts the spawn gain to 8–20%. With a full 1 KiB slab inline (the size the allocator would have mallocked), cross-thread spawns are 17–30% faster, but the 1,336-byte block leaves glibc's per-thread cache and tasks created and freed on one thread get 9–11% slower (`Task.immediate`). The result depends on the malloc in use, and it can't be measured on Darwin here. An allocator-independent fix looks like 0007's per-thread task-memory pool, which is a larger proposal. |
| 0006 | A continuation resume updates the escalation record under the status lock. The patch makes it one CAS. **Not upstreamable as is:** on `main`, `flagAsAndEnqueueOnExecutor` must decide under the lock whether to enqueue the task or an `AsyncTaskStealer` (`swift_task_getSelfOrStealerForEnqueue`), and with priority escalation enabled (Apple platforms) `swift_executor_escalate` on the generic executor now enqueues a stealer. So the record is no longer a no-op once the task is enqueued. Skipping its update would lose escalations. A version limited to builds without escalation (Linux, Windows) would also have to prove the self-or-stealer choice safe without the lock. |
| 0007 | Per-thread task-memory lists, handed between threads in batches of 32, so tasks freed on another thread don't take malloc's arena lock. |

## When a fix ships

Each fix lets Vega drop something, but only once the fix is in a **released** Swift toolchain that Vega requires. Merging into `main` isn't enough.

| PR | Remove from Vega |
|---|---|
| #93179 | `Tests/tsan.supp` and its mention in `README.md` |
| #93174, #93173, #93180 | Patches 0002, 0005 and 0004 from `runtime/patches`, and their rows in `runtime/README.md` |

## Working on a PR

- **Branches** live in the WSL checkout `~/swiftrt/upstream/swift` and are pushed to the fork `grepjava/swift`:

  | Branch | PR |
  |---|---|
  | `up-0002` | #93174 |
  | `up-0005` | #93173 |
  | `tsan-continuation-await` | #93179 |
  | `up-0004` | #93180 |
  | `up-0003` | — (held back, see above; local only) |

- **Build and test** with `~/swiftrt/upstream/up-switch.sh <branch>` (incremental rebuild), then `up-lit.sh <label>` (`test/Concurrency`). The baseline on `main` is 378 passed and 166 unsupported.
- **TSan tests** show as UNSUPPORTED in that build, because it has no `tsan_runtime` or `libdispatch`. Check them with the Swift 6.3.3 toolchain against a 6.3.3 runtime built with the fix, as was done for #93179.
- **Measuring:** `~/swiftrt/upbench` (`bench.swift`, `snap.sh <label>`, `run-box.sh` with `LABELS=`) measures `main` against a branch on the box. For changes aimed at custom executors, use Vega's `vega-bench` against a 6.3.3 runtime with only that patch (see #93180).
- **Status:** `gh pr view <n> --repo swiftlang/swift --comments` and `gh pr checks <n> --repo swiftlang/swift`.
- Commits and PR descriptions carry no attribution lines.
