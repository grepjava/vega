# Upstream pull requests

The Swift runtime fixes Vega sends upstream. Vega targets the **stock** Swift runtime. `runtime/patches` is an opt-in for servers that ship their own runtime, and each patch there should end up as a PR here.

Update the table whenever a PR changes state: opened, reviewed, CI run, merged, or released in a Swift version.

## Open

| PR | Title | Vega patch | Opened | Status |
|---|---|---|---|---|
| [swiftlang/swift#93174](https://github.com/swiftlang/swift/pull/93174) | Concurrency: remove cancellation handlers without taking the status record lock | 0002 | 2026-10-12 | ktoso replied positively and started CI (Linux, Windows, macOS); pending on 2026-10-12 |
| [swiftlang/swift#93173](https://github.com/swiftlang/swift/pull/93173) | Runtime: load 16-byte atomics with one aligned vector load on x86-64 | 0005 | 2026-10-12 | Awaiting review |
| [swiftlang/swift#93179](https://github.com/swiftlang/swift/pull/93179) | Concurrency: tell TSan when a continuation is resumed before its await | — (found while testing Vega's sync primitives) | 2026-10-12 | Awaiting review |

## Merged

None yet.

## Not yet proposed

From `runtime/patches` (see `runtime/README.md` for details). Each one needs a branch off `swiftlang/swift` `main`, a measurement, and a lit run, as #93174 had.

| Patch | Fixes |
|---|---|
| 0001 | `getPreferredTaskExecutor` takes the status-record lock and does two CASes on every enqueue. The patch makes it one acquire load. |
| 0003 | Each task costs two mallocs, the task itself plus its allocator's first slab. The patch makes it one. |
| 0004 | `Task.yield` copies `Task.currentExecutor`, retaining and releasing the executor on every yield. The patch avoids the copy. |
| 0006 | A continuation resume updates the escalation record under the status lock. The patch makes it one CAS. |
| 0007 | Per-thread task-memory lists, handed between threads in batches of 32, so tasks freed on another thread don't take malloc's arena lock. |

## When a fix ships

Each fix lets Vega drop something, but only once the fix is in a **released** Swift toolchain that Vega requires. Merging into `main` isn't enough.

| PR | Remove from Vega |
|---|---|
| #93179 | `Tests/tsan.supp` and its mention in `README.md` |
| #93174, #93173 | Patches 0002 and 0005 from `runtime/patches`, and their rows in `runtime/README.md` |

## Working on a PR

- **Branches** live in the WSL checkout `~/swiftrt/upstream/swift` and are pushed to the fork `grepjava/swift`:

  | Branch | PR |
  |---|---|
  | `up-0002` | #93174 |
  | `up-0005` | #93173 |
  | `tsan-continuation-await` | #93179 |

- **Build and test** with `~/swiftrt/upstream/up-switch.sh <branch>` (incremental rebuild), then `up-lit.sh <label>` (`test/Concurrency`). The baseline on `main` is 378 passed and 166 unsupported.
- **TSan tests** show as UNSUPPORTED in that build, because it has no `tsan_runtime` or `libdispatch`. Check them with the Swift 6.3.3 toolchain against a 6.3.3 runtime built with the fix, as was done for #93179.
- **Status:** `gh pr view <n> --repo swiftlang/swift --comments` and `gh pr checks <n> --repo swiftlang/swift`.
- Commits and PR descriptions carry no attribution lines.
