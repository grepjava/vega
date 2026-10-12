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
