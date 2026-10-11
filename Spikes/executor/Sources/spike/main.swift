@_spi(Vega) import SpikeCore

// Without a custom ExecutorFactory: only the public TaskExecutor-preference API.
let pool = Pool(threads: 4)
print("== spike: TaskExecutor preference only (Swift public API)")
line("top-level code is off-pool", currentPoolWorker() == 0)
await probePlacement(pool: pool)
let plain = await Task { currentPoolWorker() }.value
line("plain Task {} lands on pool (expected FAIL without factory)", plain > 0)
await runBenches(pool: pool, label: "global = platform default")
