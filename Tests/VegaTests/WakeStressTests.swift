import Testing
@testable import Vega

/// Lost-wake-up hunting: patterns where a job is enqueued while every worker
/// is going to sleep. A failure here is a hang, so run under `timeout`.
@Suite struct WakeStressTests {
    /// The first job arrives while the workers are still starting up.
    @Test func blockRightAfterStart() {
        for _ in 0..<2_000 {
            let rt = Runtime(workers: 8)
            #expect(rt.block { () async -> Int in 1 } == 1)
            rt.shutdown()
        }
    }

    /// A plain thread hands jobs in one at a time, each after the workers
    /// have had time to park.
    @Test func foreignEnqueuesIntoParkedPool() {
        let rt = Runtime(workers: 8)
        defer { rt.shutdown() }
        for i in 0..<5_000 {
            #expect(rt.block { () async -> Int in i } == i)
        }
    }

    /// Bursts of tiny tasks: workers keep waking, finding nothing, parking.
    @Test func spawnBursts() {
        let rt = Runtime(workers: 8)
        defer { rt.shutdown() }
        for _ in 0..<200 {
            let n = rt.block { () async -> Int in
                await withTaskGroup(of: Int.self) { g in
                    for _ in 0..<2_000 { g.addTask(executorPreference: rt.executor) { 1 } }
                    return await g.reduce(0, +)
                }
            }
            #expect(n == 2_000)
        }
    }

    @Test func discardingSpawnBursts() {
        let rt = Runtime(workers: 8)
        defer { rt.shutdown() }
        for _ in 0..<200 {
            rt.block { () async -> Void in
                await withDiscardingTaskGroup { g in
                    for _ in 0..<2_000 { g.addTask(executorPreference: rt.executor) {} }
                }
            }
        }
    }
}
