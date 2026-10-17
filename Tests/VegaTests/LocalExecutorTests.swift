import Testing
@testable import Vega

/// Not `Sendable`: shared by the tasks of one `LocalExecutor`.
private final class Tally {
    var count = 0
    var workers: Set<Int?> = []
}

private actor Pinned {
    let local: LocalExecutor
    var workers: Set<Int?> = []
    init(_ local: LocalExecutor) { self.local = local }
    nonisolated var unownedExecutor: UnownedSerialExecutor { local.unownedExecutor }

    func step() async {
        workers.insert(Runtime.currentWorker)
        await Runtime.yield()
        try? await Runtime.sleep(for: .milliseconds(1))
        workers.insert(Runtime.currentWorker)
    }
}

@Suite("LocalExecutor")
struct LocalExecutorTests {
    /// Every job runs on the bound worker, across yields and sleeps, while
    /// the other workers are free to steal.
    @Test func runsOnlyOnItsWorker() throws {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        for index in 0..<4 {
            let local = LocalExecutor(runtime: rt, worker: index)
            let workers = rt.block { () async -> Set<Int?> in
                await local.spawn { _ in
                    var seen: Set<Int?> = []
                    for _ in 0..<20 {
                        seen.insert(Runtime.currentWorker)
                        await Runtime.yield()
                        seen.insert(Runtime.currentWorker)
                        try? await Runtime.sleep(for: .milliseconds(1))
                    }
                    return seen
                }.value
            }
            #expect(workers == [index])
        }
    }

    /// State that isn't Sendable, shared by many tasks that interleave.
    @Test func sharesNonSendableState() throws {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        let local = LocalExecutor(runtime: rt, worker: 2)
        let (count, workers) = rt.block { () async -> (Int, Set<Int?>) in
            await local.spawn { local in await shareATally(local) }.value
        }
        #expect(count == 1000)
        #expect(workers == [2])
    }

    @Test func anActorOnIt() throws {
        let rt = Runtime(workers: 3)
        defer { rt.shutdown() }
        let local = LocalExecutor(runtime: rt, worker: 1)
        let pinned = Pinned(local)
        let workers = rt.block { () async -> Set<Int?> in
            await withTaskGroup(of: Void.self) { group in
                for _ in 0..<50 { group.addTask(executorPreference: rt.executor) { await pinned.step() } }
            }
            return await pinned.workers
        }
        #expect(workers == [1])
    }

    /// Work arriving from outside the runtime wakes the parked worker.
    @Test func wakesAParkedWorker() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let local = LocalExecutor(runtime: rt, worker: 1)
        for round in 0..<200 {
            let got = rt.block { await local.spawn { _ in round }.value }
            #expect(got == round)
        }
    }

    /// The default worker goes round the runtime's workers.
    @Test func defaultWorkersGoRound() throws {
        let rt = Runtime(workers: 3)
        defer { rt.shutdown() }
        var indexes: Set<Int> = []
        for _ in 0..<6 { indexes.insert(LocalExecutor(runtime: rt).worker) }
        #expect(indexes == [0, 1, 2])
    }
}

/// Many tasks on one `LocalExecutor` sharing a `Tally`, which isn't Sendable.
private func shareATally(_ local: isolated LocalExecutor) async -> (Int, Set<Int?>) {
    let tally = Tally()
    var tasks: [Task<Void, Never>] = []
    for _ in 0..<100 {
        tasks.append(local.spawnLocal {
            for _ in 0..<10 {
                tally.count += 1
                tally.workers.insert(Runtime.currentWorker)
                await Runtime.yield()
            }
        })
    }
    for task in tasks { await task.value }
    return (tally.count, tally.workers)
}
