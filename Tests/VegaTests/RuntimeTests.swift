import CVega
import Synchronization
import Testing
@testable import Vega

/// A shared, lockable list that tasks can append to.
final class Log<T: Sendable>: Sendable {
    let items = Mutex<[T]>([])
    func append(_ x: T) { items.withLock { $0.append(x) } }
    var all: [T] { items.withLock { $0 } }
}

/// Busy-wait without suspending, to hold a worker.
func spin(microseconds: UInt64) {
    let end = cv_now_ns() + microseconds * 1000
    while cv_now_ns() < end {}
}

@Suite struct RuntimeTests {
    @Test func blockReturnsValueAndRunsOnWorker() {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (value, worker) = rt.block { () async -> (Int, Int?) in (42, Runtime.currentWorker) }
        #expect(value == 42)
        #expect(worker != nil)
        #expect(Runtime.currentWorker == nil)
    }

    @Test func blockPropagatesTypedError() {
        struct Boom: Error, Equatable {}
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        #expect(throws: Boom.self) {
            try rt.block { () async throws(Boom) -> Int in throw Boom() }
        }
    }

    @Test func manySpawnedTasksAllComplete() {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        let n = 100_000
        let count = rt.block { () async -> Int in
            await withTaskGroup(of: Int.self) { g in
                for i in 0..<n { g.addTask(executorPreference: rt.executor) { i & 1 } }
                return await g.reduce(0, +)
            }
        }
        #expect(count == n / 2)
    }

    @Test func everythingAwaitedStaysOnRuntime() {
        actor Box { func hop() -> Int? { Runtime.currentWorker } }
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let seen = rt.block { () async -> [Int?] in
            var s: [Int?] = [Runtime.currentWorker]
            s.append(await Box().hop())
            s.append(Runtime.currentWorker)
            try? await Task.sleep(for: .milliseconds(2))
            s.append(Runtime.currentWorker)
            try? await Runtime.sleep(for: .milliseconds(2))
            s.append(Runtime.currentWorker)
            s.append(await rt.spawn { Runtime.currentWorker }.value)
            return s
        }
        #expect(seen.allSatisfy { $0 != nil }, "\(seen)")
    }

    /// One task spawns CPU-bound children; idle workers must steal them.
    @Test func idleWorkersStealWork() {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        let workers = rt.block { () async -> Set<Int> in
            await withTaskGroup(of: Int.self) { g in
                for _ in 0..<32 {
                    g.addTask(executorPreference: rt.executor) {
                        spin(microseconds: 2_000)
                        return Runtime.currentWorker!
                    }
                }
                return await g.reduce(into: Set<Int>()) { $0.insert($1) }
            }
        }
        #expect(workers.count >= 3, "ran on \(workers)")
        #expect(rt.metrics.map(\.steals).reduce(0, +) > 0)
    }

    @Test func sleepsWakeInOrderAndOnTime() {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let order = Log<Int>()
        let start = cv_now_ns()
        rt.block {
            await withTaskGroup(of: Void.self) { g in
                for ms in [30, 10, 20] {
                    g.addTask(executorPreference: rt.executor) {
                        try? await Runtime.sleep(for: .milliseconds(ms))
                        order.append(ms)
                    }
                }
            }
        }
        let elapsed = (cv_now_ns() - start) / 1_000_000
        #expect(order.all == [10, 20, 30])
        #expect(rt.scheduler.timedEnqueues.load(ordering: .relaxed) == 3)
        #expect(elapsed >= 30 && elapsed < 200, "took \(elapsed) ms")
    }

    /// A sleeper must wake on time even while every worker is busy.
    @Test func timersFireWhileWorkersAreBusy() {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let late = rt.block { () async -> UInt64 in
            await withTaskGroup(of: UInt64.self) { g in
                g.addTask(executorPreference: rt.executor) {
                    let t0 = cv_now_ns()
                    try? await Runtime.sleep(for: .milliseconds(5))
                    return (cv_now_ns() - t0) / 1_000_000
                }
                for _ in 0..<2 {
                    // Busy, but yielding often: Swift can't preempt a job.
                    g.addTask(executorPreference: rt.executor) {
                        for _ in 0..<200 { spin(microseconds: 100); await Task.yield() }
                        return 0
                    }
                }
                return await g.max()!
            }
        }
        #expect(late < 30, "sleep(5ms) took \(late) ms")
    }

    @Test func sleepIsCancellable() {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let t0 = cv_now_ns()
        let outcome = rt.block { () async -> String in
            let sleeper = rt.spawn { () async throws -> Void in try await Runtime.sleep(for: .seconds(10)) }
            try? await Runtime.sleep(for: .milliseconds(5))
            sleeper.cancel()
            do { try await sleeper.value; return "finished" } catch is CancellationError { return "cancelled" } catch { return "\(error)" }
        }
        #expect(outcome == "cancelled")
        #expect((cv_now_ns() - t0) / 1_000_000 < 1_000)
    }

    @Test func sleepCancelledBeforeItStartsThrowsAtOnce() {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let threw = rt.block { () async -> Bool in
            let t = rt.spawn { () async throws -> Void in
                withUnsafeCurrentTask { $0?.cancel() }
                try await Runtime.sleep(for: .seconds(10))
            }
            return (try? await t.value) == nil
        }
        #expect(threw)
    }

    /// A Vega sleep wakes on the worker that fires it: no hop through a
    /// foreign thread (Task.sleep makes one, via Swift's global executor).
    @Test func vegaSleepWakesWithoutForeignHop() {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let s = rt.scheduler
        let before = s.foreignEnqueues.load(ordering: .relaxed)
        rt.block { try? await Runtime.sleep(for: .milliseconds(5)) }
        #expect(s.foreignEnqueues.load(ordering: .relaxed) - before == 1, "only block's own start")
    }

    /// With one worker, two tasks that yield must alternate.
    @Test func yieldIsFair() {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let log = Log<Character>()
        rt.block {
            await withTaskGroup(of: Void.self) { g in
                for c in ["a", "b"] as [Character] {
                    g.addTask(executorPreference: rt.executor) {
                        for _ in 0..<5 { log.append(c); await Task.yield() }
                    }
                }
            }
        }
        let s = String(log.all)
        #expect(!s.contains("aaa") && !s.contains("bbb"), "\(s)")
    }

    /// Two tasks handing a token back and forth (the LIFO slot's case).
    @Test func pingPong() {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        let rounds = 50_000
        let done = rt.block { () async -> Int in
            let (fromA, toB) = AsyncStream.makeStream(of: Int.self)
            let (fromB, toA) = AsyncStream.makeStream(of: Int.self)
            let b = rt.spawn {
                var n = 0
                for await v in fromA { n = v; toA.yield(v + 1) }
                return n
            }
            var it = fromB.makeAsyncIterator()
            var v = 0
            for _ in 0..<rounds { toB.yield(v); v = await it.next()! }
            toB.finish()
            _ = await b.value
            return v
        }
        #expect(done == rounds)
    }
}
