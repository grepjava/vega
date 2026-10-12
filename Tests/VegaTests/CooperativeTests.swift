import Synchronization
import Testing
@testable import Vega

/// Atomics in a box, so escaping closures can share them.
final class Flag: Sendable {
    private let v = Atomic<Bool>(false)
    func set() { v.store(true, ordering: .releasing) }
    var isSet: Bool { v.load(ordering: .acquiring) }
}

final class Counter: Sendable {
    private let v = Atomic<Int>(0)
    @discardableResult func add(_ n: Int = 1) -> Int { v.add(n, ordering: .relaxed).newValue }
    var value: Int { v.load(ordering: .relaxed) }
}

@Suite struct CooperativeTests {
    @Test func yieldLetsOthersRun() {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let log = Log<String>()
        rt.block { () async -> Void in
            await withTaskGroup(of: Void.self) { g in
                for name in ["a", "b"] {
                    g.addTask(executorPreference: rt.executor) {
                        for i in 0..<3 {
                            log.append("\(name)\(i)")
                            await Runtime.yield()
                        }
                    }
                }
            }
        }
        // One worker: each yield hands over to the other task.
        let all = log.all
        #expect(all.count == 6)
        for i in 1..<all.count { #expect(all[i].first != all[i - 1].first) }
    }

    @Test func yieldOffRuntimeFallsBack() async {
        await Runtime.yield()
    }

    @Test func budgetForcesYield() {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let other = Flag()
        let spins = rt.block { () async -> Int in
            await withTaskGroup(of: Int.self) { g in
                g.addTask(executorPreference: rt.executor) {
                    // Never suspends on its own; only the budget lets the other task in.
                    var n = 0
                    while !other.isSet {
                        await Runtime.consumeBudget()
                        n += 1
                    }
                    return n
                }
                g.addTask(executorPreference: rt.executor) {
                    other.set()
                    return 0
                }
                return await g.reduce(0, +)
            }
        }
        #expect(spins <= Int(Worker.budgetPerPoll) * 2)
    }

    // MARK: Notify

    @Test func notifyPermitIsStoredOnce() {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let n = Notify()
        n.notifyOne()
        n.notifyOne() // coalesces with the first
        rt.block { () async -> Void in await n.notified() }
        let second = Flag()
        rt.spawn { await n.notified(); second.set() }
        spin(microseconds: 20_000)
        #expect(!second.isSet)
        n.notifyOne()
        while !second.isSet { spin(microseconds: 100) }
    }

    @Test func notifyOneWakesInOrderAndNotifyWaitersWakesAll() {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let n = Notify()
        let log = Log<Int>()
        let started = Counter()
        for i in 0..<3 {
            rt.spawn { started.add(); await n.notified(); log.append(i) }
            // Let each one queue up before the next, for a known order.
            while started.value <= i { spin(microseconds: 50) }
            spin(microseconds: 2_000)
        }
        n.notifyOne()
        while log.all.count < 1 { spin(microseconds: 100) }
        #expect(log.all == [0])
        n.notifyWaiters()
        while log.all.count < 3 { spin(microseconds: 100) }
        #expect(Set(log.all) == [0, 1, 2])
        // notifyWaiters stores no permit.
        let late = Flag()
        rt.spawn { await n.notified(); late.set() }
        spin(microseconds: 20_000)
        #expect(!late.isSet)
        n.notifyOne()
    }

    @Test func cancelledWaiterReturns() {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let n = Notify()
        rt.block { () async -> Void in
            let t = Task(executorPreference: rt.executor) { await n.notified() }
            try? await Runtime.sleep(for: .milliseconds(5))
            t.cancel()
            await t.value
            // Cancelled before waiting: returns at once.
            let u = Task(executorPreference: rt.executor) {
                withUnsafeCurrentTask { $0?.cancel() }
                await n.notified()
            }
            await u.value
        }
    }

    @Test func notifyPingPong() {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        let a = Notify(), b = Notify()
        let rounds = 50_000
        rt.block { () async -> Void in
            await withTaskGroup(of: Void.self) { g in
                g.addTask(executorPreference: rt.executor) {
                    for _ in 0..<rounds { await a.notified(); b.notifyOne() }
                }
                g.addTask(executorPreference: rt.executor) {
                    for _ in 0..<rounds { a.notifyOne(); await b.notified() }
                }
            }
        }
    }

    // MARK: TaskPool

    @Test func poolRunsEverything() {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        let pool = TaskPool(runtime: rt)
        let count = Counter()
        let done = Notify()
        let n = 100_000
        rt.block { () async -> Void in
            for _ in 0..<n {
                pool.spawn {
                    if count.add() == n { done.notifyOne() }
                }
            }
            await done.notified()
        }
        #expect(count.value == n)
        #expect(pool.taskCount <= 4 * 64)
        pool.close()
    }

    @Test func poolGrowsWhenClosuresSuspend() {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let pool = TaskPool(runtime: rt, maxTasks: 16)
        let gate = Notify()
        let waiting = Counter()
        for _ in 0..<8 {
            pool.spawn {
                waiting.add()
                await gate.notified()
                waiting.add(-1)
            }
        }
        // All eight must be suspended at once: needs eight pooled tasks.
        while waiting.value < 8 { spin(microseconds: 100) }
        #expect(pool.taskCount >= 8)
        gate.notifyWaiters()
        while waiting.value > 0 { spin(microseconds: 100) }
        pool.close()
    }
}
