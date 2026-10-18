import Synchronization
import Testing
@testable import Vega

private final class SeenFlag: Sendable { let value = Atomic<Int>(0) }

private struct Failed: Error, Equatable { let n: Int }

@Suite("JoinSet")
struct JoinSetTests {
    /// Results come back in the order the tasks finish, not the order they
    /// were spawned.
    @Test func resultsInCompletionOrder() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let order = rt.block { () async -> [Int] in
            let set = JoinSet<Int, Never>(runtime: rt)
            for (n, ms) in [(1, 60), (2, 10), (3, 35)] {
                set.spawn {
                    try? await Runtime.sleep(for: .milliseconds(ms))
                    return n
                }
            }
            #expect(set.count == 3)
            var order: [Int] = []
            while let r = await set.next() { order.append(r.get()) }
            #expect(set.isEmpty)
            return order
        }
        #expect(order == [2, 3, 1])
    }

    @Test func errorsComeBackTyped() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (values, errors) = rt.block { () async -> ([Int], [Failed]) in
            let set = JoinSet<Int, Failed>()
            for n in 0..<10 {
                set.spawn { () async throws(Failed) -> Int in
                    if n % 3 == 0 { throw Failed(n: n) }
                    return n
                }
            }
            var values: [Int] = [], errors: [Failed] = []
            while let r = await set.next() {
                switch r {
                case .success(let v): values.append(v)
                case .failure(let e): errors.append(e)
                }
            }
            return (values.sorted(), errors.sorted { $0.n < $1.n })
        }
        #expect(values == [1, 2, 4, 5, 7, 8])
        #expect(errors == [Failed(n: 0), Failed(n: 3), Failed(n: 6), Failed(n: 9)])
    }

    @Test func nextOnAnEmptySetIsNil() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let empty = rt.block { () async -> Bool in
            await JoinSet<Int, Never>().next() == nil
        }
        #expect(empty)
    }

    /// Many short tasks, some finishing before `spawn` has stored their
    /// handle.
    @Test func manyTasks() throws {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        let sum = rt.block { () async -> Int in
            let set = JoinSet<Int, Never>(runtime: rt)
            for n in 1...10_000 { set.spawn { n } }
            var sum = 0
            while let v = await set.nextValue() { sum += v }
            return sum
        }
        #expect(sum == 10_000 * 10_001 / 2)
    }

    @Test func cancelAllCancelsRunningAndLaterTasks() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let cancelled = rt.block { () async -> [Bool] in
            let set = JoinSet<Bool, Never>(runtime: rt)
            for _ in 0..<4 {
                set.spawn {
                    try? await Runtime.sleep(for: .seconds(30))
                    return Task.isCancelled
                }
            }
            set.cancelAll()
            set.spawn { Task.isCancelled }
            var all: [Bool] = []
            while let v = await set.nextValue() { all.append(v) }
            return all
        }
        #expect(cancelled == [true, true, true, true, true])
    }

    /// `shutdown()` waits for the tasks, and the set takes new ones after.
    @Test func shutdownThenReuse() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (empty, later) = rt.block { () async -> (Bool, Bool?) in
            let set = JoinSet<Bool, Never>(runtime: rt)
            for _ in 0..<3 {
                set.spawn {
                    try? await Runtime.sleep(for: .seconds(30))
                    return true
                }
            }
            await set.shutdown()
            let empty = set.isEmpty
            set.spawn { Task.isCancelled }
            return (empty, await set.nextValue())
        }
        #expect(empty)
        #expect(later == false)
    }

    /// A cancelled caller's `shutdown()` still waits for every task.
    @Test func shutdownByACancelledTask() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let empty = rt.block { () async -> Bool in
            let set = JoinSet<Bool, Never>(runtime: rt)
            for _ in 0..<3 {
                set.spawn {
                    // Ends a while after it is cancelled, as a task cleaning up would.
                    try? await Runtime.sleep(for: .seconds(30))
                    let end = ContinuousClock.now + .milliseconds(50)
                    while ContinuousClock.now < end { await Task.yield() }
                    return true
                }
            }
            let stopper = rt.spawn {
                withUnsafeCurrentTask { $0?.cancel() }
                await set.shutdown()
            }
            await stopper.value
            return set.isEmpty
        }
        #expect(empty)
    }

    /// Dropping the set cancels what is still in it.
    @Test func droppingTheSetCancels() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let seen = SeenFlag()
        let wasCancelled = rt.block { () async -> Bool in
            do {
                let set = JoinSet<Void, Never>(runtime: rt)
                set.spawn {
                    try? await Runtime.sleep(for: .seconds(30))
                    seen.value.store(Task.isCancelled ? 1 : 2, ordering: .releasing)
                }
                _ = set
            }
            for _ in 0..<200 where seen.value.load(ordering: .acquiring) == 0 {
                try? await Runtime.sleep(for: .milliseconds(10))
            }
            return seen.value.load(ordering: .acquiring) == 1
        }
        #expect(wasCancelled)
    }

    /// A cancelled waiter gets nil, and the result stays for the next call.
    @Test func cancellingTheWaiter() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (first, second) = rt.block { () async -> (Bool, Int?) in
            let set = JoinSet<Int, Never>(runtime: rt)
            set.spawn {
                try? await Runtime.sleep(for: .milliseconds(100))
                return 7
            }
            let waiter = rt.spawn { await set.next() == nil }
            try? await Runtime.sleep(for: .milliseconds(10))
            waiter.cancel()
            return (await waiter.value, await set.nextValue())
        }
        #expect(first)
        #expect(second == 7)
    }
}
