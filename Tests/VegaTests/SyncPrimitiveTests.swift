import Synchronization
import Testing
@testable import Vega

@Suite struct AsyncMutexTests {
    /// The lock is held across awaits: increments that yield in the middle
    /// still don't interleave.
    @Test func excludesAcrossAwaits() throws {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        let counter = AsyncMutex(0)
        let inside = Atomic<Int>(0)
        let overlap = Atomic<Bool>(false)
        try withUnsafePointer(to: inside) { insideP in
            try withUnsafePointer(to: overlap) { overlapP in
                nonisolated(unsafe) let inside = insideP, overlap = overlapP
                try rt.block { () async throws in
                    try await withThrowingTaskGroup(of: Void.self) { g in
                        for _ in 0..<50 {
                            g.addTask {
                                for _ in 0..<20 {
                                    try await counter.withLock { n in
                                        if inside.pointee.add(1, ordering: .sequentiallyConsistent).newValue > 1 {
                                            overlap.pointee.store(true, ordering: .relaxed)
                                        }
                                        let v = n
                                        await Runtime.yield()
                                        n = v + 1
                                        inside.pointee.subtract(1, ordering: .sequentiallyConsistent)
                                    }
                                }
                            }
                        }
                        try await g.waitForAll()
                    }
                }
            }
        }
        let total = try rt.block { () async throws in try await counter.withLock { $0 } }
        let overlapped = overlap.load(ordering: .relaxed)
        #expect(total == 1_000)
        #expect(!overlapped)
    }

    @Test func tryWithLockFailsWhileHeld() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let m = AsyncMutex("x")
        let (inner, outer) = try rt.block { () async throws -> (String?, String?) in
            let inner = try await m.withLock { _ in m.tryWithLock { $0 } }
            return (inner, m.tryWithLock { $0 })
        }
        #expect(inner == nil)
        #expect(outer == "x")
    }

    @Test func cancelledWaiterDoesNotTakeTheLock() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let m = AsyncMutex(0)
        let outcome = try rt.block { () async throws -> String in
            let gate = Notify()
            let holder = rt.spawn {
                try? await m.withLock { _ in await gate.notified() }
            }
            try await Runtime.sleep(for: .milliseconds(10))
            let waiter = rt.spawn { () async -> String in
                do {
                    try await m.withLock { $0 += 1 }
                    return "locked"
                } catch {
                    return "\(error)"
                }
            }
            try await Runtime.sleep(for: .milliseconds(10))
            waiter.cancel()
            let r = await waiter.value
            gate.notifyOne()
            await holder.value
            return r
        }
        #expect(outcome == "cancelled")
        let after = try rt.block { () async throws in try await m.withLock { $0 } }
        #expect(after == 0)
    }
}

@Suite struct AsyncRWLockTests {
    /// Readers share: several are inside at once. A writer is alone.
    @Test func readersShareWritersExclude() throws {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        let lock = AsyncRWLock([Int]())
        let readers = Atomic<Int>(0), maxReaders = Atomic<Int>(0), writerOverlap = Atomic<Bool>(false)
        try withUnsafePointer(to: readers) { r in
            try withUnsafePointer(to: maxReaders) { mr in
                try withUnsafePointer(to: writerOverlap) { wo in
                    nonisolated(unsafe) let readers = r, maxReaders = mr, overlap = wo
                    try rt.block { () async throws in
                        try await withThrowingTaskGroup(of: Void.self) { g in
                            for i in 0..<40 {
                                g.addTask {
                                    if i % 8 == 0 {
                                        try await lock.withWriteLock { v in
                                            if readers.pointee.load(ordering: .sequentiallyConsistent) != 0 {
                                                overlap.pointee.store(true, ordering: .relaxed)
                                            }
                                            await Runtime.yield()
                                            v.append(i)
                                        }
                                    } else {
                                        try await lock.withReadLock { _ in
                                            let n = readers.pointee.add(1, ordering: .sequentiallyConsistent).newValue
                                            var m = maxReaders.pointee.load(ordering: .relaxed)
                                            while n > m {
                                                let (ok, now) = maxReaders.pointee.compareExchange(
                                                    expected: m, desired: n, ordering: .relaxed)
                                                if ok { break }
                                                m = now
                                            }
                                            try? await Runtime.sleep(for: .milliseconds(2))
                                            readers.pointee.subtract(1, ordering: .sequentiallyConsistent)
                                        }
                                    }
                                }
                            }
                            try await g.waitForAll()
                        }
                    }
                }
            }
        }
        let written = try rt.block { () async throws in try await lock.withReadLock { $0.count } }
        let most = maxReaders.load(ordering: .relaxed), overlapped = writerOverlap.load(ordering: .relaxed)
        #expect(written == 5)
        #expect(most > 1)
        #expect(!overlapped)
    }

    @Test func tryLocks() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let lock = AsyncRWLock(1)
        let r = try rt.block { () async throws -> [Bool] in
            let underRead = try await lock.withReadLock { _ in
                [lock.tryWithReadLock { _ in true } ?? false, lock.tryWithWriteLock { _ in true } ?? false]
            }
            let underWrite = try await lock.withWriteLock { _ in
                [lock.tryWithReadLock { _ in true } ?? false]
            }
            return underRead + underWrite
        }
        #expect(r == [true, false, false])
    }
}

@Suite struct BarrierTests {
    /// Three rounds of four: each round releases together, one leader each.
    @Test func releasesTogetherWithOneLeader() throws {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        let barrier = Barrier(count: 4)
        let leaders = rt.block { () async -> Int in
            await withTaskGroup(of: Int.self) { g in
                for _ in 0..<12 {
                    g.addTask { await barrier.wait() ? 1 : 0 }
                }
                return await g.reduce(0, +)
            }
        }
        #expect(leaders == 3)
    }

    @Test func nobodyPassesEarly() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let barrier = Barrier(count: 3)
        // On the heap: the spawned tasks count after the barrier, possibly
        // once block has returned.
        let passed = PassCount()
        let seen = try rt.block { () async throws -> Int in
            for _ in 0..<2 {
                rt.spawn {
                    await barrier.wait()
                    passed.value.add(1, ordering: .relaxed)
                }
            }
            try await Runtime.sleep(for: .milliseconds(20))
            let before = passed.value.load(ordering: .relaxed)
            await barrier.wait()
            return before
        }
        #expect(seen == 0)
    }
}

@Suite struct WatchTests {
    @Test func receiversSeeTheLatestValue() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let w = Watch(0)
        let seen = try rt.block { () async throws -> [Int] in
            var r = w.subscribe()
            #expect(!r.hasChanged)
            w.send(1)
            w.send(2) // replaces 1 before the receiver looks
            try await r.changed()
            let first = r.value
            let later = rt.spawn { () async throws -> Int in
                var r2 = w.subscribe()
                try await r2.changed()
                return r2.value
            }
            try await Runtime.sleep(for: .milliseconds(10))
            w.send(3)
            return [first, try await later.value, r.value]
        }
        #expect(seen == [2, 3, 3])
    }

    @Test func closeEndsWaiting() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let w = Watch("a")
        let error = try rt.block { () async throws -> ChannelError? in
            var r = w.subscribe()
            let t = rt.spawn { () async -> ChannelError? in
                do throws(ChannelError) { try await r.changed() } catch { return error }
                return nil
            }
            try await Runtime.sleep(for: .milliseconds(10))
            w.close()
            return await t.value
        }
        #expect(error == .closed)
    }

    @Test func cancelledWaitThrows() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let w = Watch(0)
        let error = try rt.block { () async throws -> ChannelError? in
            var r = w.subscribe()
            let t = rt.spawn { () async -> ChannelError? in
                do throws(ChannelError) { try await r.changed() } catch { return error }
                return nil
            }
            try await Runtime.sleep(for: .milliseconds(10))
            t.cancel()
            return await t.value
        }
        #expect(error == .cancelled)
    }
}

@Suite struct BroadcastTests {
    @Test func everyReceiverGetsEverything() throws {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        let b = Broadcast<Int>(capacity: 128)
        let results = try rt.block { () async throws -> [[Int]] in
            let receivers = (0..<3).map { _ in b.subscribe() }
            let tasks = receivers.map { r in
                rt.spawn { () async -> [Int] in
                    var r = r
                    var got: [Int] = []
                    while let v = try? await r.receive() { got.append(v) }
                    return got
                }
            }
            for i in 0..<100 {
                b.send(i)
                if i % 10 == 0 { await Runtime.yield() }
            }
            b.close()
            var all: [[Int]] = []
            for t in tasks { all.append(await t.value) }
            return all
        }
        for r in results { #expect(r == Array(0..<100)) }
    }

    @Test func slowReceiverLags() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let b = Broadcast<Int>(capacity: 4)
        let (error, next) = try rt.block { () async throws -> (BroadcastError?, Int?) in
            var r = b.subscribe()
            for i in 0..<10 { b.send(i) }
            var lagged: BroadcastError?
            do throws(BroadcastError) { _ = try await r.receive() } catch { lagged = error }
            return (lagged, try? await r.receive())
        }
        #expect(error == .lagged(missed: 6))
        #expect(next == 6)
    }

    @Test func subscribersOnlySeeLaterValues() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        let b = Broadcast<String>(capacity: 8)
        let got = try rt.block { () async throws -> String? in
            b.send("before")
            var r = b.subscribe()
            b.send("after")
            return try await r.receive()
        }
        #expect(got == "after")
    }
}

@Suite struct ShutdownSignalTests {
    /// A trigger wakes waiters and cancels tasks inside `cancelOnTrigger`,
    /// but not ones that have left it; later entries are cancelled at once.
    @Test func triggers() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let signal = ShutdownToken()
        let (woke, cut, leftAlone, late) = try rt.block { () async throws -> (Bool, Bool, Bool, Bool) in
            let waiter = rt.spawn { () async -> Bool in
                await signal.wait()
                return signal.isTriggered
            }
            let sleeper = rt.spawn { () async -> Bool in
                do {
                    try await signal.cancelOnTrigger { try await Runtime.sleep(for: .seconds(30)) }
                    return false
                } catch {
                    return Task.isCancelled
                }
            }
            await signal.cancelOnTrigger { () async in }
            try await Runtime.sleep(for: .milliseconds(20))
            #expect(!signal.isTriggered)
            signal.trigger()
            signal.trigger()
            let leftAlone = !Task.isCancelled
            let late = await rt.spawn { () async -> Bool in
                await signal.cancelOnTrigger { () async in Task.isCancelled }
            }.value
            return (await waiter.value, await sleeper.value, leftAlone, late)
        }
        #expect(woke)
        #expect(cut)
        #expect(leftAlone)
        #expect(late)
    }
}

@Suite struct OnceCellTests {
    /// Many tasks ask at once; the initializer runs once.
    @Test func initializesOnce() throws {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        let cell = OnceCell<Int>()
        let runs = Atomic<Int>(0)
        let values = withUnsafePointer(to: runs) { p in
            nonisolated(unsafe) let runs = p
            return rt.block { () async -> [Int] in
                await withTaskGroup(of: Int.self) { g in
                    for _ in 0..<32 {
                        g.addTask {
                            await cell.getOrInit {
                                runs.pointee.add(1, ordering: .relaxed)
                                try? await Runtime.sleep(for: .milliseconds(5))
                                return 42
                            }
                        }
                    }
                    return await g.reduce(into: []) { $0.append($1) }
                }
            }
        }
        let ran = runs.load(ordering: .relaxed)
        #expect(ran == 1)
        #expect(values.allSatisfy { $0 == 42 })
        #expect(cell.value == 42)
    }

    struct Failed: Error {}

    /// A failed initializer leaves the cell empty; the next caller retries.
    @Test func failedInitializerLetsTheNextTry() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let cell = OnceCell<String>()
        let (first, second) = rt.block { () async -> (Bool, String?) in
            let failed: Bool
            do {
                _ = try await cell.getOrInit { () async throws(Failed) -> String in throw Failed() }
                failed = false
            } catch {
                failed = true
            }
            let v = await cell.getOrInit { "second" }
            return (failed, v)
        }
        #expect(first)
        #expect(second == "second")
        #expect(!cell.set("third"))
    }
}

private final class PassCount: Sendable {
    let value = Atomic<Int>(0)
}
