import Synchronization
import Testing
@testable import Vega

/// Counts drops of `Tracked` values, to check channels neither leak nor
/// double-drop what they hold.
final class DropCounter: Sendable {
    let count = Atomic<Int>(0)
    var value: Int { count.load(ordering: .acquiring) }
}

struct Tracked: ~Copyable, Sendable {
    let n: Int
    let drops: DropCounter
    deinit { drops.count.add(1, ordering: .releasing) }
}

@Suite struct SemaphoreTests {
    /// Never more holders than permits, and everybody gets a turn.
    @Test func limitsConcurrency() {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        let sem = Semaphore(permits: 3)
        let c = Gauge()
        let done = rt.block { () async -> Int in
            await withTaskGroup(of: Int.self) { g in
                for _ in 0..<200 {
                    g.addTask(executorPreference: rt.executor) {
                        guard (try? await sem.acquire()) != nil else { return 0 }
                        let now = c.inside.add(1, ordering: .relaxed).newValue
                        c.peak.max(now, ordering: .relaxed)
                        await Runtime.yield()
                        c.inside.subtract(1, ordering: .relaxed)
                        sem.release()
                        return 1
                    }
                }
                return await g.reduce(0, +)
            }
        }
        #expect(done == 200)
        #expect(c.peak.load(ordering: .relaxed) <= 3)
        #expect(sem.availablePermits == 3)
    }

    /// A big request queued first is served before later small ones.
    @Test func handsOutInOrder() {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let sem = Semaphore(permits: 0)
        let order = Log<String>()
        rt.block {
            let big = rt.spawn {
                try? await sem.acquire(3)
                order.append("big")
            }
            try? await Runtime.sleep(for: .milliseconds(10))
            let small = rt.spawn {
                try? await sem.acquire(1)
                order.append("small")
            }
            try? await Runtime.sleep(for: .milliseconds(10))
            sem.release(2) // not enough for big; small must not take them
            try? await Runtime.sleep(for: .milliseconds(10))
            #expect(order.all.isEmpty)
            sem.release(1) // completes big; still none for small
            await big.value
            try? await Runtime.sleep(for: .milliseconds(10))
            #expect(order.all == ["big"])
            sem.release(1)
            await small.value
        }
        #expect(order.all == ["big", "small"])
        #expect(sem.availablePermits == 0)
    }

    /// A cancelled waiter gives back the permits it was already handed.
    @Test func cancelledWaiterReturnsPartialPermits() {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let sem = Semaphore(permits: 1)
        let (outcome, left) = rt.block { () async -> (AcquireError?, Int) in
            let waiter = rt.spawn { () async -> AcquireError? in
                do throws(AcquireError) { try await sem.acquire(4); return nil } catch { return error }
            }
            try? await Runtime.sleep(for: .milliseconds(10))
            sem.release(2) // waiter now holds 3 of its 4
            waiter.cancel()
            return (await waiter.value, sem.availablePermits)
        }
        #expect(outcome == .cancelled)
        #expect(left == 3)
        #expect(sem.tryAcquire(3))
    }

    /// Cancelled while waiting, a non-cancellable acquire keeps waiting.
    @Test func acquireIgnoringCancellationKeepsWaiting() {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let sem = Semaphore(permits: 0)
        let outcome = rt.block { () async -> AcquireError? in
            let waiter = rt.spawn { () async -> AcquireError? in
                do throws(AcquireError) { try await sem.acquireIgnoringCancellation(2); return nil }
                catch { return error }
            }
            try? await Runtime.sleep(for: .milliseconds(10))
            waiter.cancel()
            try? await Runtime.sleep(for: .milliseconds(10))
            sem.release(2)
            return await waiter.value
        }
        #expect(outcome == nil)
        #expect(sem.availablePermits == 0)
    }

    /// A timed acquire gives up at its timeout, and what it had been handed
    /// while queued goes back.
    @Test func timedAcquireTimesOutAndHandsBackWhatItWasGiven() {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let sem = Semaphore(permits: 1)
        let (outcome, waited) = rt.block { () async -> (AcquireError?, Duration) in
            let start = ContinuousClock.now
            do throws(AcquireError) {
                try await sem.acquire(3, timeout: .milliseconds(50))
                return (nil, .zero)
            } catch {
                return (error, ContinuousClock.now - start)
            }
        }
        #expect(outcome == .timedOut)
        #expect(waited >= .milliseconds(40))
        #expect(sem.availablePermits == 1)
        #expect(sem.tryAcquire())
    }

    /// Permits released before the timeout end the wait with them.
    @Test func timedAcquireTakesPermitsReleasedInTime() {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let sem = Semaphore(permits: 0)
        let outcome = rt.block { () async -> AcquireError? in
            let waiter = rt.spawn { () async -> AcquireError? in
                do throws(AcquireError) { try await sem.acquire(timeout: .seconds(5)); return nil }
                catch { return error }
            }
            try? await Runtime.sleep(for: .milliseconds(10))
            sem.release()
            return await waiter.value
        }
        #expect(outcome == nil)
        #expect(sem.availablePermits == 0)
    }

    /// Cancelled while it waits, a timed acquire reports the cancellation,
    /// not a timeout.
    @Test func timedAcquireReportsCancellation() {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let sem = Semaphore(permits: 0)
        let outcome = rt.block { () async -> AcquireError? in
            let waiter = rt.spawn { () async -> AcquireError? in
                do throws(AcquireError) { try await sem.acquire(timeout: .seconds(5)); return nil }
                catch { return error }
            }
            try? await Runtime.sleep(for: .milliseconds(10))
            waiter.cancel()
            return await waiter.value
        }
        #expect(outcome == .cancelled)
        sem.release()
        #expect(sem.tryAcquire())
    }

    /// Off Vega's own tasks the timeout still holds.
    @Test func timedAcquireTimesOutInATaskVegaDidNotStart() async {
        let sem = Semaphore(permits: 0)
        do throws(AcquireError) {
            try await sem.acquire(timeout: .milliseconds(20))
            Issue.record("acquired")
        } catch {
            #expect(error == .timedOut)
        }
        sem.release()
        #expect(sem.tryAcquire())
    }

    @Test func closeFailsWaiters() {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let sem = Semaphore(permits: 0)
        let outcome = rt.block { () async -> AcquireError? in
            let waiter = rt.spawn { () async -> AcquireError? in
                do throws(AcquireError) { try await sem.acquire(); return nil } catch { return error }
            }
            try? await Runtime.sleep(for: .milliseconds(10))
            sem.close()
            return await waiter.value
        }
        #expect(outcome == .closed)
        #expect(sem.isClosed)
    }
}

@Suite struct OneshotTests {
    @Test func sendThenReceiveAcrossTasks() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let v = try rt.block { () async throws(ChannelError) -> Int in
            let ch = Oneshot<Int>()
            rt.spawn(with: ch.sender) { tx in
                try? await Runtime.sleep(for: .milliseconds(5))
                try? tx.send(42)
            }
            var rx = ch.receiver
            return try await rx.receive()
        }
        #expect(v == 42)
    }

    @Test func droppedSenderCloses() {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let outcome = rt.block { () async -> ChannelError? in
            let ch = Oneshot<Int>()
            rt.spawn(with: ch.sender) { tx in
                try? await Runtime.sleep(for: .milliseconds(5))
                _ = consume tx
            }
            var rx = ch.receiver
            do throws(ChannelError) { _ = try await rx.receive(); return nil } catch { return error }
        }
        #expect(outcome == .closed)
    }

    /// Sending to a dropped receiver fails and drops the value exactly once.
    @Test func droppedReceiverFailsSend() {
        let drops = DropCounter()
        let ch = Oneshot<Tracked>()
        let tx = ch.sender
        _ = consume ch.receiver
        let closed = tx.isClosed
        #expect(closed)
        var failure: ChannelError? = nil
        do throws(ChannelError) { try tx.send(Tracked(n: 1, drops: drops)) } catch { failure = error }
        #expect(failure == .closed)
        #expect(drops.value == 1)
    }

    /// A value sent but never received is dropped with the receiver.
    @Test func unreceivedValueIsDropped() throws {
        let drops = DropCounter()
        do {
            let ch = Oneshot<Tracked>()
            try ch.sender.send(Tracked(n: 1, drops: drops))
            #expect(drops.value == 0)
            _ = consume ch.receiver
        }
        #expect(drops.value == 1)
    }

    /// Cancelled while waiting, the receiver still gets the value later.
    @Test func cancelledReceiveCanRetry() {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (first, value) = rt.block { () async -> (ChannelError?, Int) in
            let ch = Oneshot<Int>()
            let waiter = rt.spawn(with: ch.receiver) { rx -> (ChannelError?, Int) in
                var rx = rx
                var first: ChannelError? = nil
                do throws(ChannelError) { _ = try await rx.receive() } catch { first = error }
                // Still cancelled: each receive gives up at once until the
                // value is there to take without waiting.
                for _ in 0..<1_000_000 {
                    if let v = try? await rx.receive() { return (first, v) }
                    await Runtime.yield()
                }
                return (first, -1)
            }
            try? await Runtime.sleep(for: .milliseconds(10))
            waiter.cancel()
            try? await Runtime.sleep(for: .milliseconds(5))
            try? ch.sender.send(7)
            return await waiter.value
        }
        #expect(first == .cancelled)
        #expect(value == 7)
    }

    @Test func tryReceive() throws {
        let ch = Oneshot<Int>()
        var rx = ch.receiver
        var e1: TryReceiveError? = nil
        do throws(TryReceiveError) { _ = try rx.tryReceive() } catch { e1 = error }
        #expect(e1 == .empty)
        try ch.sender.send(5)
        let v = try rx.tryReceive()
        #expect(v == 5)
        var e2: TryReceiveError? = nil
        do throws(TryReceiveError) { _ = try rx.tryReceive() } catch { e2 = error }
        #expect(e2 == .closed)
    }
}

@Suite struct ChannelTests {
    /// Many producers through a small buffer: everything arrives, each
    /// producer's values in order.
    @Test func manyProducersSmallBuffer() {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        let producers = 8, each = 20_000
        let (sum, ordered) = rt.block { () async -> (Int, Bool) in
            let ch = MPSCChannel<Int>(capacity: 16)
            for p in 0..<producers {
                rt.spawn(with: ch.sender.clone()) { tx in
                    for i in 0..<each { try? await tx.send(p << 32 | i) }
                }
            }
            _ = consume ch.sender
            var rx = ch.receiver
            var next = [Int](repeating: 0, count: producers)
            var sum = 0, ordered = true
            while let v = try? await rx.receive() {
                let p = v >> 32, i = v & 0xFFFF_FFFF
                if i != next[p] { ordered = false }
                next[p] = i + 1
                sum += i
            }
            return (sum, ordered)
        }
        #expect(sum == producers * (each * (each - 1) / 2))
        #expect(ordered)
    }

    /// With the buffer full, parked senders are served in the order they came.
    @Test func parkedSendersAreServedInOrder() {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let got = rt.block { () async -> [Int] in
            let ch = MPSCChannel<Int>(capacity: 1)
            try? ch.sender.trySend(0)
            for i in 1...4 {
                rt.spawn(with: ch.sender.clone()) { tx in try? await tx.send(i) }
                try? await Runtime.sleep(for: .milliseconds(5))
            }
            _ = consume ch.sender
            var rx = ch.receiver
            var got: [Int] = []
            while let v = try? await rx.receive() { got.append(v) }
            return got
        }
        #expect(got == [0, 1, 2, 3, 4])
    }

    @Test func trySendReportsFullAndClosed() throws {
        let ch = MPSCChannel<Int>(capacity: 2)
        let tx = ch.sender
        func send(_ v: Int) -> TrySendError? {
            do throws(TrySendError) { try tx.trySend(v); return nil } catch { return error }
        }
        #expect(send(1) == nil)
        #expect(send(2) == nil)
        #expect(send(3) == .full)
        var rx = ch.receiver
        let a = try rx.tryReceive()
        #expect(a == 1)
        rx.close()
        #expect(send(4) == .closed)
        let b = try rx.tryReceive() // queued values survive close()
        #expect(b == 2)
        var end: TryReceiveError? = nil
        do throws(TryReceiveError) { _ = try rx.tryReceive() } catch { end = error }
        #expect(end == .closed)
    }

    /// Dropping the receiver fails parked senders and drops every value once.
    @Test func droppedReceiverFailsParkedSenders() {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let drops = DropCounter()
        let outcomes = rt.block { () async -> [ChannelError?] in
            let ch = MPSCChannel<Tracked>(capacity: 2)
            try? ch.sender.trySend(Tracked(n: 0, drops: drops))
            try? ch.sender.trySend(Tracked(n: 1, drops: drops))
            var tasks: [Task<ChannelError?, Never>] = []
            for i in 2..<5 {
                tasks.append(rt.spawn(with: ch.sender.clone()) { tx -> ChannelError? in
                    do throws(ChannelError) { try await tx.send(Tracked(n: i, drops: drops)); return nil }
                    catch { return error }
                })
            }
            try? await Runtime.sleep(for: .milliseconds(10))
            _ = consume ch.receiver
            var out: [ChannelError?] = []
            for t in tasks { out.append(await t.value) }
            return out
        }
        #expect(outcomes == [.closed, .closed, .closed])
        #expect(drops.value == 5)
    }

    /// A cancelled parked send drops its value and leaves the channel usable.
    @Test func cancelledSendDropsItsValue() {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let drops = DropCounter()
        let (outcome, first, second) = rt.block { () async -> (ChannelError?, Int, Int) in
            let ch = MPSCChannel<Tracked>(capacity: 1)
            try? ch.sender.trySend(Tracked(n: 1, drops: drops))
            let parked = rt.spawn(with: ch.sender.clone()) { tx -> ChannelError? in
                do throws(ChannelError) { try await tx.send(Tracked(n: 2, drops: drops)); return nil }
                catch { return error }
            }
            try? await Runtime.sleep(for: .milliseconds(10))
            parked.cancel()
            let outcome = await parked.value
            try? ch.sender.trySend(Tracked(n: 3, drops: drops))  // full: dropped
            var rx = ch.receiver
            var a = -1
            if let t = try? await rx.receive() { a = t.n }
            try? await ch.sender.send(Tracked(n: 4, drops: drops))
            var b = -1
            if let t = try? await rx.receive() { b = t.n }
            return (outcome, a, b)
        }
        #expect(outcome == .cancelled)
        #expect(first == 1 && second == 4)
        #expect(drops.value == 4)
    }

    /// Cancelled while waiting, the receiver loses nothing: a value sent
    /// afterwards is still there for it.
    @Test func cancelledReceiveLosesNothing() {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (first, value) = rt.block { () async -> (ChannelError?, Int) in
            let ch = MPSCChannel<Int>(capacity: 4)
            let waiter = rt.spawn(with: ch.receiver) { rx -> (ChannelError?, Int) in
                var rx = rx
                var first: ChannelError? = nil
                do throws(ChannelError) { _ = try await rx.receive() } catch { first = error }
                for _ in 0..<1_000_000 {
                    if let v = try? await rx.receive() { return (first, v) }
                    await Runtime.yield()
                }
                return (first, -1)
            }
            try? await Runtime.sleep(for: .milliseconds(10))
            waiter.cancel()
            try? await Runtime.sleep(for: .milliseconds(5))
            try? await ch.sender.send(9)
            return await waiter.value
        }
        #expect(first == .cancelled)
        #expect(value == 9)
    }

    /// Cancelled while parked, non-cancellable sends and receives keep
    /// waiting and complete once the other side shows up.
    @Test func ignoringCancellationKeepsWaiting() {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (received, sent) = rt.block { () async -> (Int, ChannelError?) in
            // Receiver side: waits on an empty channel.
            let a = MPSCChannel<Int>(capacity: 1)
            let receiver = rt.spawn(with: a.receiver) { rx -> Int in
                var rx = rx
                return (try? await rx.receiveIgnoringCancellation()) ?? -1
            }
            // Sender side: waits on a full channel.
            let b = MPSCChannel<Int>(capacity: 1)
            try? b.sender.trySend(1)
            let sender = rt.spawn(with: b.sender.clone()) { tx -> ChannelError? in
                do throws(ChannelError) { try await tx.sendIgnoringCancellation(2); return nil }
                catch { return error }
            }
            try? await Runtime.sleep(for: .milliseconds(10))
            receiver.cancel()
            sender.cancel()
            try? await Runtime.sleep(for: .milliseconds(10))
            try? a.sender.trySend(7)
            var rx = b.receiver
            _ = try? rx.tryReceive() // makes room: the parked 2 moves in
            let sent = await sender.value
            let second = try? rx.tryReceive()
            #expect(second == 2)
            return (await receiver.value, sent)
        }
        #expect(received == 7)
        #expect(sent == nil)
    }

    @Test func unboundedNeverWaits() {
        let ch = MPSCChannel<Int>.unbounded()
        for i in 0..<100_000 { try? ch.sender.trySend(i) }
        var rx = ch.receiver
        let queued = rx.count
        #expect(queued == 100_000)
        var sum = 0
        while let v = try? rx.tryReceive() { sum += v }
        #expect(sum == 100_000 * 99_999 / 2)
    }

    /// Two tasks bouncing a counter through a pair of capacity-1 channels.
    @Test func pingPong() throws {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        let rounds = 50_000
        let last = try rt.block { () async throws(ChannelError) -> Int in
            let there = MPSCChannel<Int>(capacity: 1)
            let back = MPSCChannel<Int>(capacity: 1)
            let echo = rt.spawn(with: Bounce(rx: there.receiver, tx: back.sender)) { b in
                var rx = b.rx
                while let v = try? await rx.receive() { try? await b.tx.send(v + 1) }
            }
            let tx = there.sender
            var rx = back.receiver
            var v = 0
            for _ in 0..<rounds {
                try await tx.send(v)
                v = try await rx.receive()
            }
            _ = consume tx // closes `there`: the echo task's loop ends
            await echo.value
            return v
        }
        #expect(last == rounds)
    }
}

struct Bounce: ~Copyable, Sendable {
    var rx: MPSCChannel<Int>.Receiver
    let tx: MPSCChannel<Int>.Sender
}

final class Gauge: Sendable {
    let inside = Atomic<Int>(0)
    let peak = Atomic<Int>(0)
}
