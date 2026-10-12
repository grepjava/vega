import CVega
import Synchronization
import Testing
@testable import Vega

private let ms: UInt64 = 1_000_000

/// A small deterministic generator (xorshift64*).
private struct Rng {
    var state: UInt64
    mutating func next() -> UInt64 {
        state ^= state >> 12; state ^= state << 25; state ^= state >> 27
        return state &* 2_685_821_657_736_338_717
    }
}

/// The ids of everything `poll` returns, in order.
private func drain(_ w: inout Wheel, _ now: UInt64) -> [Int] {
    guard let due = w.poll(now) else { return [] }
    var ids: [Int] = []
    var e: UnsafeMutablePointer<TimerEntry>? = due.head
    while let cur = e {
        if case .job(let j) = cur.pointee.action { ids.append(jobID(j)) }
        e = cur.pointee.next
    }
    #expect(ids.count == due.count)
    w.recycle(due.head, due.tail)
    return ids
}

@Suite struct TimerWheelTests {
    @Test func firesInDeadlineThenFIFOOrder() {
        let t = TimerWheel(shards: 1, origin: 0)
        func add(_ id: Int, _ at: UInt64) -> TimerWheel.Added {
            t.add(.job(fakeJob(id)), deadline: at * ms, now: 0, shard: 0)
        }
        guard case .inserted(true) = add(1, 30), case .inserted(true) = add(2, 10),
              case .inserted(false) = add(3, 30), case .inserted(false) = add(4, 20) else {
            Issue.record("wrong earliest flags"); return
        }
        #expect(t.timeout(now: 5 * ms) == Int64(5 * ms))
        var order: [Int] = []
        #expect(t.fireDue(shard: 0, now: 9 * ms) { _ in order.append(0) } == 0)
        #expect(t.fireDue(shard: 0, now: 100 * ms) { if case .job(let j) = $0 { order.append(jobID(j)) } } == 4)
        #expect(order == [2, 4, 1, 3])
        #expect(t.timeout(now: 0) == -1)
        #expect(t.count == 0)
    }

    @Test func neverFiresEarly() {
        let t = TimerWheel(shards: 1, origin: 0)
        _ = t.add(.job(fakeJob(1)), deadline: 10 * ms + 500_000, now: 0, shard: 0)
        #expect(t.fireDue(shard: 0, now: 10 * ms + 900_000) { _ in } == 0)
        #expect(t.fireDue(shard: 0, now: 11 * ms) { _ in } == 1)
    }

    @Test func dueTimersAreNotLinked() {
        let t = TimerWheel(shards: 1, origin: 0)
        guard case .due = t.add(.job(fakeJob(1)), deadline: 3 * ms, now: 3 * ms, shard: 0) else {
            Issue.record("expected due"); return
        }
        _ = t.add(.job(fakeJob(2)), deadline: 50 * ms, now: 0, shard: 0)
        _ = t.fireDue(shard: 0, now: 60 * ms) { _ in }
        // The wheel has advanced to 60 ms: an earlier deadline is due even
        // with a stale `now`.
        guard case .due = t.add(.job(fakeJob(3)), deadline: 40 * ms, now: 0, shard: 0) else {
            Issue.record("expected due"); return
        }
        #expect(t.count == 0)
    }

    /// Random deadlines over every level, polled in random steps: each
    /// timer fires exactly once, in the first poll at or after its deadline.
    @Test func cascadesAcrossLevels() {
        var w = Wheel()
        defer { w.destroy() }
        var rng = Rng(state: 0x9E37_79B9_7F4A_7C15)
        var when: [Int: UInt64] = [:]
        for id in 1...5_000 {
            let level = Int(rng.next() % 6)
            let t = 1 + rng.next() % (UInt64(1) << UInt64(6 * (level + 1)))
            when[id] = t
            _ = w.insert(when: t, .job(fakeJob(id)))
        }
        #expect(w.count == 5_000)
        var now: UInt64 = 0
        var fired = Set<Int>()
        var last: UInt64 = 0
        while fired.count < when.count {
            // Small steps near the start, then bigger ones.
            now += 1 + rng.next() % max(1, now / 8 + 1)
            for id in drain(&w, now) {
                let t = when[id]!
                #expect(t <= now, "timer \(id) for \(t) fired at \(now)")
                #expect(t > last, "timer \(id) for \(t) is late: already polled to \(last)")
                #expect(fired.insert(id).inserted)
            }
            last = now
        }
        #expect(w.count == 0)
        #expect(w.nextExpiration() == nil)
    }

    /// Beyond one turn of the top level a timer goes round again, and still
    /// fires at its deadline.
    @Test func farFutureTimerWaitsForItsTurn() {
        var w = Wheel()
        defer { w.destroy() }
        let far: UInt64 = (1 << 37) + 5
        _ = w.insert(when: far, .job(fakeJob(1)))
        var now: UInt64 = 0
        while now < far - 1 {
            now = min(far - 1, now + (1 << 30) + 12_345)
            #expect(drain(&w, now).isEmpty, "fired early at \(now)")
        }
        #expect(drain(&w, far) == [1])
    }

    @Test func removeUnlinksInConstantTime() {
        var w = Wheel()
        defer { w.destroy() }
        var entries: [UnsafeMutablePointer<TimerEntry>] = []
        for i in 1...1_000 { entries.append(w.insert(when: UInt64(i * 37), .job(fakeJob(i)))) }
        // Every other one: unlinking from the middle of a slot keeps the rest.
        for (i, e) in entries.enumerated() where i % 2 == 0 { w.remove(e) }
        #expect(w.count == 500)
        let left = drain(&w, 1_000 * 37)
        #expect(left == Array(stride(from: 2, through: 1_000, by: 2)))
        // Freed entries are reused.
        for i in 1...1_000 { _ = w.insert(when: 50_000 + UInt64(i), .job(fakeJob(i))) }
        #expect(w.count == 1_000)
    }

    @Test func sameTickKeepsInsertionOrderAfterCascading() {
        var w = Wheel()
        defer { w.destroy() }
        // Level 1 at insert time, cascades to level 0 before firing.
        for i in 1...10 { _ = w.insert(when: 200, .job(fakeJob(i))) }
        #expect(drain(&w, 150).isEmpty)
        for i in 11...20 { _ = w.insert(when: 200, .job(fakeJob(i))) }
        #expect(drain(&w, 200) == Array(1...20))
    }
}

@Suite struct TimerRuntimeTests {
    /// Cancelled sleeps give their timers back at once, not at the deadline.
    @Test func cancelledSleepsFreeTheirTimers() {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let left = rt.block { () async -> Int in
            let sleepers = (0..<1_000).map { _ in
                rt.spawn { () async throws -> Void in try await Runtime.sleep(for: .seconds(60)) }
            }
            // Wait until every sleep has linked its timer.
            while rt.scheduler.timers.count < 1_000 { try? await Runtime.sleep(for: .milliseconds(1)) }
            for s in sleepers { s.cancel() }
            for s in sleepers { _ = try? await s.value }
            return rt.scheduler.timers.count
        }
        #expect(left == 0)
    }

    /// Cancellations land just before, at and after the deadline, racing
    /// the firing worker: every sleep ends exactly once, and no timer is
    /// left behind.
    @Test func cancelRacesFiring() {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        let outcomes = rt.block { () async -> (fired: Int, cancelled: Int, left: Int) in
            await withTaskGroup(of: Bool.self) { g in
                for i in 0..<2_000 {
                    g.addTask(executorPreference: rt.executor) {
                        let sleeper = rt.spawn { () async -> Bool in
                            (try? await Runtime.sleep(for: .milliseconds(2))) != nil
                        }
                        spin(microseconds: UInt64(1_000 + (i % 40) * 50))
                        sleeper.cancel()
                        return await sleeper.value
                    }
                }
                var fired = 0, cancelled = 0
                for await f in g { if f { fired += 1 } else { cancelled += 1 } }
                return (fired, cancelled, rt.scheduler.timers.count)
            }
        }
        #expect(outcomes.fired + outcomes.cancelled == 2_000)
        #expect(outcomes.left == 0)
    }

    @Test func sleepUntilWakesAtTheDeadline() {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let start = cv_now_ns()
        let deadline = ContinuousClock.now + .milliseconds(20)
        let late = rt.block { () async -> Duration in
            try? await Runtime.sleep(until: deadline)
            return deadline.duration(to: .now)
        }
        #expect(late >= .zero, "woke \(late) early")
        #expect((cv_now_ns() - start) / ms < 200)
    }

    @Test func intervalTicksOnSchedule() {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let start = cv_now_ns()
        let ticks = rt.block { () async -> [Duration] in
            var iv = Interval(every: .milliseconds(10))
            var at: [ContinuousClock.Instant] = []
            for _ in 0..<5 { at.append(try! await iv.tick()) }
            return at.map { at[0].duration(to: $0) }
        }
        let elapsed = (cv_now_ns() - start) / ms
        // Scheduled exactly one period apart; the first tick is immediate.
        #expect(ticks == (0..<5).map { .milliseconds(10 * $0) })
        #expect(elapsed >= 40 && elapsed < 300, "took \(elapsed) ms")
    }

    @Test func intervalMissedTicks() {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        func run(_ behavior: Interval.MissedTickBehavior) -> [Int] {
            rt.block { () async -> [Int] in
                var iv = Interval(every: .milliseconds(10), missedTickBehavior: behavior)
                let first = try! await iv.tick()
                spin(microseconds: 35_000) // miss three ticks
                var offsets: [Int] = []
                for _ in 0..<3 {
                    let t = try! await iv.tick()
                    let d = first.duration(to: t).components
                    offsets.append(Int(d.seconds * 1_000 + d.attoseconds / 1_000_000_000_000_000))
                }
                return offsets
            }
        }
        // Burst: the missed ticks, back to back, on the old schedule.
        #expect(run(.burst) == [10, 20, 30])
        // Skip: one late tick, then the old schedule from after now (35 ms).
        #expect(run(.skip) == [10, 40, 50])
        // Delay: a new schedule from when the late tick completed.
        let delayed = run(.delay)
        #expect(delayed[0] == 10)
        #expect(delayed[1] >= 45 && delayed[2] - delayed[1] >= 10, "\(delayed)")
    }
}
