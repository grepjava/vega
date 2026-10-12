import CVega
import Synchronization
import Testing
import Vega
import VegaTest
#if canImport(Glibc)
import Glibc
#endif

private final class ClockLog: Sendable {
    private let entries = Mutex<[String]>([])
    func add(_ s: String) { entries.withLock { $0.append(s) } }
    var all: [String] { entries.withLock { $0 } }
}

private func realMillis(since t0: UInt64) -> UInt64 { (cv_now_ns() - t0) / 1_000_000 }

@Suite struct MockClockTests {
    /// An hour-long sleep returns at once, and the clock reads an hour later.
    @Test func autoAdvanceSkipsIdleTime() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let clock = MockClock(pausing: rt)
        let start = clock.now
        let t0 = cv_now_ns()
        let after = try rt.block { () async throws -> ContinuousClock.Instant in
            try await Runtime.sleep(for: .seconds(3600))
            return Runtime.now
        }
        #expect(realMillis(since: t0) < 1_000)
        #expect(start.duration(to: after) >= .seconds(3600))
        #expect(start.duration(to: after) < .seconds(3601))
    }

    /// Timers fire in deadline order, however they were started.
    @Test func timersFireInDeadlineOrder() throws {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        _ = MockClock(pausing: rt)
        let log = ClockLog()
        try rt.block { () async throws in
            try await withThrowingTaskGroup(of: Void.self) { group in
                for hours in [5, 1, 4, 2, 3] {
                    group.addTask {
                        try await Runtime.sleep(for: .seconds(3600 * hours))
                        log.add("\(hours)")
                    }
                }
                try await group.waitForAll()
            }
        }
        #expect(log.all == ["1", "2", "3", "4", "5"])
    }

    /// Without auto-advance, time moves only when told.
    @Test func manualAdvance() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let clock = MockClock(pausing: rt, autoAdvance: false)
        let woke = Atomic<Bool>(false)
        let fired = try withUnsafePointer(to: woke) { p in
            nonisolated(unsafe) let woke = p
            return try rt.block { () async throws -> (Bool, Bool) in
                let deadline = clock.now + .seconds(10)
                let sleeper = rt.spawn {
                    try await Runtime.sleep(until: deadline)
                    woke.pointee.store(true, ordering: .sequentiallyConsistent)
                }
                await clock.advance(by: .seconds(9))
                for _ in 0..<100 { await Runtime.yield() }
                let early = woke.pointee.load(ordering: .sequentiallyConsistent)
                await clock.advance(by: .seconds(1))
                try await sleeper.value
                return (early, woke.pointee.load(ordering: .sequentiallyConsistent))
            }
        }
        #expect(fired == (false, true))
    }

    @Test func timeoutOnPausedTime() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        _ = MockClock(pausing: rt)
        let t0 = cv_now_ns()
        let timedOut = try rt.block { () async throws -> Bool in
            do {
                try await Runtime.timeout(.seconds(30)) { try await Runtime.sleep(for: .seconds(60)) }
                return false
            } catch is TimeoutError {
                return true
            }
        }
        #expect(timedOut)
        #expect(realMillis(since: t0) < 1_000)
    }

    @Test func intervalOnPausedTime() throws {
        let rt = Runtime(workers: 1)
        defer { rt.shutdown() }
        _ = MockClock(pausing: rt)
        let gaps = try rt.block { () async throws -> [Duration] in
            var interval = Interval(every: .seconds(60))
            let first = try await interval.tick()
            var gaps: [Duration] = []
            for _ in 0..<3 { gaps.append(first.duration(to: try await interval.tick())) }
            return gaps
        }
        #expect(gaps == [.seconds(60), .seconds(120), .seconds(180)])
    }

    /// Time doesn't jump while a blocking job is out: its result comes back
    /// before a timer that, in paused time, is still in the future.
    @Test func blockingJobsHoldTimeStill() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        _ = MockClock(pausing: rt)
        let log = ClockLog()
        try rt.block { () async throws in
            let timer = rt.spawn {
                try await Runtime.sleep(for: .milliseconds(10))
                log.add("timer")
            }
            _ = await Runtime.blocking { usleep(100_000) }
            log.add("blocking")
            try await timer.value
        }
        #expect(log.all == ["blocking", "timer"])
    }

    /// Resuming continues from the paused time at real speed.
    @Test func resumeRunsOnFromPausedTime() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let clock = MockClock(pausing: rt, autoAdvance: false)
        let start = clock.now
        let (ahead, slept) = try rt.block { () async throws -> (Duration, UInt64) in
            await clock.advance(by: .seconds(3600))
            clock.resume()
            let t0 = cv_now_ns()
            try await Runtime.sleep(for: .milliseconds(30))
            return (start.duration(to: Runtime.now), realMillis(since: t0))
        }
        #expect(!clock.isPaused)
        #expect(ahead >= .seconds(3600))
        #expect(slept >= 30)
    }

    /// `MockClock` is a `Clock`: code generic over clocks sleeps in paused time.
    @Test func sleepsThroughTheClockProtocol() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let clock = MockClock(pausing: rt)
        func wait<C: Clock>(on clock: C, _ d: C.Duration) async throws { try await clock.sleep(for: d) }
        let t0 = cv_now_ns()
        try rt.block { () async throws in try await wait(on: clock, .seconds(86_400)) }
        #expect(realMillis(since: t0) < 1_000)
    }
}
