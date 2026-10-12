import CVega
import Synchronization

/// The time a runtime's timers run on: the monotonic clock, or paused time
/// that moves only when a test says so (VegaTest's `MockClock`). Values are
/// `cv_now_ns()`-style nanoseconds and never go backwards.
struct RuntimeClock: ~Copyable {
    /// The paused time, or 0 while the clock runs (`cv_now_ns()` is never 0).
    private let frozen = Atomic<UInt64>(0)
    /// Added (wrapping) to `cv_now_ns()` while running: how far paused time
    /// got ahead of real time before it resumed.
    private let offset = Atomic<UInt64>(0)
    /// While paused, jump to the next timer whenever every worker is idle.
    let autoAdvance = Atomic<Bool>(false)
    /// One moment on both clocks, read once: converting through it is exact
    /// both ways (reading the two clocks afresh would add jitter).
    private let epoch: (instant: ContinuousClock.Instant, nanos: UInt64)

    init() {
        epoch = (ContinuousClock.now, cv_now_ns())
    }

    /// A clock time as a `ContinuousClock.Instant`.
    func instant(_ nanos: UInt64) -> ContinuousClock.Instant {
        epoch.instant + .nanoseconds(Int64(bitPattern: nanos &- epoch.nanos))
    }

    /// An instant as a clock time (0 at the earliest).
    func nanos(_ instant: ContinuousClock.Instant) -> UInt64 {
        let ns = Scheduler.nanoseconds(epoch.instant.duration(to: instant))
        if instant < epoch.instant {
            let back = UInt64(clamping: Scheduler.nanoseconds(instant.duration(to: epoch.instant)))
            return back >= epoch.nanos ? 0 : epoch.nanos - back
        }
        return UInt64(clamping: ns) > UInt64.max - epoch.nanos ? UInt64.max - 1 : epoch.nanos + UInt64(ns)
    }

    @inline(__always) var now: UInt64 {
        let f = frozen.load(ordering: .acquiring)
        return f != 0 ? f : cv_now_ns() &+ offset.load(ordering: .relaxed)
    }

    @inline(__always) var isPaused: Bool { frozen.load(ordering: .relaxed) != 0 }

    /// Freeze the time, rounded up to a whole `tick` after `origin`: timers
    /// round deadlines up to ticks, so a timer set from paused time then
    /// falls due exactly when the clock is advanced by its duration.
    func pause(autoAdvance: Bool, origin: UInt64, tick: UInt64) {
        self.autoAdvance.store(autoAdvance, ordering: .relaxed)
        let t = now
        let aligned = t <= origin ? origin + tick : origin + ((t - origin - 1) / tick + 1) * tick
        _ = frozen.compareExchange(expected: 0, desired: aligned, ordering: .acquiringAndReleasing)
    }

    /// Run again from the paused time, at real speed.
    func resume() {
        let f = frozen.load(ordering: .acquiring)
        guard f != 0 else { return }
        offset.store(f &- cv_now_ns(), ordering: .relaxed)
        frozen.store(0, ordering: .releasing)
    }

    /// Move paused time forward to `t` (never back). False if not paused.
    @discardableResult
    func advance(to t: UInt64) -> Bool {
        var f = frozen.load(ordering: .acquiring)
        while true {
            if f == 0 { return false }
            if f >= t { return true }
            let (done, seen) = frozen.compareExchange(expected: f, desired: t, ordering: .acquiringAndReleasing)
            if done { return true }
            f = seen
        }
    }
}

extension Runtime {
    /// The time on the calling worker's runtime clock, or the monotonic
    /// clock's off a worker. Timers compare against this.
    @inline(__always) static var nowNanos: UInt64 {
        Worker.currentScheduler?.clock.now ?? cv_now_ns()
    }

    /// Now, as the runtime's timers see it: `ContinuousClock.now`, unless a
    /// test paused the runtime's clock (VegaTest's `MockClock`).
    /// `sleep(until:)`, `timeout(until:)` and `Interval` measure from it.
    public static var now: ContinuousClock.Instant {
        guard let s = Worker.currentScheduler else { return .now }
        return s.clock.instant(s.clock.now)
    }
}

extension Scheduler {
    /// Paused time moved forward: fire what came due, here if this is one
    /// of our workers, else by waking the timer owner or a sleeper.
    func clockAdvanced() {
        if let w = Worker.current, w._withUnsafeGuaranteedRef({ $0.owner == Unmanaged.passUnretained(self).toOpaque() }) {
            _ = w._withUnsafeGuaranteedRef { fireDueTimers(on: $0) }
        }
        let owner = timerOwner.load(ordering: .sequentiallyConsistent)
        if owner >= 0 {
            cv_unpark(parkers[owner])
        } else {
            notifyParked()
        }
    }

    /// Whether paused time may jump to the next timer: nothing can run, and
    /// nothing outside the workers (a blocking job) will make it runnable.
    func canAutoAdvance() -> Bool {
        clock.autoAdvance.load(ordering: .relaxed) && idle.allParked
            && blockingInFlight.load(ordering: .sequentiallyConsistent) == 0 && !hasPendingWork()
    }
}

// Hooks for VegaTest's MockClock. SPI: paused time is for tests only.
@_spi(VegaTest)
extension Runtime {
    /// Freeze the runtime's timers at the current time.
    public func pauseClock(autoAdvance: Bool) {
        scheduler.clock.pause(autoAdvance: autoAdvance, origin: scheduler.timers.origin,
                              tick: TimerWheel.tickNanos)
        scheduler.clockAdvanced() // the timer owner re-plans its sleep
    }

    /// Let the clock run again, at real speed, from the paused time.
    public func resumeClock() {
        scheduler.clock.resume()
        scheduler.clockAdvanced()
    }

    public var isClockPaused: Bool { scheduler.clock.isPaused }

    /// The runtime clock's time.
    public var clockNow: ContinuousClock.Instant { scheduler.clock.instant(scheduler.clock.now) }

    /// Move paused time forward by `duration` and fire the timers that came due.
    public func advanceClock(by duration: Duration) {
        let now = scheduler.clock.now
        let ns = UInt64(clamping: Scheduler.nanoseconds(duration))
        advanceClock(toNanos: ns > UInt64.max - now ? UInt64.max - 1 : now + ns)
    }

    /// Move paused time forward to `deadline` (never back).
    public func advanceClock(to deadline: ContinuousClock.Instant) {
        advanceClock(toNanos: scheduler.clock.nanos(deadline))
    }

    private func advanceClock(toNanos t: UInt64) {
        precondition(scheduler.clock.advance(to: t), "advancing a clock that isn't paused")
        scheduler.clockAdvanced()
    }
}
