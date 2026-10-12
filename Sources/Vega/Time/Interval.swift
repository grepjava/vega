import CVega

/// Ticks at a fixed period, on Vega's timers (Tokio's `time::Interval`).
///
/// ```swift
/// var heartbeat = Interval(every: .seconds(1))
/// while true {
///     try await heartbeat.tick()   // the first tick completes at once
///     await sendPing()
/// }
/// ```
///
/// Ticks are scheduled from the start time, not from when `tick()` was last
/// called, so the period doesn't drift with the work done between ticks.
/// When ticks are missed (the caller was busy for longer than a period),
/// `missedTickBehavior` decides what happens.
public struct Interval: Sendable {
    public enum MissedTickBehavior: Sendable {
        /// Fire the missed ticks back to back until caught up, then keep the
        /// original schedule.
        case burst
        /// Start a new schedule: the next tick is one period after the late
        /// one completes.
        case delay
        /// Drop the missed ticks and keep the original schedule.
        case skip
    }

    public let period: Duration
    public var missedTickBehavior: MissedTickBehavior
    /// The next tick, as a `cv_now_ns()` time.
    private var deadline: UInt64
    private let periodNanos: UInt64
    /// One instant of the public clock and the same moment on the timers'
    /// clock, to report tick times as `ContinuousClock.Instant`s.
    private let base: (instant: ContinuousClock.Instant, nanos: UInt64)

    /// A tick counts as missed when it completes this late (Tokio's value).
    private static let missedAfter: UInt64 = 5_000_000

    /// Tick every `period`, the first time after `delay` (at once by default).
    public init(every period: Duration, delay: Duration = .zero,
                missedTickBehavior: MissedTickBehavior = .burst) {
        precondition(period > .zero, "Interval period must be positive")
        self.period = period
        self.missedTickBehavior = missedTickBehavior
        periodNanos = max(1, UInt64(clamping: Scheduler.nanoseconds(period)))
        let now = cv_now_ns()
        base = (ContinuousClock.now, now)
        deadline = now &+ UInt64(clamping: Scheduler.nanoseconds(delay))
    }

    /// Wait for the next tick and return when it was scheduled for.
    @discardableResult
    public mutating func tick() async throws -> ContinuousClock.Instant {
        let scheduled = deadline
        let now = cv_now_ns()
        if scheduled > now {
            try await Runtime.sleep(untilNanos: scheduled, now: now)
        } else {
            try Task.checkCancellation()
        }
        let after = cv_now_ns()
        deadline = after > scheduled + Self.missedAfter ? next(after: scheduled, now: after) : scheduled + periodNanos
        return base.instant + .nanoseconds(Int64(bitPattern: scheduled &- base.nanos))
    }

    /// Restart the schedule: the next tick is one period from now.
    public mutating func reset() {
        deadline = cv_now_ns() + periodNanos
    }

    private func next(after scheduled: UInt64, now: UInt64) -> UInt64 {
        switch missedTickBehavior {
        case .burst: scheduled + periodNanos
        case .delay: now + periodNanos
        case .skip: now + periodNanos - (now - scheduled) % periodNanos
        }
    }
}
