import Vega

/// Paused time for a runtime, for tests: Tokio's `time::pause`, `advance`
/// and auto-advance.
///
/// ```swift
/// let rt = Runtime(workers: 2)
/// let clock = MockClock(pausing: rt)
/// try rt.block {
///     try await Runtime.sleep(for: .seconds(3600))   // returns at once
/// }
/// ```
///
/// While paused, the runtime's timers (`Runtime.sleep`, `Runtime.timeout`,
/// `Interval`, and `Task.sleep` when the runtime is the global executor)
/// measure against this clock instead of real time:
///
/// - `advance(by:)` moves it forward and fires every timer that came due.
/// - With `autoAdvance` (the default), whenever every worker is idle, with
///   no ready I/O and no `Runtime.blocking` job outstanding, the clock jumps
///   straight to the next timer. A test of hour-long timeouts then runs in
///   milliseconds, in the same order the timers would fire in real time.
///
/// Real time still passes for everything else: I/O, and work on other
/// threads. `Runtime.now` reports the paused time on the runtime's workers.
public struct MockClock: Clock, Sendable {
    public typealias Instant = ContinuousClock.Instant
    public typealias Duration = Swift.Duration

    public let runtime: Runtime

    /// Pause `runtime`'s clock at the current time.
    public init(pausing runtime: Runtime, autoAdvance: Bool = true) {
        self.runtime = runtime
        runtime.pauseClock(autoAdvance: autoAdvance)
    }

    /// The paused time (or the runtime's time again after `resume()`).
    public var now: Instant { runtime.clockNow }

    public var isPaused: Bool { runtime.isClockPaused }

    /// The timers' tick.
    public var minimumResolution: Duration { .milliseconds(1) }

    /// Sleep on the runtime's timers. Call it from one of the runtime's tasks.
    public func sleep(until deadline: Instant, tolerance: Duration? = nil) async throws {
        try await Runtime.sleep(until: deadline)
    }

    /// Move time forward by `duration`, fire the timers that came due, and
    /// yield so the tasks they woke get to run.
    public func advance(by duration: Duration) async {
        runtime.advanceClock(by: duration)
        await Runtime.yield()
    }

    /// Move time forward to `deadline`; see `advance(by:)`.
    public func advance(to deadline: Instant) async {
        runtime.advanceClock(to: deadline)
        await Runtime.yield()
    }

    /// Pause again (after `resume()`), with or without auto-advance.
    public func pause(autoAdvance: Bool = true) {
        runtime.pauseClock(autoAdvance: autoAdvance)
    }

    /// Let time run again at real speed, from the paused time.
    public func resume() {
        runtime.resumeClock()
    }
}
