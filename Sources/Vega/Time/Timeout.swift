import CVega

/// A `Runtime.timeout` operation didn't finish in time.
public struct TimeoutError: Error, Sendable, Equatable, CustomStringConvertible {
    public init() {}
    public var description: String { "operation timed out" }
}

extension Runtime {
    /// Run `operation`, cancelling it if it hasn't finished after `duration`
    /// (Tokio's `time::timeout`):
    ///
    /// ```swift
    /// let n = try await Runtime.timeout(.seconds(30)) {
    ///     try await stream.read(into: &buffer)   // an idle timeout
    /// }
    /// ```
    ///
    /// The operation runs as a child task, and a Vega timer cancels that
    /// child, never the caller. If it then fails, `timeout` throws
    /// `TimeoutError`; if it finishes anyway (it raced the deadline, or
    /// ignores cancellation), its result is returned: a completed operation's
    /// result is never thrown away. Vega's I/O and sleeps end at once when
    /// cancelled. Cancelling the caller cancels the operation as usual.
    ///
    /// Finishing in time unlinks the timer in O(1). Off a Vega worker it
    /// falls back to racing a `Task.sleep`.
    public static func timeout<T: Sendable>(
        _ duration: Duration, _ operation: sending @escaping () async throws -> T
    ) async throws -> T {
        let now = nowNanos
        let ns = UInt64(clamping: Scheduler.nanoseconds(duration))
        return try await timeout(untilNanos: ns > UInt64.max - now ? UInt64.max - 1 : now + ns, now: now, operation)
    }

    /// Run `operation`, cancelling it if it hasn't finished by `deadline`.
    /// See `timeout(_:_:)`.
    public static func timeout<T: Sendable>(
        until deadline: ContinuousClock.Instant, _ operation: sending @escaping () async throws -> T
    ) async throws -> T {
        guard let s = Worker.currentScheduler else {
            return try await timeout(ContinuousClock.now.duration(to: deadline), operation)
        }
        let now = s.clock.now
        return try await timeout(untilNanos: max(s.clock.nanos(deadline), now), now: now, operation)
    }

    static func timeout<T: Sendable>(
        untilNanos deadline: UInt64, now: UInt64, _ operation: sending @escaping () async throws -> T
    ) async throws -> T {
        guard let worker = Worker.current,
              let scheduler = worker._withUnsafeGuaranteedRef({ $0.scheduler }) else {
            return try await raceSleep(nanos: deadline > now ? deadline - now : 0, operation)
        }
        // Moved into exactly one child, which is what `sending` allows; the
        // group's body closure just can't see that.
        nonisolated(unsafe) let operation = operation
        return try await withThrowingTaskGroup(of: T.self) { group in
            group.addTask(on: scheduler) {
                // The timer holds a retain on this child task, consumed by
                // whoever unlinks it: the firing worker (which cancels us)
                // or us, below.
                let task = UnsafeRawPointer(cv_task_current().unsafelyUnwrapped)
                cv_task_retain(task)
                let handle = scheduler.addTimer(.cancel(task), deadline: deadline, now: scheduler.clock.now,
                                                shard: scheduler.currentShard)
                // nil: already due, so the child is cancelled.
                func expired() -> Bool { handle.map { !scheduler.removeTimeout($0, task: task) } ?? true }
                let value: T
                do {
                    value = try await operation()
                } catch {
                    if expired() { throw TimeoutError() }
                    throw error
                }
                _ = expired()
                return value
            }
            return try await group.next()!
        }
    }

    /// `timeout` off a Vega worker: the operation against a `Task.sleep`.
    private static func raceSleep<T: Sendable>(
        nanos: UInt64, _ operation: sending @escaping () async throws -> T
    ) async throws -> T {
        nonisolated(unsafe) let operation = operation
        return try await withThrowingTaskGroup(of: RaceOutcome<T>.self) { group in
            group.addTask { .done(try await operation()) }
            group.addTask {
                try await Task.sleep(for: .nanoseconds(Int64(clamping: nanos)))
                return .elapsed
            }
            defer { group.cancelAll() }
            switch try await group.next()! {
            case .done(let v): return v
            case .elapsed: throw TimeoutError()
            }
        }
    }
}

private enum RaceOutcome<T: Sendable>: Sendable {
    case done(T)
    case elapsed
}
