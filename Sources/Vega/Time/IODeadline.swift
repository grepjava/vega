import CVega
import Synchronization

extension Runtime {
    /// Run `body` with a deadline on its I/O: a Vega socket or pipe operation
    /// in it still waiting at the deadline gives up and throws
    /// `IOError.timedOut`, and so does any that would start waiting after
    /// it.
    ///
    /// ```swift
    /// let reply = try await Runtime.withIODeadline(.seconds(5)) {
    ///     try await stream.write(request)
    ///     return try await stream.read(into: &buffer)
    /// }
    /// ```
    ///
    /// Cheaper than `timeout`, which runs its operation as a child task:
    /// `body` runs in the calling task, and the deadline interrupts its I/O
    /// the way cancellation would, without cancelling the task. So only
    /// Vega's own I/O waits are bounded, and only the calling task's -- not
    /// a `Runtime.sleep`, a channel, or what a child task waits for. A wait
    /// given up this way is one operation abandoned, as with `.cancelled`:
    /// a read may have lost nothing, but a protocol stream half read or half
    /// written is usually best closed.
    @inlinable
    public static func withIODeadline<T: ~Copyable, E: Error>(
        _ duration: Duration, isolation: isolated (any Actor)? = #isolation,
        _ body: () async throws(E) -> T
    ) async throws(E) -> T {
        // Inlined, so the body's generic work is specialized at the call;
        // setting the deadline up and down is not generic.
        let scope = IODeadlineScope(after: duration)
        defer { scope.end() }
        return try await scope.run(isolation: isolation, body)
    }

    /// Run `body` with a deadline on its I/O at `deadline`. See
    /// `withIODeadline(_:_:)`.
    @inlinable
    public static func withIODeadline<T: ~Copyable, E: Error>(
        until deadline: ContinuousClock.Instant, isolation: isolated (any Actor)? = #isolation,
        _ body: () async throws(E) -> T
    ) async throws(E) -> T {
        let scope = IODeadlineScope(until: deadline)
        defer { scope.end() }
        return try await scope.run(isolation: isolation, body)
    }

    /// Run `body` with a deadline on its I/O after `duration`, which
    /// `trigger` can also bring forward to now from another task: a reader
    /// waiting on a socket that someone else has decided to stop waiting
    /// for. A trigger fired while no scope holds it fires the next one as
    /// it starts. See `withIODeadline(_:_:)`.
    @inlinable
    public static func withIODeadline<T: ~Copyable, E: Error>(
        _ duration: Duration, trigger: IODeadlineTrigger, isolation: isolated (any Actor)? = #isolation,
        _ body: () async throws(E) -> T
    ) async throws(E) -> T {
        let scope = IODeadlineScope(after: duration)
        trigger.attach(scope.state)
        defer {
            trigger.detach()
            scope.end()
        }
        return try await scope.run(isolation: isolation, body)
    }
}

/// Ends the I/O wait of a `withIODeadline(_:trigger:_:)` scope early, from
/// any task: the wait throws `IOError.timedOut`, as if its deadline had
/// passed. One scope at a time holds a trigger.
public final class IODeadlineTrigger: @unchecked Sendable {
    private let lock = Mutex<(scope: IODeadline?, pending: Bool)>((nil, false))

    public init() {}

    /// Fires the scope holding the trigger, or the next to take it.
    public func fire() {
        let scope = lock.withLock { s -> IODeadline? in
            if let scope = s.scope { return scope }
            s.pending = true
            return nil
        }
        scope?.fire()
    }

    @usableFromInline func attach(_ scope: IODeadline) {
        let now = lock.withLock { s -> Bool in
            s.scope = scope
            defer { s.pending = false }
            return s.pending
        }
        if now { scope.fire() }
    }

    @usableFromInline func detach() {
        lock.withLock { $0.scope = nil }
    }
}

/// One `withIODeadline` scope: its deadline, and the timer that fires it.
@usableFromInline
struct IODeadlineScope: Sendable {
    @usableFromInline let state: IODeadline
    private let scheduler: Scheduler?
    private let handle: TimerHandle?
    /// Off a Vega worker, a sleeping task stands in for the timer.
    private let sleeper: Task<Void, any Error>?
    /// The task's I/O hook, if it has one: it carries the innermost
    /// deadline while the scope lasts, `previous` before and after.
    private let hook: IOTaskHook?
    private let previous: IODeadline?
    /// The deadline is on the task's hook: `run` needs no task-local.
    @usableFromInline let onHook: Bool

    @usableFromInline init(after duration: Duration) {
        let now = Runtime.nowNanos
        let ns = UInt64(clamping: Scheduler.nanoseconds(duration))
        self.init(untilNanos: ns > UInt64.max - now ? UInt64.max - 1 : now + ns, now: now)
    }

    @usableFromInline init(until deadline: ContinuousClock.Instant) {
        guard let s = Worker.currentScheduler else {
            self.init(after: ContinuousClock.now.duration(to: deadline))
            return
        }
        let now = s.clock.now
        self.init(untilNanos: max(s.clock.nanos(deadline), now), now: now)
    }

    init(untilNanos deadline: UInt64, now: UInt64) {
        let state = IODeadline(owner: cv_task_current())
        self.state = state
        hook = IOTaskHook.active
        previous = hook?.deadline
        hook?.deadline = state
        onHook = hook != nil
        if let worker = Worker.current, let scheduler = worker._withUnsafeGuaranteedRef({ $0.scheduler }) {
            // The wheel holds a retain, consumed by whoever unlinks the
            // entry: the firing worker or `end`. nil: already due, so fired.
            self.scheduler = scheduler
            handle = scheduler.addTimer(.deadline(.passRetained(state)), deadline: deadline, now: now,
                                        shard: scheduler.currentShard)
            sleeper = nil
        } else {
            scheduler = nil
            handle = nil
            sleeper = Task {
                try await Task.sleep(for: .nanoseconds(Int64(clamping: deadline > now ? deadline - now : 0)))
                state.fire()
            }
        }
    }

    /// Stop the timer, if it hasn't fired.
    @usableFromInline func end() {
        hook?.deadline = previous
        if let scheduler, let handle, scheduler.timers.remove(handle) {
            Unmanaged.passUnretained(state).release()
        }
        sleeper?.cancel()
    }

    /// `body`, with the deadline set for its task.
    @inlinable
    func run<T: ~Copyable, E: Error>(isolation: isolated (any Actor)?,
                                     _ body: () async throws(E) -> T) async throws(E) -> T {
        // A task with a hook finds the deadline there; binding the
        // task-local as well would cost a push, a pop and the hops of
        // withValue for nothing (child tasks, which inherit task-locals,
        // never see their parent's deadline).
        if onHook { return try await body() }
        // TaskLocal.withValue neither takes typed throws nor ~Copyable
        // results.
        var result: Result<T, E>? = nil
        await IODeadline.current.withValue(state, operation: { () async -> Void in
            do throws(E) {
                result = .success(try await body())
            } catch {
                result = .failure(error)
            }
        }, isolation: isolation)
        switch result.take()! {
        case .success(let value): return value
        case .failure(let error): throw error
        }
    }
}

/// The deadline of a `Runtime.withIODeadline` scope, and the I/O wait of
/// its task's that it interrupts when it fires: the task arms one wait at a
/// time with that wait's `IOInterrupt`, and the timer, on another thread,
/// fires it (see `IOInterruptSlot`).
@usableFromInline
final class IODeadline: IOInterruptSlot, @unchecked Sendable {
    /// Spelled out rather than `@TaskLocal`, so inlinable code can bind it.
    @usableFromInline static let current = TaskLocal<IODeadline?>(wrappedValue: nil)

    /// The running task's deadline, if it set one.
    @inline(__always) static var active: IODeadline? {
        if let hook = IOTaskHook.active { return hook.deadline }
        return bound
    }

    /// The deadline bound to the running task, looked up as a task-local:
    /// for a task without an `IOTaskHook`.
    @inline(__always) static var bound: IODeadline? {
        guard let d = current.get(), d.owner == cv_task_current() else { return nil }
        return d
    }
}

extension IOError {
    /// Why a wait gave up: the task was cancelled, or its I/O deadline
    /// passed.
    static var interrupted: IOError {
        !Task.isCancelled && IODeadline.active?.hasFired == true ? .timedOut : .cancelled
    }
}
