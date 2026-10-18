import CVega
import Synchronization

extension Runtime {
    /// Run `body` with a deadline on its I/O: a Vega socket or pipe operation
    /// in it still waiting at the deadline gives up and throws
    /// `IOError.timedOut`, and so does any that would start waiting after
    /// it.
    ///
    /// ```swift
    /// let reply = try await Runtime.withIOTimeout(for: .seconds(5)) {
    ///     try await stream.write(request)
    ///     return try await stream.read(into: &buffer)
    /// }
    /// ```
    ///
    /// Cheaper than `timeout`, which runs its operation as a child task:
    /// `body` runs in the calling task, on the caller's executor, and the
    /// deadline interrupts its I/O the way cancellation would, without
    /// cancelling the task. So only
    /// Vega's own I/O waits are bounded, and only the calling task's -- not
    /// a `Runtime.sleep`, a channel, or what a child task waits for. A wait
    /// given up this way is one operation abandoned, as with `.cancelled`:
    /// a read may have lost nothing, but a protocol stream half read or half
    /// written is usually best closed.
    @inlinable
    public static func withIOTimeout<T: ~Copyable, E: Error>(
        for duration: Duration,
        _ body: () async throws(E) -> T
    ) async throws(E) -> T {
        // Inlined, so the body's generic work is specialized at the call;
        // setting the deadline up and down is not generic.
        let scope = IODeadlineScope(after: duration)
        defer { scope.end() }
        return try await scope.run(body)
    }

    /// Run `body` with a deadline on its I/O at `deadline`. See
    /// `withIOTimeout(for:_:)`.
    @inlinable
    public static func withIOTimeout<T: ~Copyable, E: Error>(
        until deadline: ContinuousClock.Instant,
        _ body: () async throws(E) -> T
    ) async throws(E) -> T {
        let scope = IODeadlineScope(until: deadline)
        defer { scope.end() }
        return try await scope.run(body)
    }

    /// Run `body` with a deadline on its I/O after `duration`, which
    /// `trigger` can also bring forward to now from another task: a reader
    /// waiting on a socket that someone else has decided to stop waiting
    /// for. A trigger fired while no scope holds it fires the next one as
    /// it starts. See `withIOTimeout(for:_:)`.
    @inlinable
    public static func withIOTimeout<T: ~Copyable, E: Error>(
        for duration: Duration, trigger: IOTimeoutTrigger,
        _ body: () async throws(E) -> T
    ) async throws(E) -> T {
        let scope = IODeadlineScope(after: duration)
        trigger.attach(scope.state.takeUnretainedValue())
        defer {
            trigger.detach()
            scope.end()
        }
        return try await scope.run(body)
    }
}

/// Ends the I/O wait of a `withIOTimeout(for:trigger:_:)` scope early, from
/// any task: the wait throws `IOError.timedOut`, as if its deadline had
/// passed. One scope at a time holds a trigger.
public final class IOTimeoutTrigger: @unchecked Sendable {
    // Locked rather than Mutex: ThreadSanitizer sees its lock on Linux.
    private let lock = Locked<(scope: IODeadline?, pending: Bool)>((nil, false))

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
        // A fire that found the scope may run after it has ended: the
        // deadline must not serve the task's next scope.
        scope.lent = true
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

/// One `withIOTimeout` scope: its deadline, and the timer that fires it.
/// It owns one reference, the deadline's, and holds the rest unretained:
/// the runtime outlives its tasks, the task-local holds the hook, and an
/// outer scope its own deadline. A scope is set up and ended around every
/// read a connection waits in.
@usableFromInline
struct IODeadlineScope: Sendable {
    /// The deadline, with the retain the scope owns: `end` gives it up.
    @usableFromInline let state: Unmanaged<IODeadline>
    private let scheduler: Unmanaged<Scheduler>?
    private let handle: TimerHandle?
    /// Off a Vega worker, a sleeping task stands in for the timer.
    private let sleeper: Task<Void, any Error>?
    /// The task's I/O hook, if it has one: it carries the innermost
    /// deadline while the scope lasts, `previous` before and after.
    private let hook: Unmanaged<IOTaskHook>?
    private let previous: Unmanaged<IODeadline>?
    /// The deadline is on the task's hook: `run` needs no task-local.
    @usableFromInline let onHook: Bool

    @usableFromInline init(after duration: Duration) {
        let ns = UInt64(clamping: Scheduler.nanoseconds(duration))
        let (scheduler, shard) = IODeadlineScope.runtime
        let now = scheduler?._withUnsafeGuaranteedRef { $0.clock.now } ?? cv_now_ns()
        self.init(untilNanos: ns > UInt64.max - now ? UInt64.max - 1 : now + ns, now: now,
                  scheduler: scheduler, shard: shard)
    }

    @usableFromInline init(until deadline: ContinuousClock.Instant) {
        let (scheduler, shard) = IODeadlineScope.runtime
        guard let scheduler else {
            self.init(after: ContinuousClock.now.duration(to: deadline))
            return
        }
        let (at, now) = scheduler._withUnsafeGuaranteedRef { s in
            let now = s.clock.now
            return (max(s.clock.nanos(deadline), now), now)
        }
        self.init(untilNanos: at, now: now, scheduler: scheduler, shard: shard)
    }

    /// The runtime of the worker running the caller, and its timer shard;
    /// (nil, 0) off a worker.
    @inline(__always) private static var runtime: (Unmanaged<Scheduler>?, Int) {
        guard let worker = Worker.current else { return (nil, 0) }
        return worker._withUnsafeGuaranteedRef { w in
            guard let owner = w.owner else { return (nil, 0) }
            return (Unmanaged<Scheduler>.fromOpaque(owner), w.index)
        }
    }

    init(untilNanos deadline: UInt64, now: UInt64, scheduler: Unmanaged<Scheduler>?, shard: Int) {
        let hook = IOTaskHook.activeUnmanaged
        self.hook = hook
        // The deadline the task's last scope gave back, if any: one object
        // a task, rather than one allocated and freed for every read.
        let state = hook?._withUnsafeGuaranteedRef { $0.takeSpareDeadline() }
            ?? .passRetained(IODeadline(owner: cv_task_current()))
        self.state = state
        previous = hook?._withUnsafeGuaranteedRef { h in
            defer { h.deadlineUnmanaged = state }
            return h.deadlineUnmanaged
        }
        onHook = hook != nil
        if let scheduler {
            // The wheel holds a retain, consumed by whoever unlinks the
            // entry: the firing worker or `end`. nil: already due, so fired.
            self.scheduler = scheduler
            handle = scheduler._withUnsafeGuaranteedRef {
                $0.addTimer(.deadline(state.retain()), deadline: deadline, now: now, shard: shard)
            }
            sleeper = nil
        } else {
            self.scheduler = nil
            handle = nil
            let fired = state.takeUnretainedValue()
            sleeper = Task {
                try await Task.sleep(for: .nanoseconds(Int64(clamping: deadline > now ? deadline - now : 0)))
                fired.fire()
            }
        }
    }

    /// Stop the timer, if it hasn't fired, and give up the deadline.
    @usableFromInline func end() {
        hook?._withUnsafeGuaranteedRef { $0.deadlineUnmanaged = previous }
        if let scheduler, let handle, scheduler._withUnsafeGuaranteedRef({ $0.timers.remove(handle) }) {
            state.release() // the wheel's
            // Never fired, and nothing else can fire it now: as good as new,
            // for the task's next scope, which takes the scope's retain.
            if let hook, state._withUnsafeGuaranteedRef({ !$0.lent && !$0.hasFired }) {
                hook._withUnsafeGuaranteedRef { $0.giveSpareDeadline(state) }
                return
            }
        }
        sleeper?.cancel()
        state.release()
    }

    /// `body`, with the deadline set for its task.
    @inlinable
    func run<T: ~Copyable, E: Error>(_ body: () async throws(E) -> T) async throws(E) -> T {
        // A task with a hook finds the deadline there; binding the
        // task-local as well would cost a push, a pop and the hops of
        // withValue for nothing (child tasks, which inherit task-locals,
        // never see their parent's deadline).
        if onHook { return try await body() }
        // TaskLocal.withValue neither takes typed throws nor ~Copyable
        // results.
        var result: Result<T, E>? = nil
        await IODeadline.current.withValue(state.takeUnretainedValue(), operation: { () async -> Void in
            do throws(E) {
                result = .success(try await body())
            } catch {
                result = .failure(error)
            }
        })
        switch result.take()! {
        case .success(let value): return value
        case .failure(let error): throw error
        }
    }
}

/// The deadline of a `Runtime.withIOTimeout` scope, and the I/O wait of
/// its task's that it interrupts when it fires: the task arms one wait at a
/// time with that wait's `IOInterrupt`, and the timer, on another thread,
/// fires it (see `IOInterruptSlot`).
@usableFromInline
final class IODeadline: IOInterruptSlot, @unchecked Sendable {
    /// Spelled out rather than `@TaskLocal`, so inlinable code can bind it.
    @usableFromInline static let current = TaskLocal<IODeadline?>(wrappedValue: nil)

    /// An `IOTimeoutTrigger` holds it too: it is never reused. Only the
    /// task touches it; the atomic spares the exclusivity checks.
    private let lentFlag = Atomic<Bool>(false)

    @usableFromInline var lent: Bool {
        get { lentFlag.load(ordering: .relaxed) }
        set { lentFlag.store(newValue, ordering: .relaxed) }
    }

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
