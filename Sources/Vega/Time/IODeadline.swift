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
}

/// One `withIODeadline` scope: its deadline, and the timer that fires it.
@usableFromInline
struct IODeadlineScope: Sendable {
    @usableFromInline let state: IODeadline
    private let scheduler: Scheduler?
    private let handle: TimerHandle?
    /// Off a Vega worker, a sleeping task stands in for the timer.
    private let sleeper: Task<Void, any Error>?

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
        if let scheduler, let handle, scheduler.timers.remove(handle) {
            Unmanaged.passUnretained(state).release()
        }
        sleeper?.cancel()
    }

    /// `body`, with the deadline set for its task.
    @inlinable
    func run<T: ~Copyable, E: Error>(isolation: isolated (any Actor)?,
                                     _ body: () async throws(E) -> T) async throws(E) -> T {
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
/// its task's that it interrupts when it fires.
///
/// The task arms one wait at a time with that wait's cancel action; the
/// timer, on another thread, runs it. `state` keeps the two apart without a
/// lock: the action lives in the waiting frame, so `disarm` waits out a
/// firing that already took it.
@usableFromInline
final class IODeadline: @unchecked Sendable {
    /// Spelled out rather than `@TaskLocal`, so inlinable code can bind it.
    @usableFromInline static let current = TaskLocal<IODeadline?>(wrappedValue: nil)

    private static let idle: UInt8 = 0, armed: UInt8 = 1, firing: UInt8 = 2, fired: UInt8 = 3

    /// The task that made the scope. Task-locals are inherited, but the
    /// deadline is that task's alone.
    private let owner: UnsafeMutableRawPointer?
    private let state = Atomic<UInt8>(IODeadline.idle)
    private nonisolated(unsafe) var action: (@Sendable () -> Void)?

    init(owner: UnsafeMutableRawPointer?) { self.owner = owner }

    /// The running task's deadline, if it set one.
    @inline(__always) static var active: IODeadline? {
        guard let d = current.get(), d.owner == cv_task_current() else { return nil }
        return d
    }

    /// Past the deadline. Sequentially consistent: a wait that armed its
    /// slot and then sees false is one `fire` will find.
    var hasFired: Bool { state.load(ordering: .sequentiallyConsistent) >= Self.firing }

    /// Hand `action` to the timer until `disarm`. False if the deadline has
    /// already passed: nothing is armed.
    fileprivate func arm(_ action: @escaping @Sendable () -> Void) -> Bool {
        self.action = action
        if state.compareExchange(expected: Self.idle, desired: Self.armed, ordering: .sequentiallyConsistent).exchanged {
            return true
        }
        self.action = nil
        return false
    }

    fileprivate func disarm() {
        if !state.compareExchange(expected: Self.armed, desired: Self.idle, ordering: .acquiringAndReleasing).exchanged {
            // Fired: wait until the action has run, then drop it.
            while state.load(ordering: .acquiring) != Self.fired {}
        }
        action = nil
    }

    /// The deadline: interrupt the armed wait, if any.
    func fire() {
        while true {
            let s = state.load(ordering: .acquiring)
            if s == Self.idle {
                if state.compareExchange(expected: Self.idle, desired: Self.fired,
                                         ordering: .sequentiallyConsistent).exchanged { return }
            } else if s == Self.armed {
                if state.compareExchange(expected: Self.armed, desired: Self.firing,
                                         ordering: .sequentiallyConsistent).exchanged {
                    action?()
                    state.store(Self.fired, ordering: .releasing)
                    return
                }
            } else {
                return
            }
        }
    }
}

/// `withTaskCancellationHandler` for one I/O wait: `onCancel` runs when
/// the task is cancelled or its `Runtime.withIODeadline` deadline passes,
/// whichever comes first. `operation` is given the deadline, to check after
/// it has armed its wait as it checks `Task.isCancelled`.
@inline(__always)
func withIOCancellation<T>(_ operation: (IODeadline?) async -> T,
                           onCancel: @Sendable () -> Void) async -> T {
    guard let deadline = IODeadline.active else {
        return await withTaskCancellationHandler { await operation(nil) } onCancel: { onCancel() }
    }
    return await withoutActuallyEscaping(onCancel) { (onCancel) async -> T in
        // Past the deadline already: interrupt the wait as soon as it is
        // armed, as a cancel handler does for a task cancelled first.
        guard deadline.arm(onCancel) else {
            onCancel()
            return await withTaskCancellationHandler { await operation(deadline) } onCancel: { onCancel() }
        }
        defer { deadline.disarm() }
        return await withTaskCancellationHandler { await operation(deadline) } onCancel: { onCancel() }
    }
}

extension IOError {
    /// Why a wait gave up: the task was cancelled, or its I/O deadline
    /// passed.
    static var interrupted: IOError {
        !Task.isCancelled && IODeadline.active?.hasFired == true ? .timedOut : .cancelled
    }
}
