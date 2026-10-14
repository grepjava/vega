import CVega
import Synchronization

/// How to interrupt one armed I/O wait from another thread: what a
/// cancellation or an I/O deadline does to it. Every action is idempotent
/// and harmless once the wait has ended, so both may run it, and the waiter
/// itself when it finds it must not wait.
enum IOInterrupt {
    #if os(Linux)
    /// A ring operation: cancel it (`cv_uring_cancel`); it completes with
    /// -ECANCELED unless it completed first.
    case uring(OpaquePointer, UInt64)
    #endif
    /// A readiness wait: take the waiter out of the direction's slot and
    /// resume it with false, unless the driver took it first.
    case readiness(UnsafeMutablePointer<cv_io>, Int32)
    /// Anything else: the object's `interrupt()`. The waiter keeps it alive
    /// while armed.
    case object(Unmanaged<IOInterruptTarget>)

    @inline(__always) func fire() {
        switch self {
        #if os(Linux)
        case let .uring(op, gen):
            cv_uring_cancel(op, gen)
        #endif
        case let .readiness(io, direction):
            let waiter = cv_io_take_waiter(io, direction)
            if waiter != 0 { IOWaiter.continuation(waiter).resume(returning: false) }
        case let .object(target):
            target._withUnsafeGuaranteedRef { $0.interrupt() }
        }
    }
}

/// A wait that an `IOInterrupt.object` interrupts.
class IOInterruptTarget: @unchecked Sendable {
    func interrupt() {}
}

/// Where an I/O wait parks its `IOInterrupt` for someone on another thread to
/// fire: a task's cancellation hook, or a `Runtime.withIODeadline` deadline.
///
/// The waiting task arms one wait at a time; `fire` runs the armed action,
/// or, with nothing armed, leaves the slot fired so the next `arm` refuses.
/// Fired is final. `state` keeps the two sides apart without a lock: the
/// action is copied in before `arm` publishes it, and `disarm` waits out a
/// firing that already took it. The action lives in atomics, so neither side
/// goes through exclusivity checks or reference counting.
@usableFromInline
class IOInterruptSlot: @unchecked Sendable {
    private static let idle: UInt8 = 0, armed: UInt8 = 1, firing: UInt8 = 2, fired: UInt8 = 3
    private static let uring: UInt8 = 0, readiness: UInt8 = 1, object: UInt8 = 2

    private let state = Atomic<UInt8>(IOInterruptSlot.idle)
    private let kind = Atomic<UInt8>(0)
    private let a = Atomic<UInt>(0)
    private let b = Atomic<UInt64>(0)

    /// The task this slot serves. Task-locals are inherited by child tasks,
    /// but a slot is its task's alone.
    let owner: UnsafeMutableRawPointer?

    init(owner: UnsafeMutableRawPointer?) { self.owner = owner }

    /// Fired: the task was cancelled, or the deadline passed. Sequentially
    /// consistent: a wait that armed its slot and then sees false is one
    /// `fire` will find.
    final var hasFired: Bool { state.load(ordering: .sequentiallyConsistent) >= Self.firing }

    /// Hand `action` to whoever fires the slot, until `disarm`. False if the
    /// slot has fired already: nothing is armed, and the caller runs the
    /// action itself.
    @inline(__always)
    final func arm(_ action: IOInterrupt) -> Bool {
        switch action {
        #if os(Linux)
        case let .uring(op, gen):
            kind.store(Self.uring, ordering: .relaxed)
            a.store(UInt(bitPattern: op), ordering: .relaxed)
            b.store(gen, ordering: .relaxed)
        #endif
        case let .readiness(io, direction):
            kind.store(Self.readiness, ordering: .relaxed)
            a.store(UInt(bitPattern: io), ordering: .relaxed)
            b.store(UInt64(UInt32(bitPattern: direction)), ordering: .relaxed)
        case let .object(target):
            kind.store(Self.object, ordering: .relaxed)
            a.store(UInt(bitPattern: target.toOpaque()), ordering: .relaxed)
        }
        return state.compareExchange(expected: Self.idle, desired: Self.armed,
                                     ordering: .sequentiallyConsistent).exchanged
    }

    /// The wait is over: take the action back, waiting out a firing that
    /// took it first. Nothing to do if nothing is armed.
    @inline(__always)
    final func disarm() {
        if state.compareExchange(expected: Self.armed, desired: Self.idle, ordering: .acquiringAndReleasing).exchanged {
            return
        }
        while state.load(ordering: .acquiring) == Self.firing {}
    }

    /// Interrupt the armed wait, if any, and stay fired.
    final func fire() {
        while true {
            let s = state.load(ordering: .acquiring)
            if s == Self.idle {
                if state.compareExchange(expected: Self.idle, desired: Self.fired,
                                         ordering: .sequentiallyConsistent).exchanged { return }
            } else if s == Self.armed {
                if state.compareExchange(expected: Self.armed, desired: Self.firing,
                                         ordering: .sequentiallyConsistent).exchanged {
                    action.fire()
                    state.store(Self.fired, ordering: .releasing)
                    return
                }
            } else {
                return
            }
        }
    }

    /// The armed action, read back by `fire` after it took the slot.
    private var action: IOInterrupt {
        let a = a.load(ordering: .relaxed)
        switch kind.load(ordering: .relaxed) {
        #if os(Linux)
        case Self.uring:
            return .uring(OpaquePointer(bitPattern: a).unsafelyUnwrapped, b.load(ordering: .relaxed))
        #endif
        case Self.readiness:
            return .readiness(UnsafeMutablePointer(bitPattern: a).unsafelyUnwrapped,
                              Int32(bitPattern: UInt32(truncatingIfNeeded: b.load(ordering: .relaxed))))
        default:
            return .object(Unmanaged.fromOpaque(UnsafeRawPointer(bitPattern: a).unsafelyUnwrapped))
        }
    }
}

/// A Vega task's cancellation hook for its I/O: one cancellation handler for
/// the task's whole life, which each I/O wait arms with its `IOInterrupt`
/// instead of registering a handler of its own.
///
/// A handler per wait costs a status record added and removed under the
/// task's status-record lock, plus executor hops in and out of
/// `withTaskCancellationHandler`, each of which looks up the task's executor
/// preference under that same lock. Tasks Vega starts (`spawn`, `block`,
/// servers, `TaskPool`) carry a hook; any other task's waits fall back to a
/// handler per wait.
final class IOTaskHook: IOInterruptSlot, @unchecked Sendable {
    /// Bound by `run` to an unowned reference: reading it costs no retain.
    static let current = TaskLocal<Ref?>(wrappedValue: nil)

    struct Ref: @unchecked Sendable {
        let hook: Unmanaged<IOTaskHook>
    }

    /// The running task's own hook, if it has one.
    @inline(__always) static var active: IOTaskHook? {
        if let worker = Worker.current {
            return worker._withUnsafeGuaranteedRef { active(key: $0.ioHookKey) }
        }
        return active(key: UnsafeRawPointer(Unmanaged.passUnretained(current).toOpaque()))
    }

    /// `active`, given the task-local's key: read straight from the runtime
    /// (TaskLocal.get is generic, and copies the value through its type's
    /// witnesses).
    @inline(__always) static func active(key: UnsafeRawPointer) -> IOTaskHook? {
        guard let bound = cv_task_local_get(key),
              let ref = bound.assumingMemoryBound(to: Ref?.self).pointee else { return nil }
        let hook = ref.hook.takeUnretainedValue()
        return hook.owner == cv_task_current() ? hook : nil
    }

    /// The task's innermost `withIODeadline` deadline, unretained (its scope
    /// keeps it), so a wait finds it without a second task-local lookup.
    /// Only the task itself touches it; relaxed atomics just spare the
    /// exclusivity checks.
    private let deadlineBits = Atomic<UInt>(0)

    var deadline: IODeadline? {
        get {
            let bits = deadlineBits.load(ordering: .relaxed)
            guard bits != 0 else { return nil }
            return Unmanaged<IODeadline>.fromOpaque(UnsafeRawPointer(bitPattern: bits).unsafelyUnwrapped)
                .takeUnretainedValue()
        }
        set {
            deadlineBits.store(newValue.map { UInt(bitPattern: Unmanaged.passUnretained($0).toOpaque()) } ?? 0,
                               ordering: .relaxed)
        }
    }

    /// Run `body`, the whole of a task Vega starts, with a hook for its I/O.
    @inline(__always)
    static func run<T>(_ body: () async throws -> T) async rethrows -> T {
        let hook = IOTaskHook(owner: cv_task_current())
        // The task-local holds it unretained: keep it to the end.
        defer { withExtendedLifetime(hook) {} }
        return try await current.withValue(Ref(hook: .passUnretained(hook))) {
            try await withTaskCancellationHandler(operation: body, onCancel: { hook.fire() })
        }
    }
}

/// One I/O wait, interruptible by the task's cancellation and its
/// `Runtime.withIODeadline` deadline, whichever comes first. `wait` arms its
/// wait (a submitted ring operation, an armed readiness slot) and then calls
/// `arm` with the action that interrupts it; if `arm` returns false the task
/// is cancelled or past its deadline already, and `wait` runs the action
/// itself, as a cancellation handler would have run at once.
@inline(__always)
func withIOInterrupt<T>(_ wait: (_ arm: (IOInterrupt) -> Bool) async -> T) async -> T {
    if let hook = IOTaskHook.active {
        let deadline = hook.deadline
        let result = await wait { action in
            hook.arm(action) && (deadline?.arm(action) ?? true)
        }
        hook.disarm()
        deadline?.disarm()
        return result
    }
    // A task Vega didn't start: a cancellation handler for this wait alone.
    let deadline = IODeadline.bound
    let slot = IOInterruptSlot(owner: nil)
    return await withTaskCancellationHandler {
        let result = await wait { action in
            slot.arm(action) && (deadline?.arm(action) ?? true)
        }
        slot.disarm()
        deadline?.disarm()
        return result
    } onCancel: {
        slot.fire()
    }
}
