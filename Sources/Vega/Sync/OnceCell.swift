/// A value set once, possibly by an async initializer that only one task
/// runs: Tokio's `OnceCell`.
///
/// ```swift
/// let pool = OnceCell<ConnectionPool>()
/// let p = try await pool.getOrInit { try await ConnectionPool.open() }
/// ```
///
/// While one task initializes, others asking for the value wait for it. If
/// the initializer throws, the cell stays empty and the next waiter tries.
/// Waiting isn't cut short by cancellation (the initializer's own awaits
/// are, as usual).
public final class OnceCell<Value: Sendable>: @unchecked Sendable {
    private enum Slot {
        case empty, initializing, ready(Value)
    }

    /// What `getOrInit` does next.
    private enum Next {
        case have(Value), run, wait
    }

    // Wake codes.
    private static var settled: UInt8 { 0 }

    private let lock = RawLock()
    private let slot = Guarded(Slot.empty)
    private let waiters = Guarded(WaitList())

    public init() {}

    public init(_ value: Value) {
        slot.pointer.pointee = .ready(value)
    }

    deinit {
        waiters.pointer.pointee.destroy()
        waiters.destroy()
        slot.destroy()
        lock.destroy()
    }

    /// The value, if it is set.
    public var value: Value? {
        lock.withLock {
            if case .ready(let v) = slot.pointer.pointee { return v }
            return nil
        }
    }

    /// Set the value if nobody has (or is about to). False if it was taken.
    @discardableResult
    public func set(_ value: Value) -> Bool {
        let s = slot.pointer
        let woken = lock.withLock { () -> [WaitList.Waiter]? in
            guard case .empty = s.pointee else { return nil }
            s.pointee = .ready(value)
            return waiters.pointer.pointee.takeAll()
        }
        guard let woken else { return false }
        for w in woken { w.continuation.resume(returning: OnceCell.settled) }
        return true
    }

    /// The value, running `make` to set it if nobody has. Only one task runs
    /// `make` at a time; the rest wait for its outcome.
    public func getOrInit<E: Error>(_ make: () async throws(E) -> Value) async throws(E) -> Value {
        let s = slot.pointer
        while true {
            let next = lock.withLock { () -> Next in
                switch s.pointee {
                case .ready(let v): return .have(v)
                case .initializing: return .wait
                case .empty:
                    s.pointee = .initializing
                    return .run
                }
            }
            switch next {
            case .have(let v):
                return v
            case .wait:
                _ = await park(WaitListRef(lock: lock, list: waiters.pointer)) { () -> UInt8? in
                    if case .initializing = s.pointee { return nil }
                    return OnceCell.settled
                }
            case .run:
                let result: Result<Value, E>
                do throws(E) {
                    result = .success(try await make())
                } catch {
                    result = .failure(error)
                }
                let woken = lock.withLock { () -> [WaitList.Waiter] in
                    if case .success(let v) = result { s.pointee = .ready(v) } else { s.pointee = .empty }
                    return waiters.pointer.pointee.takeAll()
                }
                for w in woken { w.continuation.resume(returning: OnceCell.settled) }
                return try result.get()
            }
        }
    }
}
