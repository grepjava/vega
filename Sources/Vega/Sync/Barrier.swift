/// Lets `count` tasks wait until all of them have arrived: Tokio's `Barrier`.
/// Reusable: once a group is released, the next `count` arrivals form the
/// next one.
///
/// ```swift
/// let ready = Barrier(count: 4)
/// for _ in 0..<4 {
///     rt.spawn {
///         await setUp()
///         if await ready.wait() { print("all four are set up") }
///     }
/// }
/// ```
///
/// Cancelling a waiting task doesn't take it out of its group: an arrival
/// can't be undone without breaking the count for the others (Tokio's
/// `wait` isn't cancel-safe either).
public final class Barrier: @unchecked Sendable {
    public let count: Int

    private struct State {
        var arrived = 0
    }

    private let lock = RawLock()
    private let state = Guarded(State())
    private let waiters = Guarded(WaitList())

    public init(count: Int) {
        precondition(count > 0, "a Barrier needs a count of at least 1")
        self.count = count
    }

    deinit {
        waiters.pointer.pointee.destroy()
        waiters.destroy()
        state.destroy()
        lock.destroy()
    }

    /// Wait for the rest of the group. Returns true in exactly one task of
    /// each group, the last to arrive (the "leader").
    @discardableResult
    public func wait() async -> Bool {
        let s = state.pointer, list = waiters.pointer
        var released: [WaitList.Waiter] = []
        let code = await park(WaitListRef(lock: lock, list: list)) { () -> UInt8? in
            s.pointee.arrived += 1
            guard s.pointee.arrived == count else { return nil }
            s.pointee.arrived = 0
            released = list.pointee.takeAll()
            return 1
        }
        for w in released { w.continuation.resume(returning: 0) }
        if code == 0 { return false }
        await Runtime.consumeBudget()
        return true
    }
}
