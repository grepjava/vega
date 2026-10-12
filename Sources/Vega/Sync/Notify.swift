/// Wake one task, or all waiting tasks, without passing data: Tokio's `Notify`.
///
/// ```swift
/// let ready = Notify()
/// rt.spawn { await ready.notified(); print("go") }
/// ready.notifyOne()
/// ```
///
/// `notifyOne()` with nobody waiting stores a single permit, which the next
/// `notified()` consumes without suspending. Waiters are woken in FIFO order.
/// A waiter whose task is cancelled returns early.
public final class Notify: @unchecked Sendable {
    private struct Waiter {
        let id: UInt
        let continuation: UnsafeContinuation<Void, Never>
    }

    private struct State {
        var permit = false
        var waiters = RawRing<Waiter>(capacity: 4)
    }

    private let lock = RawLock()
    private let state = Guarded(State())

    public init() {}

    deinit {
        state.pointer.pointee.waiters.destroy()
        state.destroy()
        lock.destroy()
    }

    /// Wait for a notification, or consume the stored permit.
    public func notified() async {
        let s = state.pointer
        // Fast path: a permit is waiting.
        let took = lock.withLock { () -> Bool in
            guard s.pointee.permit else { return false }
            s.pointee.permit = false
            return true
        }
        if took {
            await Runtime.consumeBudget()
            return
        }

        // A task waits on one thing at a time: its address names the waiter.
        let id = withUnsafeCurrentTask { t in t.map { UInt(bitPattern: unsafeBitCast($0, to: Int.self)) } ?? 0 }
        await withTaskCancellationHandler {
            await withUnsafeContinuation { (c: UnsafeContinuation<Void, Never>) in
                let resumeNow = lock.withLock { () -> Bool in
                    if s.pointee.permit {
                        s.pointee.permit = false
                        return true
                    }
                    // Checked under the lock: either the cancel handler runs
                    // after this and finds us, or the flag is already visible.
                    if Task.isCancelled { return true }
                    s.pointee.waiters.pushBack(Waiter(id: id, continuation: c))
                    return false
                }
                if resumeNow { c.resume() }
            }
        } onCancel: {
            let waiter = lock.withLock { state.pointer.pointee.waiters.remove { $0.id == id } }
            waiter?.continuation.resume()
        }
    }

    /// As `notified()`, but a cancelled task keeps waiting until notified.
    ///
    /// Cancellation support costs a status record in the Swift runtime on
    /// every wait (installed and removed under a per-task lock); hand-off
    /// loops between tasks that are never cancelled mid-wait can skip it.
    public func notifiedIgnoringCancellation() async {
        let s = state.pointer
        await withUnsafeContinuation { (c: UnsafeContinuation<Void, Never>) in
            let resumeNow = lock.withLock { () -> Bool in
                if s.pointee.permit {
                    s.pointee.permit = false
                    return true
                }
                s.pointee.waiters.pushBack(Waiter(id: 0, continuation: c))
                return false
            }
            if resumeNow { c.resume() }
        }
    }

    /// Wake the longest-waiting task, or store a permit if none is waiting.
    public func notifyOne() {
        let s = state.pointer
        let waiter = lock.withLock { () -> Waiter? in
            if let w = s.pointee.waiters.popFront() { return w }
            s.pointee.permit = true
            return nil
        }
        waiter?.continuation.resume()
    }

    /// Wake every task waiting now. Stores no permit.
    public func notifyWaiters() {
        let s = state.pointer
        var woken = lock.withLock { () -> RawRing<Waiter> in
            let all = s.pointee.waiters
            s.pointee.waiters = RawRing(capacity: 4)
            return all
        }
        while let w = woken.popFront() { w.continuation.resume() }
        woken.destroy()
    }
}
