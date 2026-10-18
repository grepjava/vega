import Synchronization

/// Wake one task, or all waiting tasks, without passing data: Tokio's `Notify`.
///
/// ```swift
/// let ready = Notify()
/// rt.spawn { try await ready.notified(); print("go") }
/// ready.notifyOne()
/// ```
///
/// `notifyOne()` with nobody waiting stores a single permit, which the next
/// `notified()` consumes without suspending. Waiters are woken in FIFO order.
/// A waiter whose task is cancelled throws `CancellationError`.
///
/// As in Tokio, one atomic word says whether a permit is stored or tasks are
/// waiting: storing and consuming a permit are single CASes, and the lock is
/// only taken to queue or wake a waiter.
public final class Notify: @unchecked Sendable {
    /// `word` values. Only lock holders move into or out of `waiting`.
    private static let empty = 0, notified = 1, waiting = 2

    private struct Waiter {
        let id: UInt
        /// Resumed with true when notified, false when cancelled.
        let continuation: UnsafeContinuation<Bool, Never>
    }

    private struct State {
        var waiters = RawRing<Waiter>(capacity: 4)
    }

    private let word = Atomic<Int>(Notify.empty)
    private let lock = RawLock()
    private let state = Guarded(State())

    public init() {}

    deinit {
        state.pointer.pointee.waiters.destroy()
        state.destroy()
        lock.destroy()
    }

    /// Take a stored permit, if there is one.
    @inline(__always) private func takePermit() -> Bool {
        word.compareExchange(expected: Notify.notified, desired: Notify.empty,
                             successOrdering: .acquiring, failureOrdering: .relaxed).exchanged
    }

    /// Under the lock: consume a permit (true), or mark the word `waiting` so
    /// that a notifier takes the lock and finds the waiter about to be queued.
    @inline(__always) private func permitOrMarkWaiting() -> Bool {
        while true {
            switch word.load(ordering: .relaxed) {
            case Notify.notified:
                if takePermit() { return true }
            case Notify.empty:
                if word.compareExchange(expected: Notify.empty, desired: Notify.waiting,
                                        ordering: .relaxed).exchanged { return false }
            default:
                return false
            }
        }
    }

    /// Under the lock, after removing waiters: nobody left means not `waiting`.
    @inline(__always) private func clearWaitingIfEmpty(_ s: UnsafeMutablePointer<State>) {
        if s.pointee.waiters.isEmpty { word.store(Notify.empty, ordering: .relaxed) }
    }

    /// Wait for a notification, or consume the stored permit. Throws
    /// `CancellationError` if the task is cancelled first; a notification
    /// that came first is never lost to it.
    public func notified() async throws(CancellationError) {
        let s = state.pointer
        if takePermit() {
            await Runtime.consumeBudget()
            return
        }

        let id = currentTaskID()
        let notified = await withTaskCancellationHandler {
            await withUnsafeContinuation { (c: UnsafeContinuation<Bool, Never>) in
                let resumeNow = lock.withLock { () -> Bool? in
                    // Checked under the lock: either the cancel handler runs
                    // after this and finds us, or the flag is already visible.
                    if Task.isCancelled { return false }
                    if permitOrMarkWaiting() { return true }
                    s.pointee.waiters.pushBack(Waiter(id: id, continuation: c))
                    return nil
                }
                if let resumeNow { c.resume(returning: resumeNow) }
            }
        } onCancel: {
            let waiter = lock.withLock { () -> Waiter? in
                let s = state.pointer
                let w = s.pointee.waiters.remove { $0.id == id }
                if w != nil { clearWaitingIfEmpty(s) }
                return w
            }
            waiter?.continuation.resume(returning: false)
        }
        if !notified { throw CancellationError() }
    }

    /// As `notified()`, but a cancelled task keeps waiting until notified.
    ///
    /// Cancellation support costs a status record in the Swift runtime on
    /// every wait (installed and removed under a per-task lock); hand-off
    /// loops between tasks that are never cancelled mid-wait can skip it.
    public func notifiedIgnoringCancellation() async {
        let s = state.pointer
        if takePermit() {
            await Runtime.consumeBudget()
            return
        }
        _ = await withUnsafeContinuation { (c: UnsafeContinuation<Bool, Never>) in
            let resumeNow = lock.withLock { () -> Bool in
                if permitOrMarkWaiting() { return true }
                s.pointee.waiters.pushBack(Waiter(id: 0, continuation: c))
                return false
            }
            if resumeNow { c.resume(returning: true) }
        }
    }

    /// Wake the longest-waiting task, or store a permit if none is waiting.
    public func notifyOne() {
        // Nobody waiting: store the permit (or find it stored) without the lock.
        var current = word.load(ordering: .relaxed)
        while current != Notify.waiting {
            let (done, now) = word.compareExchange(expected: current, desired: Notify.notified,
                                                   successOrdering: .releasing, failureOrdering: .relaxed)
            if done { return }
            current = now
        }
        let s = state.pointer
        let waiter = lock.withLock { () -> Waiter? in
            // Waiters can have gone (cancelled) since the load: re-decide.
            if let w = s.pointee.waiters.popFront() {
                clearWaitingIfEmpty(s)
                return w
            }
            word.store(Notify.notified, ordering: .releasing)
            return nil
        }
        waiter?.continuation.resume(returning: true)
    }

    /// Wake every task waiting now. Stores no permit.
    public func notifyWaiters() {
        let s = state.pointer
        guard word.load(ordering: .acquiring) == Notify.waiting else { return }
        var woken = lock.withLock { () -> RawRing<Waiter> in
            let all = s.pointee.waiters
            s.pointee.waiters = RawRing(capacity: 4)
            if word.load(ordering: .relaxed) == Notify.waiting { word.store(Notify.empty, ordering: .relaxed) }
            return all
        }
        while let w = woken.popFront() { w.continuation.resume(returning: true) }
        woken.destroy()
    }
}
