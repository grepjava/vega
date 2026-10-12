import Synchronization

/// A counting semaphore with fair, FIFO hand-out: Tokio's `Semaphore`.
///
/// ```swift
/// let limit = Semaphore(permits: 16)
/// try await limit.acquire()
/// defer { limit.release() }
/// ```
///
/// A task asking for several permits queues behind earlier waiters and is
/// handed permits as they come back, so small requests can't starve it, and
/// later small requests can't jump ahead of it.
///
/// As in `Notify`, one atomic word holds the free permits, a "tasks are
/// waiting" bit and a "closed" bit. With nobody waiting, acquiring and
/// releasing are single CASes; the lock is only taken to queue or hand out.
/// While anybody waits, the word holds no free permits: a waiter takes all
/// that are free when it queues, and releases go to the queue first.
public final class Semaphore: @unchecked Sendable {
    private static let closedBit = 1, waitingBit = 2, shift = 2

    /// The most permits a semaphore can hold.
    public static let maxPermits = Int.max >> 3

    private struct Waiter {
        let id: UInt
        /// Permits it still needs.
        var remaining: Int
        let requested: Int
        /// Resumed with 0 (acquired), 1 (closed) or 2 (cancelled).
        let continuation: UnsafeContinuation<UInt8, Never>
    }

    private let word: Atomic<Int>
    private let lock = RawLock()
    private let waiters = Guarded(RawRing<Waiter>(capacity: 4))

    public init(permits: Int) {
        precondition(permits >= 0 && permits <= Semaphore.maxPermits, "permits out of range")
        word = Atomic(permits << Semaphore.shift)
    }

    deinit {
        waiters.pointer.pointee.destroy()
        waiters.destroy()
        lock.destroy()
    }

    /// Permits free right now.
    public var availablePermits: Int { word.load(ordering: .relaxed) >> Semaphore.shift }

    public var isClosed: Bool { word.load(ordering: .relaxed) & Semaphore.closedBit != 0 }

    /// Take `n` permits if they are free and nobody is queued for them.
    public func tryAcquire(_ n: Int = 1) -> Bool {
        precondition(n >= 0 && n <= Semaphore.maxPermits, "permits out of range")
        var w = word.load(ordering: .relaxed)
        while w & (Semaphore.closedBit | Semaphore.waitingBit) == 0 && w >> Semaphore.shift >= n {
            let (done, now) = word.compareExchange(expected: w, desired: w - n << Semaphore.shift,
                                                   successOrdering: .acquiring, failureOrdering: .relaxed)
            if done { return true }
            w = now
        }
        return false
    }

    /// Wait for `n` permits. Give them back with `release(n)`.
    public func acquire(_ n: Int = 1) async throws(AcquireError) {
        if tryAcquire(n) {
            await Runtime.consumeBudget()
            return
        }
        if isClosed { throw .closed }
        let id = currentTaskID()
        let code = await withTaskCancellationHandler {
            await withUnsafeContinuation { (c: UnsafeContinuation<UInt8, Never>) in
                let now = lock.withLock { () -> UInt8? in enqueue(id, n, c) }
                if let now { c.resume(returning: now) }
            }
        } onCancel: {
            let waiter = lock.withLock { () -> Waiter? in
                guard let w = waiters.pointer.pointee.remove(where: { $0.id == id }) else { return nil }
                // Hand on what it was given, or just clear the waiting bit.
                releaseLocked(w.requested - w.remaining)
                return w
            }
            waiter?.continuation.resume(returning: 2)
        }
        switch code {
        case 0: return
        case 1: throw .closed
        default: throw .cancelled
        }
    }

    /// Under the lock: take `n` permits now (0), report closed (1) or
    /// cancelled (2), or take what is free and queue for the rest (nil).
    private func enqueue(_ id: UInt, _ n: Int, _ c: UnsafeContinuation<UInt8, Never>) -> UInt8? {
        // Checked under the lock: either the cancel handler runs after this
        // and finds the waiter, or the flag is already visible.
        if Task.isCancelled { return 2 }
        var w = word.load(ordering: .relaxed)
        while true {
            if w & Semaphore.closedBit != 0 { return 1 }
            let take = min(w >> Semaphore.shift, n)
            let whole = take == n
            let desired = (w - take << Semaphore.shift) | (whole ? 0 : Semaphore.waitingBit)
            let (done, now) = word.compareExchange(expected: w, desired: desired,
                                                   successOrdering: .acquiring, failureOrdering: .relaxed)
            if done {
                if whole { return 0 }
                waiters.pointer.pointee.pushBack(Waiter(id: id, remaining: n - take, requested: n, continuation: c))
                return nil
            }
            w = now
        }
    }

    /// Give back `n` permits, waking queued tasks they satisfy.
    public func release(_ n: Int = 1) {
        precondition(n >= 0, "permits out of range")
        var w = word.load(ordering: .relaxed)
        while w & Semaphore.waitingBit == 0 {
            let (done, now) = word.compareExchange(expected: w, desired: w + n << Semaphore.shift,
                                                   successOrdering: .releasing, failureOrdering: .relaxed)
            if done { return }
            w = now
        }
        lock.withLock { releaseLocked(n) }
    }

    /// Under the lock: hand `n` permits to waiters in order, the rest to the
    /// word. Once nobody waits, clears the waiting bit.
    private func releaseLocked(_ n: Int) {
        let q = waiters.pointer
        var n = n
        while n > 0, let front = q.pointee.front {
            let take = min(n, front.pointee.remaining)
            front.pointee.remaining -= take
            n -= take
            if front.pointee.remaining == 0 {
                q.pointee.popFront()!.continuation.resume(returning: 0)
            }
        }
        guard q.pointee.isEmpty else { return }
        var w = word.load(ordering: .relaxed)
        while true {
            let desired = (w & ~Semaphore.waitingBit) + n << Semaphore.shift
            let (done, now) = word.compareExchange(expected: w, desired: desired,
                                                   successOrdering: .releasing, failureOrdering: .relaxed)
            if done { return }
            w = now
        }
    }

    /// Fail every waiting and future `acquire`. Permits held stay valid, and
    /// `release` still takes them back.
    public func close() {
        var woken = lock.withLock { () -> RawRing<Waiter> in
            let all = waiters.pointer.pointee
            waiters.pointer.pointee = RawRing(capacity: 4)
            var w = word.load(ordering: .relaxed)
            while true {
                let desired = (w | Semaphore.closedBit) & ~Semaphore.waitingBit
                let (done, now) = word.compareExchange(expected: w, desired: desired, ordering: .relaxed)
                if done { break }
                w = now
            }
            return all
        }
        while let w = woken.popFront() { w.continuation.resume(returning: 1) }
        woken.destroy()
    }
}
