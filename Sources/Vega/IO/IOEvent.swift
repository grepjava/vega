import Synchronization

/// A wake-up for one waiter whose wait counts as I/O: a custom `AsyncReader`
/// or `AsyncWriter` waits on it for its bytes, and the task's cancellation
/// and its `Runtime.withIOTimeout` deadline -- or that scope's trigger --
/// interrupt the wait as they would a socket's.
///
/// ```swift
/// // The reading side of an in-memory pipe.
/// while buffer.isEmpty {
///     try await arrived.wait()      // throws .timedOut past the deadline
/// }
/// ```
///
/// `signal` wakes the waiter, or, with none waiting, lets the next `wait`
/// return at once: one signal is kept, however many are sent. One task
/// waits at a time.
public final class IOEvent: Sendable {
    private let target = IOEventTarget()

    public init() {}

    /// Waits for `signal`. Throws `IOError.timedOut` when the task's I/O
    /// deadline passes or its trigger fires first, and `IOError.cancelled`
    /// when the task is cancelled. A signal sent before the wait is taken
    /// at once.
    public func wait() async throws(IOError) {
        let target = self.target
        let woken = await withIOInterrupt { arm in
            await withUnsafeContinuation { (c: UnsafeContinuation<Bool, Never>) in
                guard target.park(c) else { return }
                // Fired already: run the action, as a cancellation handler
                // would have at once.
                if !arm(.object(Unmanaged.passUnretained(target))) { target.interrupt() }
            }
        }
        // The wait is over, however it ended; the target outlives it.
        withExtendedLifetime(target) {}
        if !woken { throw IOError.interrupted }
    }

    /// Wakes the waiter, or the next to wait.
    public func signal() {
        target.signal()
    }
}

/// The waiter and the kept signal, and what an interruption does to them.
final class IOEventTarget: IOInterruptTarget, @unchecked Sendable {
    // A RawLock, not a Mutex: ThreadSanitizer doesn't see Mutex on Linux.
    private let lock = RawLock()
    private let state = Guarded<(waiter: UnsafeContinuation<Bool, Never>?, signalled: Bool)>((nil, false))

    deinit {
        state.destroy()
        lock.destroy()
    }

    /// Parks `c`. False when a signal was waiting: `c` is resumed already.
    func park(_ c: UnsafeContinuation<Bool, Never>) -> Bool {
        let s = state.pointer
        let parked = lock.withLock { () -> Bool in
            if s.pointee.signalled {
                s.pointee.signalled = false
                return false
            }
            s.pointee.waiter = c
            return true
        }
        if !parked { c.resume(returning: true) }
        return parked
    }

    func signal() {
        let s = state.pointer
        let waiter = lock.withLock { () -> UnsafeContinuation<Bool, Never>? in
            guard let w = s.pointee.waiter else {
                s.pointee.signalled = true
                return nil
            }
            s.pointee.waiter = nil
            return w
        }
        waiter?.resume(returning: true)
    }

    override func interrupt() {
        let s = state.pointer
        let waiter = lock.withLock { () -> UnsafeContinuation<Bool, Never>? in
            let w = s.pointee.waiter
            s.pointee.waiter = nil
            return w
        }
        waiter?.resume(returning: false)
    }
}
