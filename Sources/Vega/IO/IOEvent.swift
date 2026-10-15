import Synchronization

/// A wake-up for one waiter whose wait counts as I/O: a custom `AsyncReader`
/// or `AsyncWriter` waits on it for its bytes, and the task's cancellation
/// and its `Runtime.withIODeadline` deadline -- or that scope's trigger --
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
    private let state = Mutex<(waiter: UnsafeContinuation<Bool, Never>?, signalled: Bool)>((nil, false))

    /// Parks `c`. False when a signal was waiting: `c` is resumed already.
    func park(_ c: UnsafeContinuation<Bool, Never>) -> Bool {
        let parked = state.withLock { s -> Bool in
            if s.signalled {
                s.signalled = false
                return false
            }
            s.waiter = c
            return true
        }
        if !parked { c.resume(returning: true) }
        return parked
    }

    func signal() {
        let waiter = state.withLock { s -> UnsafeContinuation<Bool, Never>? in
            guard let w = s.waiter else {
                s.signalled = true
                return nil
            }
            s.waiter = nil
            return w
        }
        waiter?.resume(returning: true)
    }

    override func interrupt() {
        let waiter = state.withLock { s -> UnsafeContinuation<Bool, Never>? in
            let w = s.waiter
            s.waiter = nil
            return w
        }
        waiter?.resume(returning: false)
    }
}
