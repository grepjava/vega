#if os(Linux) || canImport(Darwin)
import CVega
import Synchronization
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

// Unix signals as async sequences, as tokio::signal::unix. A sigaction
// handler counts each signal and writes a byte to a pipe (Tokio's self-pipe);
// one process-wide thread drains the pipe and resumes the streams waiting on
// a signal whose count moved. Nothing has to be blocked in any thread, and
// the runtime's I/O driver, whichever it is, is not involved.

extension Runtime {
    /// Deliveries of `signal` (`SIGINT`, `SIGTERM`, `SIGHUP`, ...) from now
    /// on. Works from any task, on any runtime or none.
    ///
    /// The first call for a signal replaces its disposition with Vega's
    /// handler for the rest of the process: the default action (terminating,
    /// for most) no longer happens, even after every stream is gone, as with
    /// Tokio. Throws `EINVAL` for `SIGILL`, `SIGFPE`, `SIGKILL`, `SIGSEGV` and
    /// `SIGSTOP`.
    public static func signals(_ signal: Int32) throws(IOError) -> SignalStream {
        try SignalHub.shared.install(signal)
        return SignalStream(signal: signal, seen: cv_signal_count(signal))
    }
}

/// Deliveries of one signal. Each iterator yields the signal number once per
/// wake-up: signals that arrive while nobody is waiting are coalesced into
/// one, as with Tokio. A signal that arrived after the stream was made but
/// before the first `next()` is delivered. Iteration ends (`nil`) only when
/// the waiting task is cancelled.
public struct SignalStream: AsyncSequence, Sendable {
    public typealias Element = Int32
    public typealias Failure = Never

    public let signal: Int32
    var seen: UInt64

    public func makeAsyncIterator() -> Iterator { Iterator(signal: signal, seen: seen) }

    /// Wait for the next delivery, as Tokio's `recv()`; false if the task was
    /// cancelled first.
    public mutating func recv() async -> Bool {
        var it = makeAsyncIterator()
        defer { seen = it.seen }
        return await it.next() != nil
    }

    public struct Iterator: AsyncIteratorProtocol {
        public typealias Element = Int32
        public typealias Failure = Never

        let signal: Int32
        var seen: UInt64

        public mutating func next() async -> Int32? {
            let now = cv_signal_count(signal)
            if now != seen {
                seen = now
                return signal
            }
            guard let count = await SignalHub.shared.wait(signal, seen: seen) else { return nil }
            seen = count
            return signal
        }
    }
}

/// The waiting streams, and the thread that wakes them.
final class SignalHub: Sendable {
    static let shared = SignalHub()

    private struct Waiter {
        let id: UInt64
        let signal: Int32
        let seen: UInt64
        let continuation: UnsafeContinuation<UInt64?, Never>
    }

    private struct State {
        var waiters: [Waiter] = []
        var nextID: UInt64 = 0
        var dispatching = false
    }

    // A RawLock rather than Synchronization.Mutex, which TSan doesn't see
    // (it reports races inside the lock). The hub lives as long as the
    // process: neither is destroyed.
    private let lock = RawLock()
    private let guarded = Guarded(State())

    private func withState<R>(_ body: (inout State) -> R) -> R {
        lock.withLock { body(&guarded.pointer.pointee) }
    }

    func install(_ signal: Int32) throws(IOError) {
        let rc = cv_signal_install(signal)
        guard rc == 0 else { throw IOError(code: rc) }
        let start = withState { s in
            defer { s.dispatching = true }
            return !s.dispatching
        }
        guard start else { return }
        let rc2 = cv_thread_spawn({ _ in SignalHub.shared.dispatch() }, nil, "vega-signal", -1)
        precondition(rc2 == 0, "vega: cannot start the signal thread (errno \(rc2))")
    }

    /// Suspend until `signal`'s count is past `seen`; returns the count, or
    /// nil if the task is cancelled first.
    func wait(_ signal: Int32, seen: UInt64) async -> UInt64? {
        let id = withState { s in
            s.nextID += 1
            return s.nextID
        }
        let count = await withTaskCancellationHandler {
            await withUnsafeContinuation { (c: UnsafeContinuation<UInt64?, Never>) in
                let resume: UInt64?? = withState { s in
                    // The handler counts before it writes the pipe, so a
                    // signal the dispatcher has already handled shows here.
                    let now = cv_signal_count(signal)
                    if now != seen { return .some(now) }
                    // The cancel handler may have looked before we were in
                    // the list; it runs after the flag is set.
                    if Task.isCancelled { return .some(nil) }
                    s.waiters.append(Waiter(id: id, signal: signal, seen: seen, continuation: c))
                    return .none
                }
                if let resume { c.resume(returning: resume) }
            }
        } onCancel: {
            let waiter = withState { s -> Waiter? in
                guard let i = s.waiters.firstIndex(where: { $0.id == id }) else { return nil }
                return s.waiters.remove(at: i)
            }
            waiter?.continuation.resume(returning: nil)
        }
        // A delivery can resume us before we suspend; see cv_tsan_acquire.
        cv_tsan_acquire(cv_task_current())
        return count
    }

    private func dispatch() -> Never {
        while true {
            cv_signal_wait()
            var ready: [(UnsafeContinuation<UInt64?, Never>, UInt64)] = []
            withState { s in
                s.waiters.removeAll { w in
                    let now = cv_signal_count(w.signal)
                    guard now != w.seen else { return false }
                    ready.append((w.continuation, now))
                    return true
                }
            }
            for (c, count) in ready { c.resume(returning: count) }
        }
    }
}
#endif
