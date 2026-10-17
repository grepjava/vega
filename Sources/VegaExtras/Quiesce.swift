import Synchronization
import Vega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#elseif os(Windows)
import ucrt
#endif

/// Graceful shutdown for a process with several servers, as NIOExtras'
/// `ServerQuiescingHelper`: when SIGTERM or SIGINT arrives (or `trigger()`
/// is called), every server registered stops taking work and finishes what
/// it has, within one grace period, and `run()` returns once all are done.
///
/// ```swift
/// let quiesce = Quiesce(gracePeriod: .seconds(20))
/// quiesce.add(httpServer)
/// quiesce.add { grace in await quicEndpoint.close(grace: grace) }
/// try await quiesce.run()      // returns after SIGTERM, all drained
/// ```
public final class Quiesce: Sendable {
    public typealias Shutdown = @Sendable (Duration) async -> Void

    private let gracePeriod: Duration
    private let signals: [Int32]
    private let shutdowns = Mutex<[Shutdown]>([])
    /// Set by `trigger()` or a signal; `run()` waits on it.
    public let signal = ShutdownSignal()

    /// - Parameters:
    ///   - gracePeriod: how long the servers get to finish, all together.
    ///   - signals: the signals that start it; none for `trigger()` only.
    public init(gracePeriod: Duration = .seconds(30), signals: [Int32] = [SIGTERM, SIGINT]) {
        self.gracePeriod = gracePeriod
        self.signals = signals
    }

    /// Shut `server` down with the others.
    public func add(_ server: TCPServer) {
        add { grace in await server.shutdown(gracePeriod: grace) }
    }

    /// Run `shutdown` with the others, given the grace period: for anything
    /// with a graceful close of its own.
    public func add(_ shutdown: @escaping Shutdown) {
        shutdowns.withLock { $0.append(shutdown) }
    }

    /// Start shutting down, as a signal would.
    public func trigger() {
        signal.trigger()
    }

    /// Wait for a signal or `trigger()`, then shut everything registered
    /// down at once, and return when it all has.
    public func run() async throws(IOError) {
        let watchers = try signals.map { s throws(IOError) in try Runtime.signals(s) }
        await withTaskGroup(of: Void.self) { group in
            for stream in watchers {
                group.addTask { [signal] in
                    var it = stream.makeAsyncIterator()
                    if await it.next() != nil { signal.trigger() }
                }
            }
            await signal.wait()
            group.cancelAll()
        }
        let all = shutdowns.withLock { $0 }
        let grace = gracePeriod
        await withTaskGroup(of: Void.self) { group in
            for shutdown in all { group.addTask { await shutdown(grace) } }
        }
    }
}
