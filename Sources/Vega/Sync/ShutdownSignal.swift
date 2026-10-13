import CVega
import Synchronization

/// "Start shutting down", given once to everything serving: tokio-util's
/// `CancellationToken`, NIOExtras' quiescing. Servers take one and stop
/// cleanly when it triggers: HTTP/1 closes idle connections and ends busy
/// ones after the current response, HTTP/2 sends GOAWAY and finishes its
/// open streams.
///
/// ```swift
/// let shutdown = ShutdownSignal()
/// let server = try TCPServer.bind(port: 8080, configuration: .init(shutdownSignal: shutdown)) { conn in
///     try? await HTTP1Server.serve(conn, shutdown: shutdown) { request in HTTPResponse(body: "hi") }
/// }
/// // ...
/// await server.shutdown(gracePeriod: .seconds(10))   // triggers `shutdown`
/// ```
public final class ShutdownSignal: Sendable {
    private struct State {
        var triggered = false
        var nextID: UInt64 = 0
        /// Tasks in `cancelOnTrigger`, each retained.
        var tasks: [UInt64: UInt] = [:]
    }

    private let state = Mutex(State())
    private let triggered = Watch(false)

    public init() {}

    /// Whether `trigger()` has been called.
    public var isTriggered: Bool { state.withLock { $0.triggered } }

    /// Begin shutting down: wake `wait()`ers and cancel the tasks in
    /// `cancelOnTrigger`. Calls after the first do nothing.
    public func trigger() {
        state.withLock { s in
            guard !s.triggered else { return }
            s.triggered = true
            // Under the lock: once `cancelOnTrigger` has unregistered, its
            // task can't be cancelled by a trigger that found it earlier.
            for task in s.tasks.values {
                let t = UnsafeRawPointer(bitPattern: task).unsafelyUnwrapped
                cv_task_cancel(UnsafeMutableRawPointer(mutating: t))
                cv_task_release(t)
            }
            s.tasks = [:]
        }
        triggered.send(true)
    }

    /// Return once triggered (or the calling task is cancelled).
    public func wait() async {
        var r = triggered.subscribe()
        while !r.value {
            do {
                try await r.changed()
            } catch {
                return
            }
        }
    }

    /// Run `operation`, cancelling the calling task if the signal triggers
    /// meanwhile (or already has): for a wait that shutdown should cut
    /// short, like reading the next request on an idle connection. The task
    /// stays cancelled afterwards, as with any cancellation.
    public func cancelOnTrigger<T, E: Error>(_ operation: () async throws(E) -> T) async throws(E) -> T {
        guard let task = cv_task_current() else { return try await operation() }
        let id = state.withLock { s -> UInt64? in
            if s.triggered {
                cv_task_cancel(task)
                return nil
            }
            s.nextID += 1
            cv_task_retain(task)
            s.tasks[s.nextID] = UInt(bitPattern: task)
            return s.nextID
        }
        defer {
            if let id, state.withLock({ $0.tasks.removeValue(forKey: id) }) != nil {
                cv_task_release(task)
            }
        }
        return try await operation()
    }
}
