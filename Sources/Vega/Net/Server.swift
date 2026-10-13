#if os(Linux) || canImport(Darwin)
import CVega
import Synchronization
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// A TCP server: accept loops that spawn a task per connection, NIO's
/// `ServerBootstrap` and Tokio's accept-and-spawn loop in one.
///
/// ```swift
/// let server = try TCPServer.bind(port: 8080) { stream in
///     await serve(stream)
/// }
/// // ...
/// await server.shutdown(gracePeriod: .seconds(10))
/// ```
///
/// - Several accept loops (`acceptors`) share the port with SO_REUSEPORT,
///   so the kernel spreads connections across them (Linux).
/// - `maxConnections` stops accepting while that many are open: excess
///   connections wait in the kernel's backlog instead of exhausting fds.
/// - Transient accept failures (out of fds or memory, a connection aborted
///   before it was accepted) don't stop the server; it backs off and goes on.
/// - `shutdown(gracePeriod:)` stops accepting, lets open connections finish
///   for the grace period, then cancels the rest. Handlers that keep a
///   connection open across requests can watch `waitForShutdown()` to close
///   between requests.
public final class TCPServer: Sendable {
    public struct Configuration: Sendable {
        /// Accept loops, each with its own listener on the port. More than
        /// one implies `reusePort`.
        public var acceptors = 1
        public var backlog = 1024
        public var reusePort = false
        /// The most connections open at once; nil for no limit.
        public var maxConnections: Int?
        /// Set on each listener after it's bound (`.fastOpen`, buffer sizes).
        public var listenerOptions: [SocketOption: Int] = [:]
        /// Set on each accepted connection before its handler runs; one that
        /// fails drops the connection.
        public var connectionOptions: [SocketOption: Int] = [:]

        public init(acceptors: Int = 1, maxConnections: Int? = nil,
                    connectionOptions: [SocketOption: Int] = [:]) {
            self.acceptors = acceptors
            self.maxConnections = maxConnections
            self.connectionOptions = connectionOptions
        }
    }

    private enum Slot: Sendable {
        /// Counted, its task not yet recorded.
        case starting
        case running(Task<Void, Never>)
    }

    private struct State: Sendable {
        /// Set once open connections are being cancelled: late starters
        /// cancel themselves.
        var cancelling = false
        var connections: [UInt64: Slot] = [:]
        var acceptorTasks: [Task<Void, Never>] = []
        var acceptorsRunning = 0
        var acceptError: IOError?
    }

    /// The address the server listens on (its port, if bound to port 0).
    public let localAddress: SocketAddress
    private let configuration: Configuration
    private let handler: @Sendable (consuming TCPStream) async -> Void
    private let scheduler: Scheduler
    private let permits: Semaphore?
    private let state = Watch(State())
    /// Apart from `state`, so handlers waiting for shutdown aren't woken by
    /// every connection coming and going.
    private let shuttingDown = Watch(false)
    private let nextID = Atomic<UInt64>(0)
    private let open = Atomic<Int>(0)

    /// Listen on `host` and `port` (0 picks a free one) and serve each
    /// connection with `handler`, in its own task. Call from a task on a
    /// Vega runtime.
    public static func bind(host: String = "", port: Int, configuration: Configuration = .init(),
                            handler: @escaping @Sendable (consuming TCPStream) async -> Void) throws(IOError) -> TCPServer {
        guard let scheduler = Worker.currentScheduler else { throw .notOnRuntime }
        let acceptors = max(configuration.acceptors, 1)
        let reusePort = configuration.reusePort || acceptors > 1
        let first = try listener(host, port, configuration, reusePort)
        let server = TCPServer(localAddress: try first.localAddress, configuration: configuration,
                               handler: handler, scheduler: scheduler)
        server.startAcceptor(first)
        for _ in 1..<acceptors {
            do {
                server.startAcceptor(try listener(host, server.port, configuration, reusePort))
            } catch {
                server.stopAccepting()
                throw error
            }
        }
        return server
    }

    private static func listener(_ host: String, _ port: Int, _ configuration: Configuration,
                                 _ reusePort: Bool) throws(IOError) -> TCPListener {
        let l = try TCPListener.bind(host: host, port: port, backlog: configuration.backlog, reusePort: reusePort)
        for (option, value) in configuration.listenerOptions { try l.setOption(option, to: value) }
        return l
    }

    private init(localAddress: SocketAddress, configuration: Configuration,
                 handler: @escaping @Sendable (consuming TCPStream) async -> Void, scheduler: Scheduler) {
        self.localAddress = localAddress
        self.configuration = configuration
        self.handler = handler
        self.scheduler = scheduler
        permits = configuration.maxConnections.map { Semaphore(permits: max($0, 1)) }
    }

    /// The port the server listens on.
    public var port: Int { localAddress.port ?? 0 }

    /// Connections open now.
    public var connectionCount: Int { open.load(ordering: .relaxed) }

    /// Whether `shutdown` has begun.
    public var isShuttingDown: Bool { shuttingDown.value }

    /// Why an accept loop stopped, if one stopped on an error it couldn't
    /// ride out.
    public var acceptError: IOError? { state.value.acceptError }

    /// Return once `shutdown` begins (or the task is cancelled).
    public func waitForShutdown() async {
        var r = shuttingDown.subscribe()
        while !r.value {
            do {
                try await r.changed()
            } catch {
                return
            }
        }
    }

    /// Return once the server has stopped: no accept loop running (after
    /// `shutdown`, or an accept error) and no connection open.
    public func wait() async {
        await waitUntil { $0.acceptorsRunning == 0 && $0.connections.isEmpty }
    }

    /// Stop accepting, give open connections up to `gracePeriod` to finish,
    /// then cancel the ones left and wait for them to end.
    public func shutdown(gracePeriod: Duration) async {
        stopAccepting()
        if gracePeriod > .zero {
            _ = try? await Runtime.timeout(gracePeriod) { [self] in
                await waitUntil { $0.connections.isEmpty }
            }
        }
        var running: [Task<Void, Never>] = []
        state.modify { s in
            s.cancelling = true
            for case .running(let task) in s.connections.values { running.append(task) }
        }
        for task in running { task.cancel() }
        await wait()
    }

    private func stopAccepting() {
        shuttingDown.send(true)
        var acceptors: [Task<Void, Never>] = []
        state.modify { acceptors = $0.acceptorTasks }
        for task in acceptors { task.cancel() }
    }

    private func waitUntil(_ done: (State) -> Bool) async {
        var r = state.subscribe()
        while !done(r.value) {
            do {
                try await r.changed()
            } catch {
                return
            }
        }
    }

    // MARK: - Accepting

    private func startAcceptor(_ listener: consuming TCPListener) {
        let box = Handoff(listener)
        state.modify { $0.acceptorsRunning += 1 }
        let task = Task(executorPreference: scheduler) { [self] in
            await acceptLoop(box.take())
            state.modify { $0.acceptorsRunning -= 1 }
        }
        state.modify { $0.acceptorTasks.append(task) }
        // stopAccepting sets the flag before reading the tasks: one of the
        // two sees the other.
        if shuttingDown.value { task.cancel() }
    }

    private func acceptLoop(_ listener: consuming TCPListener) async {
        while !Task.isCancelled {
            if let permits {
                do {
                    try await permits.acquire()
                } catch {
                    return
                }
            }
            let stream: TCPStream
            do {
                stream = try await listener.accept()
            } catch {
                permits?.release()
                if error == .cancelled || Task.isCancelled { return }
                switch error.code {
                case ECONNABORTED, EPROTO, EINTR, EPERM:
                    // That connection is gone; the next one is fine.
                    continue
                case EMFILE, ENFILE, ENOBUFS, ENOMEM:
                    // Out of fds or memory: wait for connections to close
                    // rather than spin on the error.
                    do {
                        try await Runtime.sleep(for: .milliseconds(10))
                    } catch {
                        return
                    }
                    continue
                default:
                    state.modify { $0.acceptError = error }
                    return
                }
            }
            var configured = true
            for (option, value) in configuration.connectionOptions {
                do {
                    try stream.setOption(option, to: value)
                } catch {
                    configured = false
                    break
                }
            }
            guard configured else {
                permits?.release()
                continue
            }
            start(stream)
        }
    }

    private func start(_ stream: consuming TCPStream) {
        let id = nextID.add(1, ordering: .relaxed).newValue
        open.add(1, ordering: .relaxed)
        state.modify { $0.connections[id] = .starting }
        let box = Handoff(stream)
        let handler = handler
        let task = Task(executorPreference: scheduler) { [self] in
            await handler(box.take())
            open.subtract(1, ordering: .relaxed)
            permits?.release()
            state.modify { $0.connections[id] = nil }
        }
        // Recorded unless it already finished; cancelled if shutdown got
        // there first.
        var cancel = false
        state.modify { s in
            guard s.connections[id] != nil else { return }
            s.connections[id] = .running(task)
            cancel = s.cancelling
        }
        if cancel { task.cancel() }
    }
}

/// Connection settings for outgoing TCP: NIO's `ClientBootstrap`.
///
/// ```swift
/// let client = TCPClient(connectTimeout: .seconds(5), resolver: .system,
///                        options: [.keepAlive: 1])
/// let stream = try await client.connect(host: "example.com", port: 443)
/// ```
public struct TCPClient: Sendable {
    /// How long a whole connect may take, lookup included; nil for no limit.
    /// Exceeding it throws ETIMEDOUT.
    public var connectTimeout: Duration?
    /// Happy Eyeballs' delay between attempts (see `TCPStream.connect(to:attemptDelay:)`).
    public var attemptDelay: Duration
    /// Looks names up; nil uses `getaddrinfo` on the blocking pool.
    public var resolver: Resolver?
    /// Set on each connection once it's open.
    public var options: [SocketOption: Int]

    public init(connectTimeout: Duration? = .seconds(30), attemptDelay: Duration = .milliseconds(250),
                resolver: Resolver? = nil, options: [SocketOption: Int] = [:]) {
        self.connectTimeout = connectTimeout
        self.attemptDelay = attemptDelay
        self.resolver = resolver
        self.options = options
    }

    /// Connect to `host` (a name or an address) and `port`.
    public func connect(host: String, port: Int) async throws(IOError) -> TCPStream {
        let resolver = resolver, delay = attemptDelay
        return try await connect { () async throws(IOError) -> TCPStream in
            if let resolver {
                try await TCPStream.connect(host: host, port: port, resolver: resolver, attemptDelay: delay)
            } else {
                try await TCPStream.connect(host: host, port: port, attemptDelay: delay)
            }
        }
    }

    /// Connect to the first of `addresses` that answers (Happy Eyeballs).
    public func connect(to addresses: [SocketAddress]) async throws(IOError) -> TCPStream {
        let delay = attemptDelay
        return try await connect { () async throws(IOError) -> TCPStream in
            try await TCPStream.connect(to: addresses, attemptDelay: delay)
        }
    }

    private func connect(
        _ operation: @escaping @Sendable () async throws(IOError) -> TCPStream
    ) async throws(IOError) -> TCPStream {
        let stream: TCPStream
        if let connectTimeout {
            do {
                stream = try await Runtime.timeout(connectTimeout) { Handoff(try await operation()) }.take()
            } catch let error as IOError {
                throw error
            } catch is TimeoutError {
                throw IOError(code: ETIMEDOUT)
            } catch {
                throw .cancelled
            }
        } else {
            stream = try await operation()
        }
        for (option, value) in options { try stream.setOption(option, to: value) }
        return stream
    }
}
#endif
