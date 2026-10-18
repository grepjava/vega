#if canImport(Network)
import CVega
import Darwin
import Dispatch
import Foundation
import Network

// IOBackend.network: TCP over Apple's Network.framework. An NWConnection or
// NWListener sits behind the same IORegistration the fd-backed drivers use
// (its `nw` field), so TCPStream, TCPListener and the split halves keep
// their API. Network.framework calls back on a dispatch queue; those
// callbacks resume the waiting task the way Runtime.blocking's threads do,
// through the runtime's foreign enqueue.

enum NetworkIO {
    /// Whether `backend` (with `VEGA_DRIVER` for `.automatic`) asks for
    /// Network.framework.
    static func wanted(_ backend: IOBackend) -> Bool {
        switch backend.kind {
        case .network: return true
        case .readiness, .ioUring: return false
        case .automatic, .iocp: // (.iocp is Windows only)
            if let v = getenv("VEGA_DRIVER") { return String(cString: v) == "network" }
            #if os(macOS)
            return false
            #else
            return true
            #endif
        }
    }

    /// Whether the task running the caller is on a runtime using this backend.
    @inline(__always) static var active: Bool {
        Worker.currentScheduler?.usesNetwork ?? false
    }

    /// Callbacks for each socket run on a serial queue of their own, all
    /// sharing one concurrent target.
    static let target = DispatchQueue(label: "vega.network", qos: .userInitiated, attributes: .concurrent)

    /// Socket options for the next connections this task makes
    /// (`TCPClient.options`): Network.framework takes them when a connection
    /// is created, not after.
    @TaskLocal static var connectOptions: [SocketOption: Int] = [:]

    /// TCP parameters, with TLS that Network.framework runs when `tls` is
    /// given (`NetworkTLS`). `options` are applied here; ones
    /// Network.framework has no setting for throw `.unsupported`.
    static func parameters(_ options: [SocketOption: Int] = [:], tls: NWProtocolTLS.Options? = nil,
                           reuse: Bool = false) throws(IOError) -> NWParameters {
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true // as cv_tcp_accepted and cv_connect_new do
        var reuse = reuse
        for (option, value) in options {
            switch option {
            case .reuseAddress, .reusePort: reuse = reuse || value != 0
            default: try set(option, value, on: tcp)
            }
        }
        let p = NWParameters(tls: tls, tcp: tcp)
        p.allowLocalEndpointReuse = reuse
        return p
    }

    /// The TCP options Network.framework has settings for.
    private static func set(_ option: SocketOption, _ value: Int, on tcp: NWProtocolTCP.Options) throws(IOError) {
        switch option {
        case .noDelay: tcp.noDelay = value != 0
        case .keepAlive: tcp.enableKeepalive = value != 0
        case .keepAliveIdle: tcp.keepaliveIdle = value
        case .keepAliveInterval: tcp.keepaliveInterval = value
        case .keepAliveCount: tcp.keepaliveCount = value
        case .fastOpen: tcp.enableFastOpen = value != 0
        default: throw .unsupported
        }
    }

    /// An option's value as the connection was created with it.
    static func option(_ option: SocketOption, of parameters: NWParameters) throws(IOError) -> Int {
        guard let tcp = parameters.defaultProtocolStack.transportProtocol as? NWProtocolTCP.Options else {
            throw .unsupported
        }
        switch option {
        case .noDelay: return tcp.noDelay ? 1 : 0
        case .keepAlive: return tcp.enableKeepalive ? 1 : 0
        case .keepAliveIdle: return tcp.keepaliveIdle
        case .keepAliveInterval: return tcp.keepaliveInterval
        case .keepAliveCount: return tcp.keepaliveCount
        case .fastOpen: return tcp.enableFastOpen ? 1 : 0
        case .reuseAddress, .reusePort: return parameters.allowLocalEndpointReuse ? 1 : 0
        default: throw .unsupported
        }
    }

    // MARK: Streams

    /// Connect to `host` (a name or an address) and `port`. Network.framework
    /// resolves the name and races the addresses itself (Happy Eyeballs).
    static func connect(host: String, port: Int, tls: NWProtocolTLS.Options? = nil,
                        parameters given: NWParameters? = nil) async throws(IOError) -> IORegistration {
        let parameters: NWParameters
        if let given { parameters = given } else { parameters = try self.parameters(connectOptions, tls: tls) }
        guard let p = NWEndpoint.Port(rawValue: UInt16(clamping: port)), port > 0, port <= 65535 else {
            throw IOError(code: EINVAL)
        }
        let connection = NWConnection(host: NWEndpoint.Host(host), port: p, using: parameters)
        let stream = NetworkStream(connection)
        let ready = Rendezvous<IOError?>()
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready: ready.offer(nil)
            // A refused or unreachable connect waits for a better path in
            // Network.framework; a socket connect fails, and so does this.
            // (So does a TLS handshake that fails: Network.framework reports
            // it as waiting, with the TLS error.)
            case .waiting(let e), .failed(let e): ready.offer(map(e))
            case .cancelled: ready.offer(.cancelled)
            default: break
            }
        }
        connection.start(queue: stream.queue)
        if var error = await ready.wait(cancelled: .cancelled) {
            if error == .cancelled { error = .interrupted }
            connection.stateUpdateHandler = nil
            connection.cancel()
            throw error
        }
        connection.stateUpdateHandler = nil
        stream.settle(nil)
        return registration(for: stream)
    }

    static func connect(to address: SocketAddress) async throws(IOError) -> IORegistration {
        try await connect(host: address.host, port: address.port ?? 0)
    }

    /// The registration for a started connection.
    static func registration(for handle: NetworkHandle) -> IORegistration {
        let io = UnsafeMutablePointer<cv_io>.allocate(capacity: 1)
        io.initialize(to: cv_io())
        io.pointee.fd = -1
        io.pointee.refs = 1
        // Counted with the runtime's open sockets, as the uring driver does.
        if let count = Worker.currentScheduler?.socketCount {
            io.pointee.count = count
            cv_count_add(count, 1)
        }
        return IORegistration(io: io, nw: UnsafeRawPointer(Unmanaged.passRetained(handle).toOpaque()))
    }

    /// One owner of `io` lets go; the last cancels the connection.
    static func release(_ io: UnsafeMutablePointer<cv_io>, _ nw: UnsafeRawPointer) {
        guard cv_io_unref(io) == 0 else { return }
        let handle = Unmanaged<NetworkHandle>.fromOpaque(nw).takeRetainedValue()
        handle.close()
        if let count = io.pointee.count { cv_count_add(count, -1) }
        io.deallocate()
    }

    @inline(__always) static func handle(_ nw: UnsafeRawPointer) -> NetworkHandle {
        Unmanaged<NetworkHandle>.fromOpaque(nw).takeUnretainedValue()
    }

    // MARK: Listeners

    /// Listen on `host` (empty: all interfaces) and `port` (0: any). Blocks
    /// until the listener is ready (a few milliseconds), as bind(2) and
    /// listen(2) return at once for fd-backed listeners.
    /// `connectionOptions` apply to every connection it accepts.
    static func listen(host: String, port: Int, backlog: Int, reusePort: Bool, tls: NWProtocolTLS.Options? = nil,
                       connectionOptions: [SocketOption: Int] = [:]) throws(IOError) -> IORegistration {
        guard port >= 0, port <= 65535 else { throw IOError(code: EINVAL) }
        // Always, as cv_tcp_listen sets SO_REUSEADDR: without it Network.framework
        // refuses a second listener on the port even on another address (::1
        // after 127.0.0.1). An exact duplicate is still EADDRINUSE.
        let params = try parameters(connectionOptions, tls: tls, reuse: true)
        let p = port == 0 ? NWEndpoint.Port.any : NWEndpoint.Port(rawValue: UInt16(port))!
        if !host.isEmpty { params.requiredLocalEndpoint = .hostPort(host: NWEndpoint.Host(host), port: p) }
        let listener: NWListener
        do {
            listener = host.isEmpty ? try NWListener(using: params, on: p) : try NWListener(using: params)
        } catch {
            throw map(error)
        }
        let acceptor = NetworkAcceptor(listener)
        if let error = acceptor.start() { throw error }
        return registration(for: acceptor)
    }

    // MARK: Errors and addresses

    static func map(_ error: Error) -> IOError {
        guard let e = error as? NWError else { return IOError(code: EIO) }
        switch e {
        case .posix(let code): return IOError(code: code.rawValue)
        case .dns: return IOError(code: EHOSTUNREACH)
        // The OSStatus (errSSL..., -98xx) says which check failed.
        case .tls(let status): return IOError(code: EPROTO, message: "TLS: OSStatus \(status)")
        default: return IOError(code: EIO)
        }
    }

    static func address(_ endpoint: NWEndpoint?) throws(IOError) -> SocketAddress {
        guard case .hostPort(let host, let port)? = endpoint else { throw IOError(code: ENOTCONN) }
        var text: String
        switch host {
        case .ipv4(let a): text = "\(a)"
        case .ipv6(let a): text = "\(a)"
        case .name(let n, _): text = n
        @unknown default: text = "\(host)"
        }
        if let percent = text.firstIndex(of: "%") { text = String(text[..<percent]) } // scope
        return try SocketAddress(host: text, port: Int(port.rawValue))
    }
}

/// What an IORegistration's `nw` points at.
class NetworkHandle: @unchecked Sendable {
    let queue = DispatchQueue(label: "vega.network.socket", target: NetworkIO.target)
    func close() {}
}

/// A one-shot handoff between a Network.framework callback (or a cancel)
/// and the task waiting for it: whichever comes first wins.
final class Rendezvous<T: Sendable>: IOInterruptTarget, @unchecked Sendable {
    private let lock = RawLock()
    private var continuation: UnsafeContinuation<T, Never>?
    private var value: T?
    private var done = false
    /// What `interrupt` offers: set by `wait` before it arms.
    private var cancelled: T?

    deinit { lock.destroy() }

    /// Wait for `offer`; `cancelled` if the task is cancelled, or its I/O
    /// deadline passes, first.
    func wait(cancelled: T) async -> T {
        self.cancelled = cancelled
        let result = await withIOInterrupt { arm in
            await withUnsafeContinuation { (c: UnsafeContinuation<T, Never>) in
                lock.lock()
                if let value {
                    lock.unlock()
                    c.resume(returning: value)
                    return
                }
                continuation = c
                lock.unlock()
                let cancel = IOInterrupt.object(.passUnretained(self))
                if !arm(cancel) { cancel.fire() }
            }
        }
        cv_tsan_acquire(cv_task_current())
        return result
    }

    /// Settle the wait with `v`, if nothing has yet.
    func offer(_ v: T) {
        lock.lock()
        guard !done else {
            lock.unlock()
            return
        }
        done = true
        if let c = continuation {
            continuation = nil
            lock.unlock()
            c.resume(returning: v)
        } else {
            value = v
            lock.unlock()
        }
    }

    /// Cancellation or the deadline: settle the wait with `cancelled`.
    override func interrupt() {
        if let cancelled { offer(cancelled) }
    }
}

/// A TCP connection. Received bytes collect in `stash` until a read takes
/// them, so a read cancelled while Network.framework is receiving loses
/// nothing: the next read gets those bytes.
final class NetworkStream: NetworkHandle, @unchecked Sendable {
    let connection: NWConnection
    private let lock = RawLock()
    private var stash: [UInt8] = []
    private var stashStart = 0
    private var ended = false
    private var failure: IOError?
    private var receiving = false
    private var reader: Rendezvous<Bool>?
    /// How the connection's start (with TLS, its handshake) ended: nil
    /// until it has, then nil inside for ready.
    private var started: IOError??
    private var startWaiters: [Rendezvous<Bool>] = []

    init(_ connection: NWConnection) {
        self.connection = connection
    }

    /// Follow an accepted connection's state, for `ready()`.
    func watch() {
        connection.stateUpdateHandler = { [self] state in
            switch state {
            case .ready: settle(nil)
            case .waiting(let e), .failed(let e): settle(NetworkIO.map(e))
            case .cancelled: settle(IOError(code: ECONNABORTED))
            default: break
            }
        }
    }

    /// The connection is ready, or never will be.
    func settle(_ error: IOError?) {
        lock.lock()
        guard started == nil else {
            lock.unlock()
            return
        }
        started = .some(error)
        let all = startWaiters
        startWaiters.removeAll()
        lock.unlock()
        for w in all { w.offer(true) }
    }

    /// Wait until the connection is ready: for TLS, until the handshake is
    /// done. Throws how it failed.
    func ready() async throws(IOError) {
        while true {
            lock.lock()
            if let started {
                lock.unlock()
                if let error = started { throw error }
                return
            }
            let r = Rendezvous<Bool>()
            startWaiters.append(r)
            lock.unlock()
            guard await r.wait(cancelled: false) else {
                lock.lock()
                startWaiters.removeAll { $0 === r }
                lock.unlock()
                throw .interrupted
            }
        }
    }

    /// The TLS session's metadata, once ready; nil without TLS.
    var tlsMetadata: sec_protocol_metadata_t? {
        (connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata)?.securityProtocolMetadata
    }

    deinit { lock.destroy() }

    /// As close(2): what was sent still goes out, then FIN (after TLS's
    /// close_notify). The connection is cancelled once that is done.
    override func close() {
        connection.stateUpdateHandler = nil
        let connection = self.connection
        connection.send(content: nil, contentContext: .finalMessage, isComplete: true,
                        completion: .contentProcessed { _ in connection.cancel() })
    }

    func read(into buffer: inout IOBuffer) async throws(IOError) -> Int {
        guard buffer.spareCapacity > 0 else { throw IOError.readIntoFullBuffer }
        while true {
            lock.lock()
            if stashStart < stash.count {
                let n = min(buffer.spareCapacity, stash.count - stashStart)
                stash.withUnsafeBytes { all in
                    (buffer.base + buffer.count).copyMemory(from: all.baseAddress! + stashStart, byteCount: n)
                }
                stashStart += n
                if stashStart == stash.count {
                    stash.removeAll(keepingCapacity: true)
                    stashStart = 0
                }
                lock.unlock()
                buffer.readable += n
                await Runtime.consumeBudget()
                return n
            }
            if let failure {
                lock.unlock()
                throw failure
            }
            if ended {
                lock.unlock()
                return 0
            }
            let r = Rendezvous<Bool>()
            reader = r
            let start = !receiving
            receiving = true
            lock.unlock()
            if start { receive() }
            guard await r.wait(cancelled: false) else {
                lock.lock()
                if reader === r { reader = nil }
                lock.unlock()
                throw .interrupted
            }
        }
    }

    /// Wait until a read would return at once: false for data, true for the
    /// end of the stream or a failure.
    func waitReadable() async throws(IOError) -> Bool {
        while true {
            lock.lock()
            if stashStart < stash.count {
                lock.unlock()
                return false
            }
            if ended || failure != nil {
                lock.unlock()
                return true
            }
            let r = Rendezvous<Bool>()
            reader = r
            let start = !receiving
            receiving = true
            lock.unlock()
            if start { receive() }
            guard await r.wait(cancelled: false) else {
                lock.lock()
                if reader === r { reader = nil }
                lock.unlock()
                throw .interrupted
            }
        }
    }

    private func receive() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [self] data, _, complete, error in
            lock.lock()
            receiving = false
            if let data, !data.isEmpty { stash.append(contentsOf: data) }
            if complete { ended = true }
            if let error, !complete { failure = NetworkIO.map(error) }
            let r = reader
            reader = nil
            lock.unlock()
            r?.offer(true)
        }
    }

    /// Send `data`; returns once Network.framework has taken it.
    func write(_ data: Data) async throws(IOError) {
        let done = Rendezvous<IOError?>()
        connection.send(content: data, completion: .contentProcessed { error in
            done.offer(error.map(NetworkIO.map))
        })
        // A cancelled write gives up waiting; the bytes still go out.
        if let error = await done.wait(cancelled: .cancelled) { throw error == .cancelled ? .interrupted : error }
        await Runtime.consumeBudget()
    }

    /// Whether a read would return at once: bytes received, end of stream,
    /// or a failure. Network.framework only says so to a receive, so one is
    /// started if none is in flight -- an idle connection asked again later
    /// has its answer.
    var hasPendingInput: Bool {
        lock.lock()
        let known = stashStart < stash.count || ended || failure != nil
        let start = !known && !receiving
        if start { receiving = true }
        lock.unlock()
        if start { receive() }
        return known
    }

    /// Send end of stream (FIN) after what was sent before. Not under TLS:
    /// Network.framework's TLS takes a final send and says it went, but the
    /// peer sees no end of stream until the connection is closed, so a
    /// half-close there would leave both ends waiting. `.unsupported`.
    func shutdownWrite() throws(IOError) {
        if isTLS { throw .unsupported }
        connection.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .idempotent)
    }

    /// Whether Network.framework runs TLS on this connection.
    var isTLS: Bool {
        connection.parameters.defaultProtocolStack.applicationProtocols.contains { $0 is NWProtocolTLS.Options }
    }
}

/// A listener: connections Network.framework hands over queue here until
/// `accept` takes them.
final class NetworkAcceptor: NetworkHandle, @unchecked Sendable {
    let listener: NWListener
    private let lock = RawLock()
    private var pending: [NWConnection] = []
    private var failure: IOError?
    /// Accepts waiting, oldest first (several accept loops can share one).
    private var waiters: [Rendezvous<Bool>] = []

    init(_ listener: NWListener) {
        self.listener = listener
    }

    deinit { lock.destroy() }

    /// Start listening and wait until it is ready, or failed.
    func start() -> IOError? {
        let ready = DispatchSemaphore(value: 0)
        let first = StartResult() // touched on the listener's queue only
        listener.stateUpdateHandler = { [self] state in
            switch state {
            case .ready:
                if !first.signalled { first.signalled = true; ready.signal() }
            case .failed(let e), .waiting(let e):
                let error = NetworkIO.map(e)
                if !first.signalled {
                    first.error = error
                    first.signalled = true
                    ready.signal()
                }
                lock.lock()
                failure = error
                let all = waiters
                waiters.removeAll()
                lock.unlock()
                for w in all { w.offer(true) }
            default: break
            }
        }
        listener.newConnectionHandler = { [self] connection in
            lock.lock()
            pending.append(connection)
            let w = waiters.isEmpty ? nil : waiters.removeFirst()
            lock.unlock()
            w?.offer(true)
        }
        listener.start(queue: queue)
        if ready.wait(timeout: .now() + .seconds(10)) == .timedOut {
            listener.cancel()
            return IOError(code: ETIMEDOUT)
        }
        // The handler set these on the listener's queue before signalling.
        return queue.sync { first.error }
    }

    private final class StartResult: @unchecked Sendable {
        var signalled = false
        var error: IOError?
    }

    var port: Int { Int(listener.port?.rawValue ?? 0) }

    /// Stop listening before returning, as close(2) does: a connect right
    /// after is refused. Waits for Network.framework (well under a second).
    override func close() {
        let cancelled = DispatchSemaphore(value: 0)
        listener.newConnectionHandler = nil
        listener.stateUpdateHandler = { state in
            if case .cancelled = state { cancelled.signal() }
        }
        listener.cancel()
        _ = cancelled.wait(timeout: .now() + .seconds(1))
        lock.lock()
        let left = pending
        pending.removeAll()
        lock.unlock()
        for c in left { c.cancel() }
    }

    func accept() async throws(IOError) -> IORegistration {
        while true {
            lock.lock()
            if !pending.isEmpty {
                let connection = pending.removeFirst()
                lock.unlock()
                let stream = NetworkStream(connection)
                stream.watch()
                connection.start(queue: stream.queue)
                await Runtime.consumeBudget()
                return NetworkIO.registration(for: stream)
            }
            if let failure {
                lock.unlock()
                throw failure
            }
            let r = Rendezvous<Bool>()
            waiters.append(r)
            lock.unlock()
            guard await r.wait(cancelled: false) else {
                lock.lock()
                waiters.removeAll { $0 === r }
                lock.unlock()
                throw .interrupted
            }
        }
    }
}

extension IORegistration {
    /// A Network.framework socket's registration (`NetworkIO.registration`).
    init(io: UnsafeMutablePointer<cv_io>, nw: UnsafeRawPointer) {
        self.io = io
        driver = nil
        owner = nil
        self.nw = nw
    }

    /// The Network.framework operations behind the fd-backed ones in
    /// Stream.swift, which branch here when `nw` is set.
    func nwRead(into buffer: inout IOBuffer, _ nw: UnsafeRawPointer) async throws(IOError) -> Int {
        try await (NetworkIO.handle(nw) as! NetworkStream).read(into: &buffer)
    }

    func nwWrite(_ nw: UnsafeRawPointer, parts count: Int, _ part: (Int) -> UnsafeRawBufferPointer) async throws(IOError) {
        var data = Data()
        for i in 0..<count { data.append(contentsOf: part(i)) }
        guard !data.isEmpty else { return }
        let stream = NetworkIO.handle(nw) as! NetworkStream
        // There is no readiness to wait for here: under
        // `Runtime.withWriteStallTimeout`, and no deadline of its own, the
        // send goes in slices, each given the limit, so a peer that keeps
        // taking bytes keeps the write going and one that takes none for
        // the limit stops it, as `wait(CV_IO_WRITE)` does on a socket.
        // Network.framework finishes a send only once all of it is taken.
        if let stall = WriteStall.active, IODeadline.active == nil {
            let slice = 64 * 1024
            var start = data.startIndex
            while start < data.endIndex {
                let end = min(start + slice, data.endIndex)
                let part = data[start..<end]
                try await Runtime.withIOTimeout(for: .nanoseconds(Int64(clamping: stall))) { () async throws(IOError) in
                    try await stream.write(part)
                }
                start = end
            }
            return
        }
        try await stream.write(data)
    }

    func nwAccept(_ nw: UnsafeRawPointer) async throws(IOError) -> IORegistration {
        try await (NetworkIO.handle(nw) as! NetworkAcceptor).accept()
    }

    func nwWaitReadable(_ nw: UnsafeRawPointer) async throws(IOError) -> Bool {
        try await (NetworkIO.handle(nw) as! NetworkStream).waitReadable()
    }

    func nwHasPendingInput(_ nw: UnsafeRawPointer) -> Bool {
        (NetworkIO.handle(nw) as? NetworkStream)?.hasPendingInput ?? false
    }

    func nwShutdownWrite(_ nw: UnsafeRawPointer) throws(IOError) {
        try (NetworkIO.handle(nw) as? NetworkStream)?.shutdownWrite()
    }

    func nwAddress(_ nw: UnsafeRawPointer, local: Bool) throws(IOError) -> SocketAddress {
        switch NetworkIO.handle(nw) {
        case let s as NetworkStream:
            let path = s.connection.currentPath
            return try NetworkIO.address(local ? path?.localEndpoint : path?.remoteEndpoint)
        case let a as NetworkAcceptor:
            guard local else { throw IOError(code: ENOTCONN) }
            return try SocketAddress(host: "::", port: a.port)
        default:
            throw IOError(code: ENOTSOCK)
        }
    }

    var nwPort: Int? {
        guard let nw else { return nil }
        return (NetworkIO.handle(nw) as? NetworkAcceptor)?.port
    }

    /// Another owner of this Network.framework socket, as `split` makes:
    /// more accept loops on one listener.
    func nwShared() -> IORegistration {
        cv_io_ref(io, 1)
        return self
    }

    /// Options are fixed when a Network.framework socket is made: reading
    /// one gives that value, and setting one to it changes nothing.
    func nwOption(_ nw: UnsafeRawPointer, _ option: SocketOption) throws(IOError) -> Int {
        switch NetworkIO.handle(nw) {
        case let s as NetworkStream: return try NetworkIO.option(option, of: s.connection.parameters)
        case let a as NetworkAcceptor: return try NetworkIO.option(option, of: a.listener.parameters)
        default: throw .unsupported
        }
    }

    func nwSetOption(_ nw: UnsafeRawPointer, _ option: SocketOption, _ value: Int) throws(IOError) {
        let current = try nwOption(nw, option)
        let same = option == .noDelay || option == .keepAlive || option == .fastOpen ||
            option == .reuseAddress || option == .reusePort ? (current != 0) == (value != 0) : current == value
        if !same { throw .unsupported }
    }
}
#endif
