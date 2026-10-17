// VegaCrypto's platforms and traits only: QUIC's TLS 1.3 is built on it.
#if (os(Linux) || os(macOS) || os(Windows)) && (OpenSSL || BoringSSL)
import Synchronization
import Vega
import VegaIO
import VegaQUIC

/// Why a QUIC connection or stream stopped.
public enum QUICConnectionError: Error, Hashable, Sendable, CustomStringConvertible {
    /// The connection is closed: by either side (`application` says whose
    /// code it is: the protocol above QUIC's, or QUIC's own), or because the
    /// peer went quiet past the idle timeout.
    case connectionClosed(code: UInt64, application: Bool)
    /// The peer reset the stream: it won't send the rest.
    case streamReset(code: UInt64)
    /// The peer asked us to stop sending on the stream.
    case stopSending(code: UInt64)
    /// The endpoint has shut down.
    case endpointClosed
    /// The socket under the endpoint failed.
    case io(IOError)

    public var description: String {
        switch self {
        case .connectionClosed(let code, let application):
            "connection closed (\(application ? "application" : "transport") code \(code))"
        case .streamReset(let code): "stream reset by the peer (code \(code))"
        case .stopSending(let code): "the peer asked to stop sending (code \(code))"
        case .endpointClosed: "the endpoint is closed"
        case .io(let error): "\(error)"
        }
    }

    /// As an `IOError`, for `AsyncReader` and `AsyncWriter`.
    var ioError: IOError {
        switch self {
        case .connectionClosed, .streamReset: .connectionReset
        case .stopSending: .brokenPipe
        case .endpointClosed: .cancelled
        case .io(let error): error
        }
    }
}

/// One QUIC connection, server or client side, as its tasks see it. The
/// endpoint's task owns the transport; this hands work to it.
public final class QUICConnectionHandle: Sendable {
    struct State {
        var incoming: [QUICStreamHandle] = []
        var acceptWaiter: UnsafeContinuation<QUICStreamHandle?, Never>?
        var opens: [(unidirectional: Bool, waiter: UnsafeContinuation<Result<QUICStreamHandle, QUICConnectionError>, Never>)] = []
        var closed: QUICConnectionError?
        var alpn: [UInt8] = []
        var serverName = ""
        var handshakeWaiter: UnsafeContinuation<Result<Void, QUICConnectionError>, Never>?
        var established = false
    }

    let endpoint: QUICEndpoint
    /// The endpoint task's side: only that task touches it.
    nonisolated(unsafe) let core: EndpointConnection
    let state = Mutex(State())
    /// Where the peer was when the connection began.
    public let remoteAddress: SocketAddress

    init(endpoint: QUICEndpoint, core: EndpointConnection, remoteAddress: SocketAddress) {
        self.endpoint = endpoint
        self.core = core
        self.remoteAddress = remoteAddress
    }

    /// The application protocol the handshake agreed on (ALPN).
    public var alpn: [UInt8] { state.withLock { $0.alpn } }

    /// The server name the client asked for (SNI): on a client, the one in
    /// its configuration.
    public var serverName: String { state.withLock { $0.serverName } }

    /// Why the connection ended, once it has.
    public var closeReason: QUICConnectionError? { state.withLock { $0.closed } }

    /// The next stream the peer opened; nil once the connection is closed.
    public func acceptStream() async -> QUICStreamHandle? {
        await withUnsafeContinuation { (c: UnsafeContinuation<QUICStreamHandle?, Never>) in
            let now = state.withLock { s -> (Bool, QUICStreamHandle?) in
                if !s.incoming.isEmpty { return (true, s.incoming.removeFirst()) }
                if s.closed != nil { return (true, nil) }
                precondition(s.acceptWaiter == nil, "QUICConnectionHandle.acceptStream() called while another call waits")
                s.acceptWaiter = c
                return (false, nil)
            }
            if now.0 { c.resume(returning: now.1) }
        }
    }

    /// Open a stream, waiting while the peer allows no more.
    public func openStream(unidirectional: Bool = false) async throws(QUICConnectionError) -> QUICStreamHandle {
        let result = await withUnsafeContinuation { (c: UnsafeContinuation<Result<QUICStreamHandle, QUICConnectionError>, Never>) in
            let failed = state.withLock { s -> QUICConnectionError? in
                if let closed = s.closed { return closed }
                s.opens.append((unidirectional, c))
                return nil
            }
            if let failed { c.resume(returning: .failure(failed)) } else { endpoint.post(.open(self)) }
        }
        return try result.get()
    }

    /// Close the connection with an application error code (0 for none).
    /// Streams' waiting reads and writes fail; the peer is told at once.
    public func close(code: UInt64 = 0, reason: String = "") {
        endpoint.post(.close(self, code, Array(reason.utf8)))
    }

    // MARK: From the endpoint

    func deliver(_ stream: QUICStreamHandle) {
        let waiter = state.withLock { s -> UnsafeContinuation<QUICStreamHandle?, Never>? in
            if let w = s.acceptWaiter {
                s.acceptWaiter = nil
                return w
            }
            s.incoming.append(stream)
            return nil
        }
        waiter?.resume(returning: stream)
    }

    func established(alpn: [UInt8], serverName: String) {
        let waiter = state.withLock { s -> UnsafeContinuation<Result<Void, QUICConnectionError>, Never>? in
            s.alpn = alpn
            s.serverName = serverName
            s.established = true
            defer { s.handshakeWaiter = nil }
            return s.handshakeWaiter
        }
        waiter?.resume(returning: .success(()))
    }

    /// Wait for the handshake (a client's connect).
    func handshake() async throws(QUICConnectionError) {
        let result = await withUnsafeContinuation { (c: UnsafeContinuation<Result<Void, QUICConnectionError>, Never>) in
            let now = state.withLock { s -> Result<Void, QUICConnectionError>? in
                if s.established { return .success(()) }
                if let closed = s.closed { return .failure(closed) }
                s.handshakeWaiter = c
                return nil
            }
            if let now { c.resume(returning: now) }
        }
        try result.get()
    }

    /// Opens waiting for the peer's stream limit, for the endpoint to try.
    func takeOpens() -> [(unidirectional: Bool, waiter: UnsafeContinuation<Result<QUICStreamHandle, QUICConnectionError>, Never>)] {
        state.withLock { s in
            defer { s.opens.removeAll() }
            return s.opens
        }
    }

    func requeue(_ open: (unidirectional: Bool, waiter: UnsafeContinuation<Result<QUICStreamHandle, QUICConnectionError>, Never>)) {
        state.withLock { $0.opens.append(open) }
    }

    func fail(_ error: QUICConnectionError) {
        let (accept, opens, handshake) = state.withLock { s in
            if s.closed == nil { s.closed = error }
            defer {
                s.acceptWaiter = nil
                s.opens.removeAll()
                s.handshakeWaiter = nil
            }
            return (s.acceptWaiter, s.opens, s.handshakeWaiter)
        }
        accept?.resume(returning: nil)
        for open in opens { open.waiter.resume(returning: .failure(error)) }
        handshake?.resume(returning: .failure(error))
    }
}

/// One QUIC stream: `AsyncReader` and `AsyncWriter`, so `FramedRead`,
/// `FramedWrite` and the rest of VegaIO work over it.
///
/// Reads give the peer more room as they take bytes (flow control); a
/// write waits while too much is queued for the peer to take. Read to the
/// end (a read of 0) and `finish()`, or `close()`, so the endpoint can let
/// the stream go.
public final class QUICStreamHandle: AsyncReader, AsyncWriter, Sendable {
    /// Bytes queued for sending past which a write waits, and the level a
    /// waiting write goes on at.
    static let highWater = 256 * 1024
    static let lowWater = 64 * 1024

    enum ReadEnd {
        case fin
        case failed(QUICConnectionError)
    }

    struct State {
        var inbox: [UInt8] = []
        var inStart = 0
        var readEnd: ReadEnd?
        var reader: UnsafeContinuation<Void, Never>?
        /// Bytes the application has taken, all told.
        var consumed: UInt64 = 0
        var outbox: [UInt8] = []
        var outStart = 0
        var finQueued = false
        var resetQueued: UInt64?
        var stopQueued: UInt64?
        var writeEnd: QUICConnectionError?
        var writer: UnsafeContinuation<Void, Never>?
        /// On the endpoint's list already.
        var posted = false
    }

    /// The stream ID: its low bits say who opened it and whether it's
    /// unidirectional (RFC 9000 section 2.1).
    public let id: UInt64
    let connection: QUICConnectionHandle
    let state = Mutex(State())

    init(id: UInt64, connection: QUICConnectionHandle) {
        self.id = id
        self.connection = connection
    }

    public var isUnidirectional: Bool { id & 0x2 != 0 }

    /// Why reading or writing stopped, if one did with an error.
    public var error: QUICConnectionError? {
        state.withLock { s in
            if case .failed(let e) = s.readEnd { return e }
            return s.writeEnd
        }
    }

    // MARK: Reading

    /// Read into `buffer`'s spare capacity: the bytes read, 0 at the end of
    /// the stream. A reset stream or a closed connection throws
    /// `.connectionReset` (`error` says which).
    public func read(into buffer: inout IOBuffer) async throws(IOError) -> Int {
        while true {
            let outcome = state.withLock { s -> (n: Int, end: ReadEnd?, post: Bool) in
                let held = s.inbox.count - s.inStart
                if held > 0 {
                    let n = min(held, buffer.spareCapacity)
                    let start = s.inStart
                    _ = s.inbox.withUnsafeBytes { buffer.append(UnsafeRawBufferPointer(rebasing: $0[start..<(start + n)])) }
                    s.inStart += n
                    if s.inStart == s.inbox.count {
                        s.inbox.removeAll(keepingCapacity: true)
                        s.inStart = 0
                    }
                    s.consumed += UInt64(n)
                    let post = !s.posted
                    s.posted = true
                    return (n, nil, post)
                }
                return (0, s.readEnd, false)
            }
            if outcome.n > 0 {
                if outcome.post { connection.endpoint.post(.stream(self)) }
                return outcome.n
            }
            switch outcome.end {
            case .fin: return 0
            case .failed(let error): throw error.ioError
            case nil: break
            }
            if buffer.spareCapacity == 0 { return 0 }
            try await waitToRead()
        }
    }

    private func waitToRead() async throws(IOError) {
        let cancelled: Bool = await withTaskCancellationHandler {
            await withUnsafeContinuation { (c: UnsafeContinuation<Void, Never>) in
                let wait = state.withLock { s -> Bool in
                    if s.inbox.count > s.inStart || s.readEnd != nil || Task.isCancelled { return false }
                    s.reader = c
                    return true
                }
                if !wait { c.resume() }
            }
            return Task.isCancelled
        } onCancel: {
            let waiter = state.withLock { s in
                defer { s.reader = nil }
                return s.reader
            }
            waiter?.resume()
        }
        if cancelled { throw .cancelled }
    }

    /// Everything until the end of the stream.
    public func readAll(limit: Int = .max) async throws(IOError) -> [UInt8] {
        var all: [UInt8] = []
        var buffer = IOBuffer(capacity: 16 * 1024)
        while true {
            buffer.clear()
            let n = try await read(into: &buffer)
            if n == 0 { return all }
            buffer.withUnsafeBytes { all.append(contentsOf: $0) }
            if all.count > limit { throw IOError(code: -6, message: "QUIC stream longer than \(limit) bytes") }
        }
    }

    /// Tell the peer to stop sending (STOP_SENDING); reads end with an error.
    public func stopSending(code: UInt64 = 0) {
        let (post, reader) = state.withLock { s in
            s.stopQueued = code
            if s.readEnd == nil { s.readEnd = .failed(.streamReset(code: code)) }
            s.inbox.removeAll()
            s.inStart = 0
            let post = !s.posted
            s.posted = true
            defer { s.reader = nil }
            return (post, s.reader)
        }
        reader?.resume()
        if post { connection.endpoint.post(.stream(self)) }
    }

    // MARK: Writing

    /// Queue all of `bytes` for sending, waiting while too much is queued.
    public func write(_ bytes: UnsafeRawBufferPointer) async throws(IOError) {
        try await queued(enqueue(bytes))
    }

    /// `write`, from an array.
    public func write(_ bytes: [UInt8]) async throws(IOError) {
        try await queued(bytes.withUnsafeBytes { enqueue($0) })
    }

    private func enqueue(_ bytes: UnsafeRawBufferPointer) -> (error: QUICConnectionError?, post: Bool, wait: Bool) {
        state.withLock { s -> (QUICConnectionError?, Bool, Bool) in
            if let e = s.writeEnd { return (e, false, false) }
            precondition(!s.finQueued && s.resetQueued == nil, "QUICStreamHandle.write after finish() or reset()")
            s.outbox.append(contentsOf: bytes)
            let post = !s.posted
            s.posted = true
            return (nil, post, s.outbox.count - s.outStart > Self.highWater)
        }
    }

    private func queued(_ outcome: (error: QUICConnectionError?, post: Bool, wait: Bool)) async throws(IOError) {
        if let error = outcome.error { throw error.ioError }
        if outcome.post { connection.endpoint.post(.stream(self)) }
        if outcome.wait { try await waitToWrite() }
    }

    private func waitToWrite() async throws(IOError) {
        let cancelled: Bool = await withTaskCancellationHandler {
            await withUnsafeContinuation { (c: UnsafeContinuation<Void, Never>) in
                let wait = state.withLock { s -> Bool in
                    if s.outbox.count - s.outStart <= Self.lowWater || s.writeEnd != nil || Task.isCancelled { return false }
                    s.writer = c
                    return true
                }
                if !wait { c.resume() }
            }
            return Task.isCancelled
        } onCancel: {
            let waiter = state.withLock { s in
                defer { s.writer = nil }
                return s.writer
            }
            waiter?.resume()
        }
        if cancelled { throw .cancelled }
        if let error = state.withLock({ $0.writeEnd }) { throw error.ioError }
    }

    /// End the stream (FIN) once what is queued has gone.
    public func finish() {
        let post = state.withLock { s -> Bool in
            s.finQueued = true
            let post = !s.posted
            s.posted = true
            return post
        }
        if post { connection.endpoint.post(.stream(self)) }
    }

    /// Abandon sending (RESET_STREAM): what is queued is dropped.
    public func reset(code: UInt64 = 0) {
        let post = state.withLock { s -> Bool in
            s.resetQueued = code
            s.outbox.removeAll()
            s.outStart = 0
            let post = !s.posted
            s.posted = true
            return post
        }
        if post { connection.endpoint.post(.stream(self)) }
    }

    /// `finish()`, and `stopSending()` if the peer's side hasn't ended.
    public func close() {
        let reading = state.withLock { $0.readEnd == nil }
        if !isUnidirectional || QUICStreamKind.isClientInitiated(id) != connection.core.isServer {
            if state.withLock({ $0.writeEnd == nil && !$0.finQueued && $0.resetQueued == nil }) { finish() }
        }
        if reading { stopSending() }
    }

    // MARK: From the endpoint

    /// The peer's bytes, in order.
    func received(_ p: UnsafePointer<UInt8>, _ n: Int) {
        let reader = state.withLock { s -> UnsafeContinuation<Void, Never>? in
            if s.stopQueued == nil { s.inbox.append(contentsOf: UnsafeBufferPointer(start: p, count: n)) }
            defer { s.reader = nil }
            return s.reader
        }
        reader?.resume()
    }

    func endRead(_ end: ReadEnd) {
        let reader = state.withLock { s -> UnsafeContinuation<Void, Never>? in
            if s.readEnd == nil { s.readEnd = end }
            defer { s.reader = nil }
            return s.reader
        }
        reader?.resume()
    }

    func endWrite(_ error: QUICConnectionError) {
        let writer = state.withLock { s -> UnsafeContinuation<Void, Never>? in
            if s.writeEnd == nil { s.writeEnd = error }
            s.outbox.removeAll()
            s.outStart = 0
            defer { s.writer = nil }
            return s.writer
        }
        writer?.resume()
    }

    func fail(_ error: QUICConnectionError) {
        endRead(.failed(error))
        endWrite(error)
    }
}
#endif
