// VegaCrypto's platforms and traits only: QUIC's TLS 1.3 is built on it.
#if (os(Linux) || os(macOS) || os(Windows)) && (OpenSSL || BoringSSL)
import Synchronization
import Vega
import VegaIO
@_spi(Garuda) import VegaQUICCore

/// Why a QUIC connection or stream operation failed.
///
/// A struct rather than an enum, so that kinds of failure can be added
/// without breaking anyone's exhaustive `switch`: switch over `code`, or
/// compare the error itself where its kind carries nothing more
/// (`catch QUICConnectionError.endpointClosed`, `error == .endpointClosed`).
public struct QUICConnectionError: Error, Hashable, Sendable, CustomStringConvertible {
    /// What kind of failure this is.
    public let code: Code
    public let errorCode: UInt64?
    public let isApplicationError: Bool
    public let ioError: IOError?

    /// The kinds of `QUICConnectionError`.
    public struct Code: Hashable, Sendable, CustomStringConvertible {
        let rawValue: UInt8

        /// The connection is closed by either side, with `errorCode`
        /// (`isApplicationError` says whose code it is: the protocol above
        /// QUIC's, or QUIC's own).
        public static let connectionClosed = Code(rawValue: 0)
        /// The peer reset the stream, with `errorCode`: it won't send the rest.
        public static let streamReset = Code(rawValue: 1)
        /// The peer asked us to stop sending on the stream, with `errorCode`.
        public static let stopSending = Code(rawValue: 2)
        /// The endpoint has shut down.
        public static let endpointClosed = Code(rawValue: 3)
        /// The socket under the endpoint failed.
        public static let io = Code(rawValue: 4)
        /// The peer went quiet past the idle timeout (or, connecting, never
        /// answered).
        public static let idleTimeout = Code(rawValue: 5)
        /// The handshake failed, and QUIC closed the connection with
        /// `errorCode`: 0x100 plus the TLS alert, 0x12a when the certificate
        /// was refused.
        public static let handshakeFailed = Code(rawValue: 6)
        /// The waiting task was cancelled.
        public static let cancelled = Code(rawValue: 7)

        public var description: String {
            let names = ["connectionClosed", "streamReset", "stopSending", "endpointClosed", "io",
                         "idleTimeout", "handshakeFailed", "cancelled"]
            return Int(rawValue) < names.count ? names[Int(rawValue)] : "code \(rawValue)"
        }
    }

    init(_ code: Code, errorCode: UInt64? = nil, isApplicationError: Bool = false, ioError: IOError? = nil) {
        self.code = code
        self.errorCode = errorCode
        self.isApplicationError = isApplicationError
        self.ioError = ioError
    }

    /// The connection is closed by either side, with `errorCode`
    /// (`isApplicationError` says whose code it is: the protocol above
    /// QUIC's, or QUIC's own).
    public static func connectionClosed(code errorCode: UInt64, application isApplicationError: Bool) -> QUICConnectionError { QUICConnectionError(.connectionClosed, errorCode: errorCode, isApplicationError: isApplicationError) }
    /// The peer reset the stream, with `errorCode`: it won't send the rest.
    public static func streamReset(code errorCode: UInt64) -> QUICConnectionError { QUICConnectionError(.streamReset, errorCode: errorCode) }
    /// The peer asked us to stop sending on the stream, with `errorCode`.
    public static func stopSending(code errorCode: UInt64) -> QUICConnectionError { QUICConnectionError(.stopSending, errorCode: errorCode) }
    /// The endpoint has shut down.
    public static let endpointClosed = QUICConnectionError(.endpointClosed)
    /// The socket under the endpoint failed.
    public static func io(_ ioError: IOError) -> QUICConnectionError { QUICConnectionError(.io, ioError: ioError) }
    /// The peer went quiet past the idle timeout (or, connecting, never
    /// answered).
    public static let idleTimeout = QUICConnectionError(.idleTimeout)
    /// The handshake failed, and QUIC closed the connection with `errorCode`:
    /// 0x100 plus the TLS alert, 0x12a when the certificate was refused.
    public static func handshakeFailed(code errorCode: UInt64) -> QUICConnectionError { QUICConnectionError(.handshakeFailed, errorCode: errorCode) }
    /// The waiting task was cancelled.
    public static let cancelled = QUICConnectionError(.cancelled)

    public var description: String {
        switch code {
        case .connectionClosed: "connection closed (\(isApplicationError ? "application" : "transport") code \(errorCode!))"
        case .streamReset: "stream reset by the peer (code \(errorCode!))"
        case .stopSending: "the peer asked to stop sending (code \(errorCode!))"
        case .endpointClosed: "the endpoint is closed"
        case .io: "\(ioError!)"
        case .idleTimeout: "the connection timed out, idle"
        case .handshakeFailed: "the handshake failed (code \(errorCode!))"
        case .cancelled: "cancelled"
        default: "\(code)"
        }
    }

    /// As an `IOError`, for `AsyncReader` and `AsyncWriter`.
    var asIOError: IOError {
        switch code {
        case .connectionClosed, .streamReset: .connectionReset
        case .stopSending: .brokenPipe
        case .endpointClosed, .cancelled: .cancelled
        case .idleTimeout: .timedOut
        default: ioError ?? .connectionReset
        }
    }
}

/// One QUIC connection, server or client side, as its tasks see it. The
/// endpoint's task owns the transport; this hands work to it.
public final class QUICConnection: Sendable {
    typealias Open = (id: UInt64, unidirectional: Bool, waiter: UnsafeContinuation<Result<QUICStream, QUICConnectionError>, Never>)

    struct State {
        var incoming: [QUICStream] = []
        var acceptWaiter: UnsafeContinuation<QUICStream?, Never>?
        var opens: [Open] = []
        var nextOpen: UInt64 = 0
        /// Opens cancelled while the endpoint held them: failed when it
        /// gives them back.
        var cancelledOpens: Set<UInt64> = []
        var closed: QUICConnectionError?
        var alpn: [UInt8] = []
        var serverName = ""
        var handshakeWaiter: UnsafeContinuation<Result<Void, QUICConnectionError>, Never>?
        var established = false
    }

    let endpoint: QUICEndpoint
    /// The endpoint task's side: only that task touches it.
    nonisolated(unsafe) let core: EndpointConnection
    let state = Locked(State())
    /// Where the peer was when the connection began.
    public let remoteAddress: SocketAddress

    init(endpoint: QUICEndpoint, core: EndpointConnection, remoteAddress: SocketAddress) {
        self.endpoint = endpoint
        self.core = core
        self.remoteAddress = remoteAddress
    }

    /// The application protocol the handshake agreed on (ALPN).
    public var applicationProtocol: String { state.withLock { String(decoding: $0.alpn, as: UTF8.self) } }

    /// The server name the client asked for (SNI): on a client, the one in
    /// its configuration.
    public var serverName: String { state.withLock { $0.serverName } }

    /// Why the connection ended, once it has.
    public var closeReason: QUICConnectionError? { state.withLock { $0.closed } }

    /// The next stream the peer opened; nil once the connection is closed.
    public func acceptStream() async -> QUICStream? {
        await withUnsafeContinuation { (c: UnsafeContinuation<QUICStream?, Never>) in
            let now = state.withLock { s -> (Bool, QUICStream?) in
                if !s.incoming.isEmpty { return (true, s.incoming.removeFirst()) }
                if s.closed != nil { return (true, nil) }
                precondition(s.acceptWaiter == nil, "QUICConnection.acceptStream() called while another call waits")
                s.acceptWaiter = c
                return (false, nil)
            }
            if now.0 { c.resume(returning: now.1) }
        }
    }

    /// Open a stream, waiting while the peer allows no more. Throws
    /// `.cancelled` if the task is cancelled first.
    public func openStream(unidirectional: Bool = false) async throws(QUICConnectionError) -> QUICStream {
        let id = state.withLock { s in
            defer { s.nextOpen &+= 1 }
            return s.nextOpen
        }
        let result = await withTaskCancellationHandler {
            await withUnsafeContinuation { (c: UnsafeContinuation<Result<QUICStream, QUICConnectionError>, Never>) in
                let failed = state.withLock { s -> QUICConnectionError? in
                    // Checked under the lock: either the cancel handler runs
                    // after this and finds the open, or the flag is visible.
                    if Task.isCancelled { return .cancelled }
                    if let closed = s.closed { return closed }
                    s.opens.append((id, unidirectional, c))
                    return nil
                }
                if let failed { c.resume(returning: .failure(failed)) } else { endpoint.post(.open(self)) }
            }
        } onCancel: {
            let waiter = state.withLock { s -> UnsafeContinuation<Result<QUICStream, QUICConnectionError>, Never>? in
                guard let i = s.opens.firstIndex(where: { $0.id == id }) else {
                    // The endpoint has it, or it is done: fail it if it comes back.
                    s.cancelledOpens.insert(id)
                    return nil
                }
                return s.opens.remove(at: i).waiter
            }
            waiter?.resume(returning: .failure(.cancelled))
        }
        return try result.get()
    }

    /// Close the connection with an application error code (0 for none).
    /// Streams' waiting reads and writes fail; the peer is told at once.
    public func close(code: UInt64 = 0, reason: String = "") {
        endpoint.post(.close(self, code, Array(reason.utf8)))
    }

    // MARK: From the endpoint

    func deliver(_ stream: QUICStream) {
        let waiter = state.withLock { s -> UnsafeContinuation<QUICStream?, Never>? in
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
    func takeOpens() -> [Open] {
        state.withLock { s in
            defer { s.opens.removeAll() }
            return s.opens
        }
    }

    func requeue(_ open: Open) {
        let cancelled = state.withLock { s -> Bool in
            if s.cancelledOpens.remove(open.id) != nil { return true }
            s.opens.append(open)
            return false
        }
        if cancelled { open.waiter.resume(returning: .failure(.cancelled)) }
    }

    /// An open the endpoint has answered: no longer cancellable.
    func opened(_ open: Open) {
        state.withLock { s in
            if !s.cancelledOpens.isEmpty { s.cancelledOpens.remove(open.id) }
        }
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
public final class QUICStream: AsyncReader, AsyncWriter, Sendable {
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
    let connection: QUICConnection
    let state = Locked(State())

    init(id: UInt64, connection: QUICConnection) {
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
            case .failed(let error): throw error.asIOError
            case nil: break
            }
            if buffer.spareCapacity == 0 { throw IOError.readIntoFullBuffer }
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
            if all.count > limit { throw IOError(code: IOError.limitExceeded.code, message: "QUIC stream longer than \(limit) bytes") }
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
            precondition(!s.finQueued && s.resetQueued == nil, "QUICStream.write after finish() or reset()")
            s.outbox.append(contentsOf: bytes)
            let post = !s.posted
            s.posted = true
            return (nil, post, s.outbox.count - s.outStart > Self.highWater)
        }
    }

    private func queued(_ outcome: (error: QUICConnectionError?, post: Bool, wait: Bool)) async throws(IOError) {
        if let error = outcome.error { throw error.asIOError }
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
        if let error = state.withLock({ $0.writeEnd }) { throw error.asIOError }
    }

    /// `finish()`, as `AsyncWriter` names it.
    public func shutdownWrite() { finish() }

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
