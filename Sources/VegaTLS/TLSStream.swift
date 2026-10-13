// On the OpenSSL or BoringSSL trait; not on iOS, tvOS, watchOS or visionOS.
#if (os(Linux) || os(macOS) || os(Windows)) && (OpenSSL || BoringSSL)
import CVegaTLS
import Synchronization
import Vega
import VegaIO

/// TLS over any Vega byte stream: tokio-rustls's `TlsStream`. It is itself
/// an `AsyncReader` and `AsyncWriter`, so codecs and `Framed` run over it
/// unchanged.
///
/// ```swift
/// let tcp = try await TCPStream.connect(host: "example.com", port: 443)
/// let tls = try await TLSStream.connect(tcp, serverName: "example.com", context: client)
/// try await tls.write(request)
///
/// let conn = try await listener.accept()
/// let tls = try await TLSStream.accept(conn.stream, context: server)
/// ```
///
/// The TLS library (the system's OpenSSL) never sees the socket: ciphertext
/// moves through memory, read and written by this value on the transport.
/// Failures throw `IOError.tls` with OpenSSL's reason as the message; a
/// peer that closes without close_notify throws `IOError.tlsTruncated` (a
/// read that returns 0 means a clean close). One task at a time reads and
/// writes; `split(_:)` gives a reader and a writer for two tasks.
public struct TLSStream<Transport: AsyncReader & AsyncWriter & ~Copyable>: ~Copyable {
    private let transport: Transport
    private let state: TLSState

    private init(transport: consuming Transport, state: TLSState) {
        self.transport = transport
        self.state = state
    }

    /// Be the client: handshake with the server at the other end of
    /// `transport`. `serverName` is sent (SNI) and the certificate checked
    /// against it; an IP address is checked as one and not sent.
    public static func connect(_ transport: consuming Transport, serverName: String?,
                               context: TLSContext) async throws(IOError) -> TLSStream {
        guard context.configuration.role == .client else {
            throw IOError(code: IOError.tls.code, message: "connect needs a client context")
        }
        let stream = TLSStream(transport: transport, state: try TLSState(context, host: serverName))
        try await stream.handshake()
        return stream
    }

    /// Be the server: handshake with the client at the other end.
    public static func accept(_ transport: consuming Transport, context: TLSContext) async throws(IOError) -> TLSStream {
        guard context.configuration.role == .server else {
            throw IOError(code: IOError.tls.code, message: "accept needs a server context")
        }
        let stream = TLSStream(transport: transport, state: try TLSState(context, host: nil))
        try await stream.handshake()
        return stream
    }

    // MARK: - What was agreed

    /// The ALPN protocol chosen, if any.
    public var applicationProtocol: String? { state.string(cv_tls_alpn) }
    /// The server name the client asked for (SNI), if any.
    public var serverName: String? { state.string(cv_tls_server_name) }
    public var version: TLSConfiguration.Version? { TLSConfiguration.Version(rawValue: UInt16(cv_tls_version(state.tls))) }
    /// Whether an earlier session was resumed (no full handshake).
    public var isResumed: Bool { cv_tls_resumed(state.tls) != 0 }
    /// The peer's certificate as DER, if it sent one.
    public var peerCertificate: [UInt8]? {
        let n = Int(cv_tls_peer_certificate(state.tls, nil, 0))
        guard n > 0 else { return nil }
        var der = [UInt8](repeating: 0, count: n)
        _ = cv_tls_peer_certificate(state.tls, &der, Int32(n))
        return der
    }

    // MARK: - Data

    /// Read plaintext into `buffer`'s spare capacity: the bytes read, or 0
    /// once the peer has closed with close_notify (or with a full buffer).
    public func read(into buffer: inout IOBuffer) async throws(IOError) -> Int {
        guard buffer.spareCapacity > 0 else { return 0 }
        while true {
            let n = state.decrypt(into: &buffer)
            if n < 0 && n != Int(CV_TLS_WANT_READ) {
                // An alert may be queued for a peer that's gone: best effort.
                try? await flush()
            } else {
                // Reading can answer the peer (a key update): send that first.
                try await flush()
            }
            switch n {
            case Int(CV_TLS_WANT_READ):
                try await state.fill(from: transport)
            default:
                if let n = try state.result(n, buffer: &buffer) { return n }
            }
        }
    }

    /// Encrypt and send all of `bytes`.
    public func write(_ bytes: UnsafeRawBufferPointer) async throws(IOError) {
        try await state.write(bytes, to: transport)
    }

    public func write(_ buffer: borrowing IOBuffer) async throws(IOError) {
        try await write(buffer.withUnsafeBytes { $0 })
    }

    /// Send close_notify, then give back the transport (to shut down or
    /// close). The peer's reads then return 0.
    public consuming func close() async throws(IOError) -> Transport {
        state.locked { cv_tls_close(state.tls) }
        try await flush()
        return transport
    }

    // MARK: - Moving ciphertext

    private func handshake() async throws(IOError) {
        while true {
            let r = cv_tls_handshake(state.tls)
            try await flush() // our flight, or the alert that ends it
            switch r {
            case 1: return
            case CV_TLS_WANT_READ:
                if try await !fillDuringHandshake() {
                    throw IOError(code: IOError.tls.code, message: "handshake: the peer closed the connection")
                }
            default:
                throw state.error()
            }
        }
    }

    /// Send whatever ciphertext is waiting.
    private func flush() async throws(IOError) {
        try await state.flush(to: transport)
    }

    /// false at the transport's end.
    private func fillDuringHandshake() async throws(IOError) -> Bool {
        try await state.fillDuringHandshake(from: transport)
    }
}

extension TLSStream: AsyncReader, AsyncWriter where Transport: ~Copyable {}

extension TLSStream where Transport: ~Copyable {
    /// A reader and a writer for two tasks to use at once, over the halves
    /// `splitTransport` makes of the transport:
    ///
    /// ```swift
    /// let halves = tls.split { $0.halves() }
    /// ```
    ///
    /// The writer sends anything reading makes the engine want to send (a
    /// key update's answer) with its next write.
    public consuming func split<Reader: AsyncReader & ~Copyable, Writer: AsyncWriter & ~Copyable>(
        _ splitTransport: (consuming Transport) -> StreamHalves<Reader, Writer>
    ) -> StreamHalves<TLSReader<Reader>, TLSWriter<Writer>> {
        let state = self.state
        let split = splitTransport(transport)
        return StreamHalves(reader: TLSReader(transport: split.reader, state: state),
                            writer: TLSWriter(transport: split.writer, state: state))
    }
}

extension TLSStream where Transport == TCPStream {
    /// `split(_:)` over the TCP stream's halves.
    public consuming func halves() -> StreamHalves<TLSReader<ReadHalf>, TLSWriter<WriteHalf>> {
        split { $0.halves() }
    }
}

/// The reading half of a split `TLSStream`.
public struct TLSReader<Transport: AsyncReader & ~Copyable>: ~Copyable, AsyncReader {
    private let transport: Transport
    private let state: TLSState

    init(transport: consuming Transport, state: TLSState) {
        self.transport = transport
        self.state = state
    }

    /// Read plaintext: the bytes read, or 0 after the peer's close_notify.
    public func read(into buffer: inout IOBuffer) async throws(IOError) -> Int {
        guard buffer.spareCapacity > 0 else { return 0 }
        while true {
            let n = state.decrypt(into: &buffer)
            if n == Int(CV_TLS_WANT_READ) {
                try await state.fill(from: transport)
            } else if let n = try state.result(n, buffer: &buffer) {
                return n
            }
        }
    }
}

/// The writing half of a split `TLSStream`.
public struct TLSWriter<Transport: AsyncWriter & ~Copyable>: ~Copyable, AsyncWriter {
    private let transport: Transport
    private let state: TLSState

    init(transport: consuming Transport, state: TLSState) {
        self.transport = transport
        self.state = state
    }

    public func write(_ bytes: UnsafeRawBufferPointer) async throws(IOError) {
        try await state.write(bytes, to: transport)
    }

    public func write(_ buffer: borrowing IOBuffer) async throws(IOError) {
        try await write(buffer.withUnsafeBytes { $0 })
    }

    /// Send close_notify: the peer's reads then return 0.
    public func close() async throws(IOError) {
        state.locked { cv_tls_close(state.tls) }
        try await state.flush(to: transport)
    }
}

extension TLSReader: Sendable where Transport: Sendable & ~Copyable {}
extension TLSWriter: Sendable where Transport: Sendable & ~Copyable {}

/// One connection's engine and ciphertext buffers, shared by a stream's
/// halves. Every call into the engine holds the lock; I/O never does. The
/// reading side alone uses `inbound`, the writing side alone `outbound`.
final class TLSState: @unchecked Sendable {
    /// Plaintext per record write: four full records.
    static let chunk = 64 * 1024

    let tls: OpaquePointer
    let context: TLSContext // keeps OpenSSL's context alive
    var inbound = IOBuffer(capacity: 32 * 1024)
    var outbound = IOBuffer(capacity: 80 * 1024)

    init(_ context: TLSContext, host: String?) throws(IOError) {
        var raw: OpaquePointer?
        if let e = TLSContext.call({ err, len in
            raw = cv_tls_new(context.raw, host, err, len)
            return raw == nil ? -1 : 0
        }) {
            throw e
        }
        tls = raw!
        self.context = context
    }

    private let lock = Mutex(())

    deinit { cv_tls_free(tls) }

    func locked<R>(_ body: () -> R) -> R {
        lock.withLock { _ in body() }
    }

    func error() -> IOError {
        IOError(code: IOError.tls.code, message: locked { String(cString: cv_tls_error(tls)) })
    }

    /// Plaintext into `buffer`'s spare capacity: a byte count or a
    /// `CV_TLS_` result.
    func decrypt(into buffer: inout IOBuffer) -> Int {
        let to = buffer.spareBytes, room = buffer.spareCapacity
        return locked { cv_tls_read(tls, to, room) }
    }

    /// What a read's result means: bytes read (counted into `buffer`), or a
    /// throw. nil only for `CV_TLS_WANT_READ`.
    func result(_ n: Int, buffer: inout IOBuffer) throws(IOError) -> Int? {
        switch n {
        case 0...:
            buffer.count += n
            return n
        case Int(CV_TLS_WANT_READ):
            return nil
        case Int(CV_TLS_TRUNCATED):
            throw .tlsTruncated
        default:
            throw error()
        }
    }

    /// Encrypt all of `bytes` and send it, in pieces so a large write's
    /// ciphertext isn't all in memory.
    func write<W: AsyncWriter & ~Copyable>(_ bytes: UnsafeRawBufferPointer, to transport: borrowing W) async throws(IOError) {
        guard let base = bytes.baseAddress else { return }
        var done = 0
        while done < bytes.count {
            let chunk = min(bytes.count - done, TLSState.chunk)
            let at = base + done
            if locked({ cv_tls_write(tls, at, chunk) }) < 0 { throw error() }
            done += chunk
            try await flush(to: transport)
        }
    }

    /// Send whatever ciphertext is waiting.
    func flush<W: AsyncWriter & ~Copyable>(to transport: borrowing W) async throws(IOError) {
        while true {
            outbound.clear()
            let to = outbound.spareBytes, room = outbound.spareCapacity
            let n = locked { cv_tls_pending(tls) > 0 ? cv_tls_drain(tls, to, room) : 0 }
            guard n > 0 else { return }
            outbound.count = n
            try await transport.write(outbound)
        }
    }

    /// Read ciphertext from the transport into the engine; its end, too.
    func fill<R: AsyncReader & ~Copyable>(from transport: borrowing R) async throws(IOError) {
        if try await !fillDuringHandshake(from: transport) { locked { cv_tls_feed_eof(tls) } }
    }

    /// false at the transport's end.
    func fillDuringHandshake<R: AsyncReader & ~Copyable>(from transport: borrowing R) async throws(IOError) -> Bool {
        inbound.clear()
        let n = try await transport.read(into: &inbound)
        guard n > 0 else { return false }
        let tls = self.tls
        inbound.withUnsafeBytes { bytes in locked { cv_tls_feed(tls, bytes.baseAddress, bytes.count) } }
        return true
    }

    func string(_ get: (OpaquePointer?, UnsafeMutablePointer<CChar>?, Int32) -> Int32) -> String? {
        var buf = [CChar](repeating: 0, count: 256)
        let n = Int(get(tls, &buf, Int32(buf.count)))
        guard n > 0 else { return nil }
        return String(decoding: buf.prefix(n).map(UInt8.init(bitPattern:)), as: UTF8.self)
    }
}

extension TLSStream: Sendable where Transport: Sendable & ~Copyable {}
#endif
