// On the OpenSSL or BoringSSL trait; not on iOS, tvOS, watchOS or visionOS.
#if (os(Linux) || os(macOS) || os(Windows)) && (OpenSSL || BoringSSL)
import CVegaTLS
import Synchronization
import Vega
import VegaIO
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

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
/// moves through memory, read and written by this value on the transport;
/// the library decrypts it where it was read, and this value sends what the
/// library wrote from where it wrote it.
/// Failures throw `IOError.tls` with OpenSSL's reason as the message; a
/// peer that closes without close_notify throws `IOError.tlsTruncated` (a
/// read that returns 0 means a clean close). One task at a time reads and
/// writes; `split(_:)` gives a reader and a writer for two tasks.
///
/// On Linux, with `TLSConfiguration.kernelOffload`, a stream over a
/// `TCPStream` hands its records to the kernel's TLS once the handshake is
/// done: writes then go to the socket as they are, and `sendFile` sends a
/// file with sendfile(2), never copying it into this process. With
/// `.transmitAndReceive` the kernel decrypts too, from the first record
/// boundary after anything the library already holds has been read (a TLS
/// 1.3 client first lets the library read one record, the server's session
/// tickets). After that, TLS 1.3 session tickets the server sends are not
/// kept, and a peer's KeyUpdate needs a kernel that can rekey (Linux 6.14
/// and later; older ones fail the read). `kernelOffload` says what the
/// kernel has.
public struct TLSStream<Transport: AsyncReader & AsyncWriter & ~Copyable>: ~Copyable {
    private let transport: Transport
    private let state: TLSState

    private init(transport: consuming Transport, state: TLSState) {
        self.transport = transport
        self.state = state
    }

    /// Be the client: handshake with the server at the other end of
    /// `transport`. `serverName` is sent (SNI) and the certificate checked
    /// against it; an IP address is checked as one and not sent. nil is for
    /// a context that doesn't verify (`.disabled`) only: a certificate
    /// checked against no name would be anyone's.
    public static func connect(_ transport: consuming Transport, serverName: String?,
                               context: TLSContext) async throws(IOError) -> TLSStream {
        guard context.configuration.role == .client else {
            throw IOError(code: IOError.tls.code, message: "connect needs a client context")
        }
        if serverName?.isEmpty ?? true, context.configuration.verification != .disabled {
            throw IOError(code: IOError.tls.code, message: "a verifying client needs a server name to check the certificate against")
        }
        let stream = TLSStream(transport: transport, state: try TLSState(context, host: serverName))
        try await stream.handshake()
        try await stream.offload()
        return stream
    }

    /// Be the server: handshake with the client at the other end.
    public static func accept(_ transport: consuming Transport, context: TLSContext) async throws(IOError) -> TLSStream {
        guard context.configuration.role == .server else {
            throw IOError(code: IOError.tls.code, message: "accept needs a server context")
        }
        let stream = TLSStream(transport: transport, state: try TLSState(context, host: nil))
        try await stream.handshake()
        try await stream.offload()
        return stream
    }

    // MARK: - What was agreed

    /// The ALPN protocol chosen, if any.
    public var applicationProtocol: String? { state.string(cv_tls_alpn) }
    /// The server name the client asked for (SNI), if any.
    public var serverName: String? { state.string(cv_tls_server_name) }
    public var version: TLSVersion? {
        let code = cv_tls_version(state.tls)
        return code > 0 ? TLSVersion(rawValue: UInt16(code)) : nil
    }
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
    /// What Linux's kernel TLS has of this connection now: `.off` where it
    /// has nothing (not asked for, or not to be had); `.transmit` once it
    /// encrypts; `.transmitAndReceive` once it decrypts too, which with
    /// receive offload asked for can be after the first reads.
    public var kernelOffload: TLSConfiguration.KernelOffload { state.kernelOffload }
    /// Whether the kernel encrypts what this stream sends.
    public var isKernelOffloaded: Bool { state.kernelOffload != .off }

    // MARK: - Data

    /// Read plaintext into `buffer`'s spare capacity: the bytes read, or 0
    /// once the peer has closed with close_notify; a full buffer throws `IOError.limitExceeded`.
    public func read(into buffer: inout IOBuffer) async throws(IOError) -> Int {
        guard buffer.spareCapacity > 0 else { throw IOError.readIntoFullBuffer }
        #if os(Linux)
        if state.kernelReceivePending { state.startKernelReceive() }
        if state.kernelReceives { return try await state.kernelRead(from: transport, into: &buffer) }
        #endif
        // A drained engine has nothing to give before the transport does.
        var fill = state.drained
        while true {
            if fill { try await state.fill(from: transport) }
            let (n, pending) = state.decrypt(into: &buffer)
            if pending {
                if n < 0 && n != Int(CV_TLS_WANT_READ) {
                    // An alert may be queued for a peer that's gone: best effort.
                    try? await flush()
                } else {
                    // Reading can answer the peer (a key update): send that first.
                    try await flush()
                }
            }
            if let n = try state.result(n, buffer: &buffer) { return n }
            fill = true // CV_TLS_WANT_READ
        }
    }

    /// Encrypt and send all of `bytes`.
    public func write(_ bytes: UnsafeRawBufferPointer) async throws(IOError) {
        try await state.write(bytes, to: transport)
    }

    public func write(_ buffer: borrowing IOBuffer) async throws(IOError) {
        try await state.write(buffer.withUnsafeBytes { $0 }, to: transport)
    }

    /// Send close_notify, then end the transport's sending side: the peer's
    /// reads return 0, and this side can still read.
    public func shutdownWrite() async throws(IOError) {
        try await state.close(transport)
        try await transport.shutdownWrite()
    }

    /// Send close_notify, then give back the transport (to shut down or
    /// close). The peer's reads then return 0.
    public consuming func close() async throws(IOError) -> Transport {
        try await state.close(transport)
        return transport
    }

    /// TLS 1.3: new keys for what we send from here on (a KeyUpdate), and
    /// with `requestPeerUpdate` the peer asked to renew its own. Throws
    /// `IOError.tls` on TLS 1.2, which has no such thing.
    public func updateKeys(requestPeerUpdate: Bool = false) async throws(IOError) {
        try await state.updateKeys(requestPeerUpdate, transport)
    }

    // MARK: - Moving ciphertext

    private func handshake() async throws(IOError) {
        while true {
            let (r, pending) = state.handshakeStep()
            if pending { try await flush() } // our flight, or the alert that ends it
            switch r {
            case 1: return
            case CV_TLS_WANT_READ:
                if try await !state.fill(from: transport) {
                    throw IOError(code: IOError.tls.code, message: "handshake: the peer closed the connection")
                }
            default:
                throw state.error()
            }
        }
    }

    /// Hand the records to the kernel, if asked and it can take them.
    private func offload() async throws(IOError) {
        #if os(Linux)
        guard state.context.configuration.kernelOffload != .off else { return }
        // What the library still has to send goes first, encrypted by it.
        var st = cv_tls_status()
        cv_tls_ktls_settle(state.tls, &st)
        if st.pending > 0 { try await flush() }
        state.startKernel(kernelSocket(of: transport))
        #endif
    }

    /// Send whatever ciphertext is waiting.
    private func flush() async throws(IOError) {
        try await state.flush(to: transport)
    }
}

extension TLSStream: AsyncReader, AsyncWriter where Transport: ~Copyable {}

extension TLSStream where Transport: ~Copyable {
    /// A reader and a writer for two tasks to use at once, over the halves
    /// `splitTransport` makes of the transport:
    ///
    /// ```swift
    /// let halves = tls.split { $0.split() }
    /// ```
    ///
    /// The writer sends anything reading makes the engine want to send (a
    /// key update's answer) with its next write.
    public consuming func split<Reader: AsyncReader & ~Copyable, Writer: AsyncWriter & ~Copyable>(
        _ splitTransport: (consuming Transport) -> StreamHalves<Reader, Writer>
    ) -> StreamHalves<TLSReader<Reader>, TLSWriter<Writer>> {
        let state = self.state
        state.isSplit = true // from here on two tasks share the engine
        let split = splitTransport(transport)
        return StreamHalves(reader: TLSReader(transport: split.reader, state: state),
                            writer: TLSWriter(transport: split.writer, state: state))
    }
}

extension TLSStream where Transport == TCPStream {
    /// `split(_:)` over the TCP stream's halves.
    public consuming func split() -> StreamHalves<TLSReader<ReadHalf>, TLSWriter<WriteHalf>> {
        split { $0.split() }
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
        guard buffer.spareCapacity > 0 else { throw IOError.readIntoFullBuffer }
        #if os(Linux)
        if state.kernelReceivePending { state.startKernelReceive() }
        if state.kernelReceives { return try await state.kernelRead(from: transport, into: &buffer) }
        #endif
        var fill = state.drained
        while true {
            if fill { try await state.fill(from: transport) }
            // Anything to send waits for the writer's next write.
            let (n, _) = state.decrypt(into: &buffer)
            if let n = try state.result(n, buffer: &buffer) { return n }
            fill = true // CV_TLS_WANT_READ
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
        try await state.write(buffer.withUnsafeBytes { $0 }, to: transport)
    }

    /// Send close_notify: the peer's reads then return 0.
    public func close() async throws(IOError) {
        try await state.close(transport)
    }

    /// Send close_notify, then end the transport's sending side.
    public func shutdownWrite() async throws(IOError) {
        try await state.close(transport)
        try await transport.shutdownWrite()
    }

    /// `TLSStream.updateKeys(requestPeerUpdate:)`, from the writing half.
    public func updateKeys(requestPeerUpdate: Bool = false) async throws(IOError) {
        try await state.updateKeys(requestPeerUpdate, transport)
    }

    /// Whether the kernel encrypts what this half sends.
    public var isKernelOffloaded: Bool { state.kernelSends }
}

extension TLSReader: Sendable where Transport: Sendable & ~Copyable {}
extension TLSWriter: Sendable where Transport: Sendable & ~Copyable {}

/// One connection's engine and the peer's ciphertext, shared by a stream's
/// halves. I/O never holds the lock; once the stream is split, every call
/// into the engine does. Until then one task at a time uses it all, and
/// there is nothing to lock against. The reading side alone uses
/// `inbound`; the engine's output is taken by one sender at a time.
final class TLSState: @unchecked Sendable {
    /// Plaintext per record write: four full records.
    static let chunk = 64 * 1024

    let tls: OpaquePointer
    let context: TLSContext // keeps OpenSSL's context alive
    /// The peer's ciphertext as read; the engine has taken the first
    /// `taken` bytes, and takes the rest in place on later calls.
    var inbound = IOBuffer(capacity: 32 * 1024)
    var taken = 0
    /// The last read left the engine drained: it can't return anything
    /// before more ciphertext comes, so the next read reads the transport
    /// first.
    var drained = false
    /// Set by `split`, before the halves go to their tasks.
    var isSplit = false
    #if os(Linux)
    // Kernel TLS. The socket is set before the stream can be split; the
    // rest belongs to the reading side.
    /// The socket whose records the kernel encrypts, or -1.
    var kernelSocket: Int32 = -1
    /// The kernel decrypts too.
    var kernelReceives = false
    /// It is to, once the engine has given out everything it holds.
    var kernelReceivePending = false
    /// The peer's close_notify came through the kernel.
    var kernelClosed = false
    /// Handshake messages read through the kernel, until whole.
    var handshakeBytes: [UInt8] = []
    #endif

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
        #if os(Linux)
        switch context.configuration.kernelOffload {
        case .off: break
        case .transmit: cv_tls_ktls_want(tls, CV_KTLS_TX)
        case .transmitAndReceive: cv_tls_ktls_want(tls, CV_KTLS_TX | CV_KTLS_RX)
        }
        #endif
    }

    // A RawLock, not a Mutex: ThreadSanitizer doesn't see Mutex on Linux.
    private let lock = RawLock()

    deinit {
        cv_tls_free(tls)
        lock.destroy()
    }

    /// A call into the engine: under the lock once the stream is split.
    @inline(__always)
    func engine<R>(_ body: () -> R) -> R {
        if isSplit { return lock.withLock { body() } }
        return body()
    }

    /// Input the engine holds: plaintext not yet read, or ciphertext read
    /// and not yet taken.
    var hasBufferedInput: Bool {
        taken < inbound.count || engine { cv_tls_buffered(tls) != 0 }
    }

    func error() -> IOError {
        IOError(code: IOError.tls.code, message: engine { String(cString: cv_tls_error(tls)) })
    }

    /// One handshake step: 1, or a `CV_TLS_` result; and whether there is
    /// ciphertext to send.
    func handshakeStep() -> (Int32, pending: Bool) {
        let input = inbound.withUnsafeBytes { $0 }
        let at = input.baseAddress.map { $0 + taken }, left = input.count - taken
        var st = cv_tls_status()
        let r = engine { cv_tls_handshake(tls, at, left, &st) }
        taken += st.used
        return (r, st.pending > 0)
    }

    /// Plaintext into `buffer`'s spare capacity: a byte count or a
    /// `CV_TLS_` result; and whether there is ciphertext to send.
    func decrypt(into buffer: inout IOBuffer) -> (Int, pending: Bool) {
        let to = buffer.spareBytes, room = buffer.spareCapacity
        let input = inbound.withUnsafeBytes { $0 }
        let at = input.baseAddress.map { $0 + taken }, left = input.count - taken
        var st = cv_tls_status()
        let n = engine { cv_tls_read(tls, at, left, to, room, &st) }
        taken += st.used
        drained = st.drained != 0
        return (n, st.pending > 0)
    }

    /// What a read's result means: bytes read (counted into `buffer`), or a
    /// throw. nil only for `CV_TLS_WANT_READ`.
    func result(_ n: Int, buffer: inout IOBuffer) throws(IOError) -> Int? {
        switch n {
        case 0...:
            buffer.readable += n
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
        #if os(Linux)
        if kernelSocket >= 0 {
            try await kernelOwedUpdate()
            return try await transport.write(bytes)
        }
        #endif
        guard let base = bytes.baseAddress else { return }
        var done = 0
        while done < bytes.count {
            let chunk = min(bytes.count - done, TLSState.chunk)
            let at = base + done
            var st = cv_tls_status()
            if engine({ cv_tls_write(tls, at, chunk, &st) }) < 0 { throw error() }
            done += chunk
            // flush(to:), written out: an async call fewer per write.
            var count = 0
            while let ciphertext = engine({ cv_tls_take_output(tls, &count) }) {
                do {
                    try await transport.write(UnsafeRawBufferPointer(start: ciphertext, count: count))
                } catch {
                    engine { cv_tls_return_output(tls) }
                    throw error
                }
                engine { cv_tls_return_output(tls) }
                if !isSplit { break }
            }
        }
    }

    /// Send whatever ciphertext is waiting, from the engine's own buffer.
    func flush<W: AsyncWriter & ~Copyable>(to transport: borrowing W) async throws(IOError) {
        while true {
            var count = 0
            guard let bytes = engine({ cv_tls_take_output(tls, &count) }) else { return }
            do {
                try await transport.write(UnsafeRawBufferPointer(start: bytes, count: count))
            } catch {
                engine { cv_tls_return_output(tls) }
                throw error
            }
            engine { cv_tls_return_output(tls) }
            // Only the other half of a split stream can have added more.
            if !isSplit { return }
        }
    }

    /// Read ciphertext from the transport for the engine, or tell it the
    /// transport's end (and return false).
    @discardableResult
    func fill<R: AsyncReader & ~Copyable>(from transport: borrowing R) async throws(IOError) -> Bool {
        // The engine wants more only once it has taken all it was handed,
        // so this is nearly always a clear.
        if taken == inbound.count {
            inbound.clear()
        } else if taken > 0 {
            inbound.consume(taken)
        }
        taken = 0
        #if os(Linux)
        // Receive offload waits for a record boundary: read no further
        // than the end of the record the engine is inside.
        if kernelReceivePending, case let short = engine({ cv_tls_ktls_rx_short(tls) }), short > 0 {
            var part = IOBuffer(capacity: short)
            let n = try await transport.read(into: &part)
            guard n > 0 else {
                engine { cv_tls_feed_eof(tls) }
                return false
            }
            if inbound.spareCapacity < n { inbound.reserveCapacity(inbound.count + n) }
            part.withUnsafeBytes { _ = inbound.append($0) }
            drained = false
            return true
        }
        #endif
        if inbound.spareCapacity == 0 { inbound.reserveCapacity(inbound.capacity * 2) }
        let n = try await transport.read(into: &inbound)
        guard n > 0 else {
            engine { cv_tls_feed_eof(tls) }
            return false
        }
        drained = false
        return true
    }

    /// Send close_notify.
    func close<W: AsyncWriter & ~Copyable>(_ transport: borrowing W) async throws(IOError) {
        #if os(Linux)
        if kernelSocket >= 0 { return try await sendKernelRecord(TLSState.alert, [1, 0]) } // warning, close_notify
        #endif
        engine { cv_tls_close(tls) }
        try await flush(to: transport)
    }

    func updateKeys<W: AsyncWriter & ~Copyable>(_ request: Bool, _ transport: borrowing W) async throws(IOError) {
        guard cv_tls_version(tls) == Int32(TLSVersion.v1_3.rawValue) else {
            throw IOError(code: IOError.tls.code, message: "key update: TLS 1.3 only")
        }
        #if os(Linux)
        if kernelSocket >= 0 {
            _ = cv_tls_ktls_take_owed_update(tls) // this one answers too
            return try await kernelKeyUpdate(request: request)
        }
        #endif
        var st = cv_tls_status()
        if engine({ cv_tls_key_update(tls, request ? 1 : 0, &st) }) != 0 { throw error() }
        try await flush(to: transport)
    }

    #if !os(Windows)
    /// `sendFile` where the kernel doesn't encrypt: the file read here, a
    /// piece at a time, and written as any plaintext is.
    func copyFile<W: AsyncWriter & ~Copyable>(_ file: Int32, offset: Int64, count: Int,
                                              to transport: borrowing W) async throws(IOError) -> Int {
        let chunk = min(count, TLSState.chunk)
        guard chunk > 0 else { return 0 }
        let buffer = UnsafeMutableRawPointer.allocate(byteCount: chunk, alignment: 16)
        defer { buffer.deallocate() }
        var sent = 0
        while sent < count {
            let n = pread(file, buffer, min(chunk, count - sent), off_t(offset + Int64(sent)))
            if n < 0 {
                if errno == EINTR { continue }
                throw IOError(code: errno)
            }
            if n == 0 { break } // the file ended
            try await write(UnsafeRawBufferPointer(start: buffer, count: n), to: transport)
            sent += n
        }
        return sent
    }
    #endif

    func string(_ get: (OpaquePointer?, UnsafeMutablePointer<CChar>?, Int32) -> Int32) -> String? {
        var buf = [CChar](repeating: 0, count: 256)
        let n = Int(get(tls, &buf, Int32(buf.count)))
        guard n > 0 else { return nil }
        return String(decoding: buf.prefix(n).map(UInt8.init(bitPattern:)), as: UTF8.self)
    }
}

extension TLSStream: Sendable where Transport: Sendable & ~Copyable {}

extension TLSStream: PendingInputProbing where Transport: PendingInputProbing & ~Copyable {
    /// Whether a read would return at once: input the engine or its buffer
    /// already holds, or anything waiting on the transport.
    public var hasPendingInput: Bool {
        state.hasBufferedInput || transport.hasPendingInput
    }
}

#if !os(Windows)
extension TLSStream where Transport == TCPStream {
    /// Send up to `count` bytes of the open file `file` (a descriptor) from
    /// `offset`. With the kernel encrypting (`kernelOffload`), by
    /// sendfile(2): the file never passes through this process. Otherwise
    /// it is read here and sent as any write is. Returns the bytes sent:
    /// `count`, or fewer when the file ends first. The file is not closed.
    public func sendFile(_ file: Int32, offset: Int64 = 0, count: Int) async throws(IOError) -> Int {
        #if os(Linux)
        if state.kernelSocket >= 0 {
            try await state.kernelOwedUpdate()
            return try await transport.sendFile(file, offset: offset, count: count)
        }
        #endif
        return try await state.copyFile(file, offset: offset, count: count, to: transport)
    }
}

extension TLSWriter where Transport == WriteHalf {
    /// `TLSStream.sendFile(_:offset:count:)`, from the writing half.
    public func sendFile(_ file: Int32, offset: Int64 = 0, count: Int) async throws(IOError) -> Int {
        #if os(Linux)
        if state.kernelSocket >= 0 {
            try await state.kernelOwedUpdate()
            return try await transport.sendFile(file, offset: offset, count: count)
        }
        #endif
        return try await state.copyFile(file, offset: offset, count: count, to: transport)
    }
}
#endif

extension TLSState {
    /// Whether the kernel encrypts: set before the stream can be split, so
    /// either half may ask.
    var kernelSends: Bool {
        #if os(Linux)
        kernelSocket >= 0
        #else
        false
        #endif
    }

    var kernelOffload: TLSConfiguration.KernelOffload {
        #if os(Linux)
        guard kernelSocket >= 0 else { return .off }
        return kernelReceives ? .transmitAndReceive : .transmit
        #else
        return .off
        #endif
    }
}

#if os(Linux)
/// The socket under `transport` that kernel TLS can take over: a TCP
/// stream's; -1 for any other transport.
func kernelSocket<T: ~Copyable>(of transport: borrowing T) -> Int32 {
    guard ObjectIdentifier(T.self) == ObjectIdentifier(TCPStream.self) else { return -1 }
    return withUnsafePointer(to: transport) {
        UnsafeRawPointer($0).assumingMemoryBound(to: TCPStream.self).pointee.fileDescriptor
    }
}

/// Kernel TLS: the records of a direction the kernel has are plaintext to
/// this process, but for those other than application data, which a plain
/// read fails on with EIO and which are read and sent here with their type.
extension TLSState {
    static let alert: Int32 = 21
    static let handshake: Int32 = 22
    static let applicationData: Int32 = 23

    /// After the handshake: give the kernel our direction on `fd` (-1: no
    /// socket, which fails as a kernel without TLS does), and the peer's if
    /// asked and the engine holds nothing of it.
    func startKernel(_ fd: Int32) {
        let wanted = context.configuration.kernelOffload
        guard wanted != .off, cv_tls_ktls_enable_tx(tls, fd) == 1 else { return }
        kernelSocket = fd
        if wanted == .transmitAndReceive {
            kernelReceivePending = true
            startKernelReceive()
        }
    }

    /// Give the kernel the peer's direction if the engine has nothing left
    /// of it: no ciphertext unread, no plaintext unread, no part-record.
    func startKernelReceive() {
        guard taken == inbound.count else { return }
        switch engine({ cv_tls_ktls_enable_rx(tls, kernelSocket) }) {
        case 1:
            kernelReceives = true
            kernelReceivePending = false
            inbound = IOBuffer(capacity: 1) // reads go to the caller's buffer now
            taken = 0
        case 0:
            break
        default:
            kernelReceivePending = false
        }
    }

    /// Read plaintext the kernel decrypted.
    func kernelRead<R: AsyncReader & ~Copyable>(from transport: borrowing R,
                                                into buffer: inout IOBuffer) async throws(IOError) -> Int {
        while !kernelClosed {
            var failure: IOError?
            var n = 0
            do throws(IOError) {
                n = try await transport.read(into: &buffer)
            } catch {
                failure = error
            }
            if let failure {
                // EIO: a record other than data is next.
                guard failure.code == EIO else { throw kernelError(failure) }
                if let n = try kernelRecord() { return n }
                continue
            }
            // The connection ended without close_notify.
            if n == 0 { throw .tlsTruncated }
            return n
        }
        return 0
    }

    /// Read the record at the head of the socket: nil once it's dealt with
    /// (or was data after all), 0 for the peer's close_notify.
    func kernelRecord() throws(IOError) -> Int? {
        var record = [UInt8](repeating: 0, count: 16 * 1024 + 256)
        var type: Int32 = 0
        let n = record.withUnsafeMutableBytes { cv_ktls_recv_record(kernelSocket, $0.baseAddress, $0.count, &type) }
        if n < 0 {
            let code = Int32(-n)
            if code == EAGAIN || code == EINTR { return nil }
            throw kernelError(IOError(code: code))
        }
        switch type {
        case TLSState.applicationData:
            return nil
        case 0:
            throw .tlsTruncated // the end, where a record should be
        case TLSState.alert:
            guard n >= 2 else { throw IOError(code: IOError.tls.code, message: "read: a malformed alert") }
            if record[1] == 0 { // close_notify
                kernelClosed = true
                return 0
            }
            if record[0] == 1 { return nil } // a warning: ignored, as the library does
            throw IOError(code: IOError.tls.code, message: "read: the peer sent alert \(record[1])")
        case TLSState.handshake:
            handshakeBytes += record[0..<n]
            try kernelHandshakeMessages()
            return nil
        default:
            throw IOError(code: IOError.tls.code, message: "read: an unexpected record (kernel TLS)")
        }
    }

    /// The post-handshake messages whole in `handshakeBytes`: TLS 1.3's
    /// session tickets (not kept: the library can't be given them) and
    /// KeyUpdate (the kernel rekeyed, and our own owed if asked for).
    func kernelHandshakeMessages() throws(IOError) {
        while handshakeBytes.count >= 4 {
            let length = Int(handshakeBytes[1]) << 16 | Int(handshakeBytes[2]) << 8 | Int(handshakeBytes[3])
            guard length <= 64 * 1024 else {
                throw IOError(code: IOError.tls.code, message: "read: a handshake message too long (kernel TLS)")
            }
            guard handshakeBytes.count >= 4 + length else { return }
            let type = handshakeBytes[0]
            let first = length > 0 ? handshakeBytes[4] : 0
            handshakeBytes.removeFirst(4 + length)
            switch type {
            case 0, 4: // TLS 1.2's HelloRequest (no renegotiation here), NewSessionTicket
                break
            case 24: // KeyUpdate
                guard length == 1, first <= 1 else {
                    throw IOError(code: IOError.tls.code, message: "read: a malformed KeyUpdate")
                }
                if engine({ cv_tls_ktls_update(tls, kernelSocket, 0) }) != 0 {
                    throw IOError(code: IOError.tls.code, message: "read: the kernel can't take the peer's new keys (KeyUpdate)")
                }
                if first == 1 { cv_tls_ktls_owe_update(tls) }
            default:
                throw IOError(code: IOError.tls.code, message: "read: an unexpected handshake message (kernel TLS)")
            }
        }
    }

    /// The kernel's failures, said as TLS ones where they are.
    func kernelError(_ e: IOError) -> IOError {
        switch e.code {
        case EBADMSG: IOError(code: IOError.tls.code, message: "read: bad record (kernel TLS)")
        case EMSGSIZE: IOError(code: IOError.tls.code, message: "read: record overflow (kernel TLS)")
        default: e
        }
    }

    /// Answer the peer's request for a KeyUpdate before anything more goes.
    func kernelOwedUpdate() async throws(IOError) {
        if cv_tls_ktls_take_owed_update(tls) != 0 { try await kernelKeyUpdate(request: false) }
    }

    /// Send a KeyUpdate under the current key, then switch to the next.
    func kernelKeyUpdate(request: Bool) async throws(IOError) {
        try await sendKernelRecord(TLSState.handshake, [24, 0, 0, 1, request ? 1 : 0])
        if engine({ cv_tls_ktls_update(tls, kernelSocket, 1) }) != 0 {
            throw IOError(code: IOError.tls.code, message: "key update: the kernel can't take new keys")
        }
    }

    /// A record of `type` through the kernel.
    func sendKernelRecord(_ type: Int32, _ bytes: [UInt8]) async throws(IOError) {
        var sent = 0
        var pause = Duration.milliseconds(1)
        while sent < bytes.count {
            let n = bytes.withUnsafeBytes { cv_ktls_send_record(kernelSocket, type, $0.baseAddress! + sent, $0.count - sent) }
            if n >= 0 {
                sent += n
                continue
            }
            switch Int32(-n) {
            case EINTR:
                continue
            case EAGAIN:
                // The socket is full, and this is no read or write of its
                // own to wait for room: look again in a while.
                do {
                    try await Runtime.sleep(for: pause)
                } catch {
                    throw .cancelled
                }
                pause = min(pause * 2, .milliseconds(50))
            default:
                throw IOError(code: Int32(-n))
            }
        }
    }
}
#endif
#endif
