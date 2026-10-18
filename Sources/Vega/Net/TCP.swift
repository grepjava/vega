#if os(Linux) || canImport(Darwin) || os(Windows)
import CVega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#elseif os(Windows)
import ucrt
#endif

/// A listening TCP socket.
///
/// ```swift
/// let listener = try TCPListener.bind(port: 8080)
/// while true {
///     let stream = try await listener.accept()
///     rt.spawn(with: stream) { stream in await serve(stream) }
/// }
/// ```
///
/// Sockets belong to the runtime whose task created them and must not
/// outlive it. Closing is dropping: the fd is closed when the value goes away.
public struct TCPListener: ~Copyable, Sendable {
    let reg: IORegistration

    /// Listen on `host` (an address or name; empty for all interfaces) and
    /// `port` (0 picks a free one). Call from a task on a Vega runtime.
    public static func bind(host: String = "", port: Int, backlog: Int = 1024,
                            reusePort: Bool = false) throws(IOError) -> TCPListener {
        #if canImport(Network)
        if NetworkIO.active {
            return TCPListener(reg: try NetworkIO.listen(host: host, port: port, backlog: backlog, reusePort: reusePort))
        }
        #endif
        let driver = try IODriver.current()
        var err: Int32 = 0
        let fd = cv_tcp_listen(host, Int32(port), Int32(backlog), reusePort ? 1 : 0, &err)
        guard fd >= 0 else { throw IOError(code: err) }
        return TCPListener(reg: try IORegistration(fd: fd, driver: driver))
    }

    deinit { reg.close() }

    /// The port the listener is bound to.
    public var localPort: Int {
        #if canImport(Network)
        if let port = reg.nwPort { return port }
        #endif
        return Int(cv_local_port(reg.fd))
    }

    public var localAddress: SocketAddress { get throws(IOError) { try reg.localAddress } }

    /// Wait for the next connection.
    public func accept() async throws(IOError) -> TCPStream {
        #if os(Windows)
        if reg.overlapped(CV_OVL_ACCEPT) { return TCPStream(reg: try await reg.acceptOverlapped()) }
        #endif
        return TCPStream(reg: try await reg.accept(cv_tcp_accept))
    }
}

/// A TCP connection. One task reads and writes it at a time; `split()` it
/// for a reader and a writer that run at once.
public struct TCPStream: ~Copyable, Sendable {
    @usableFromInline let reg: IORegistration

    init(reg: IORegistration) { self.reg = reg }

    // connect(host:port:attemptDelay:) and connect(to: [SocketAddress]):
    // Happy Eyeballs, in HappyEyeballs.swift.

    /// Connect to `address`. Call from a task on a Vega runtime.
    public static func connect(to address: SocketAddress) async throws(IOError) -> TCPStream {
        #if canImport(Network)
        if NetworkIO.active { return TCPStream(reg: try await NetworkIO.connect(to: address)) }
        #endif
        let driver = try IODriver.current()
        var err: Int32 = 0
        #if os(Windows)
        if cv_driver_overlapped(driver.raw, CV_OVL_CONNECT) != 0 {
            // ConnectEx: the completion says it's connected.
            let fd = withUnsafePointer(to: address.raw) { cv_socket_open(cv_sockaddr_family($0), socketStream, &err) }
            guard fd >= 0 else { throw IOError(code: err) }
            let stream = TCPStream(reg: try IORegistration(fd: fd, driver: driver))
            try await stream.reg.connectOverlapped(to: address)
            return stream
        }
        #endif
        let fd = withUnsafePointer(to: address.raw) { cv_connect_new($0, socketStream, &err) }
        guard fd >= 0 else { throw IOError(code: err) }
        let stream = TCPStream(reg: try IORegistration(fd: fd, driver: driver))
        try await stream.reg.connected(err)
        return stream
    }

    deinit { reg.close() }

    /// Read into `buffer`'s spare capacity. Returns the bytes read: 0 means
    /// the peer closed its side (or the buffer has no room left).
    @inlinable
    public func read(into buffer: inout IOBuffer) async throws(IOError) -> Int {
        // Inlined, a read on the ring suspends the caller directly: see
        // `RingRead`.
        let reg = reg
        if let ring = reg.ringRead(&buffer) {
            let res = await withUnsafeContinuation { reg.submit(ring, $0) }
            var yield = false
            let n = try reg.finish(ring, res, &buffer, &yield)
            if n >= 0 {
                if yield { await Runtime.yieldSpent() }
                return n
            }
        }
        return try await reg.readSlow(into: &buffer)
    }

    /// Wait until a read would return at once, without reading: for input
    /// to arrive, or for the peer to close its side.
    public func readable() async throws(IOError) {
        _ = try await reg.waitReadable()
    }

    /// Wait until the peer closes its side of the connection, or resets it,
    /// and return true; or return false as soon as input arrives instead,
    /// since a close behind that input can't be seen until it is read. For a
    /// server that wants to stop work a client no longer waits for -- an
    /// HTTP/1 request whose client hung up -- while it reads nothing.
    /// Cancellation and `Runtime.withIOTimeout` end the wait as they end a
    /// read.
    public func peerClosed() async throws(IOError) -> Bool {
        try await reg.waitReadable()
    }

    // The writes are inlinable so that one the socket takes at once (nearly
    // all of them) costs the caller no async call: see `sendNow`.

    /// Write all of `buffer`'s readable bytes.
    @inlinable
    public func write(_ buffer: borrowing IOBuffer) async throws(IOError) {
        try await write(buffer.withUnsafeBytes { $0 })
    }

    /// Write all of `bytes`. They must stay valid until this returns.
    @inlinable
    public func write(_ bytes: UnsafeRawBufferPointer) async throws(IOError) {
        var status: Int32 = 0
        let sent = reg.sendNow(bytes, &status)
        if status != 0 { try await reg.writeRest(bytes, sent: sent, status: status) }
    }
    /// Write all of `head`, then all of `body`, in one system call where the
    /// socket has room (a header and a payload, say).
    @inlinable
    public func write(_ head: borrowing IOBuffer, _ body: borrowing IOBuffer) async throws(IOError) {
        let a = head.withUnsafeBytes { $0 }, b = body.withUnsafeBytes { $0 }
        var status: Int32 = 0
        let sent = reg.sendNow(a, b, &status)
        if status != 0 { try await reg.writeRest(a, b, sent: sent, status: status) }
    }

    /// Write all of `parts` in order, gathered into as few system calls as
    /// possible. They must stay valid until this returns.
    @inlinable
    public func write(vectored parts: UnsafeBufferPointer<UnsafeRawBufferPointer>) async throws(IOError) {
        var status: Int32 = 0
        let sent = reg.sendNow(vectored: parts, &status)
        if status != 0 { try await reg.writeRest(vectored: parts, sent: sent, status: status) }
    }


    /// Send as much of `parts` as the socket takes now, without waiting:
    /// the bytes sent, which may be fewer than offered, or 0 if it is full.
    /// For code that must not suspend (a NIO channel's flush, say); send the
    /// rest with `write(vectored:)`. Always 0 on Network.framework.
    public func tryWrite(vectored parts: UnsafeBufferPointer<UnsafeRawBufferPointer>) throws(IOError) -> Int {
        try reg.trySend(parts: parts.count) { parts[$0] }
    }

    /// Send up to `count` bytes of the open file `file` (a descriptor) from
    /// `offset`, without copying them through this process where the system
    /// allows (sendfile(2) on Linux and Darwin, TransmitFile on Windows,
    /// where `file` is the file's handle). Returns the bytes sent: `count`,
    /// or fewer when the file ends first. The file is not closed.
    ///
    /// On Windows a send cancelled (by the task's cancellation or its I/O
    /// deadline) aborts the connection: Winsock can't say how much of it
    /// went.
    public func sendFile(_ file: Int32, offset: Int64 = 0, count: Int) async throws(IOError) -> Int {
        try await reg.sendFile(file, offset: offset, count: count)
    }

    /// Stop sending: the peer reads end-of-stream once it has the rest.
    public func shutdownWrite() throws(IOError) { try reg.shutdownWrite() }

    public var localAddress: SocketAddress { get throws(IOError) { try reg.localAddress } }
    public var peerAddress: SocketAddress { get throws(IOError) { try reg.peerAddress } }

    /// Split into a reading half and a writing half that different tasks
    /// can use at the same time. No reference counting: the halves share
    /// the registration, and the second to be dropped closes the socket.
    public consuming func split() -> SplitStream {
        let reg = self.reg
        discard self
        cv_io_split(reg.io)
        return SplitStream(reader: ReadHalf(reg: reg), writer: WriteHalf(reg: reg))
    }
}

extension IODriver {
    /// The driver of the runtime running the caller.
    static func current() throws(IOError) -> IODriver {
        guard let s = Worker.currentScheduler else { throw .notOnRuntime }
        if s.usesRings { return IODriver(raw: nil, owner: UnsafeRawPointer(Unmanaged.passUnretained(s).toOpaque())) }
        guard let d = s.driver else { throw .unsupported }
        return d
    }
}
#endif
