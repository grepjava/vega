#if os(Linux) || canImport(Darwin)
import CVega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
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
        let driver = try IODriver.current()
        var err: Int32 = 0
        let fd = cv_tcp_listen(host, Int32(port), Int32(backlog), reusePort ? 1 : 0, &err)
        guard fd >= 0 else { throw IOError(code: err) }
        return TCPListener(reg: try IORegistration(fd: fd, driver: driver))
    }

    deinit { reg.close() }

    /// The port the listener is bound to.
    public var localPort: Int { Int(cv_local_port(reg.fd)) }

    public var localAddress: SocketAddress { get throws(IOError) { try reg.localAddress } }

    /// Wait for the next connection.
    public func accept() async throws(IOError) -> TCPStream {
        TCPStream(reg: try await reg.accept(cv_tcp_accept))
    }
}

/// A TCP connection. One task reads and writes it at a time; `split()` it
/// for a reader and a writer that run at once.
public struct TCPStream: ~Copyable, Sendable {
    let reg: IORegistration

    init(reg: IORegistration) { self.reg = reg }

    // connect(host:port:attemptDelay:) and connect(to: [SocketAddress]):
    // Happy Eyeballs, in HappyEyeballs.swift.

    /// Connect to `address`. Call from a task on a Vega runtime.
    public static func connect(to address: SocketAddress) async throws(IOError) -> TCPStream {
        let driver = try IODriver.current()
        var err: Int32 = 0
        let fd = withUnsafePointer(to: address.raw) { cv_connect_new($0, socketStream, &err) }
        guard fd >= 0 else { throw IOError(code: err) }
        let stream = TCPStream(reg: try IORegistration(fd: fd, driver: driver))
        try await stream.reg.connected(err)
        return stream
    }

    deinit { reg.close() }

    /// Read into `buffer`'s spare capacity. Returns the bytes read: 0 means
    /// the peer closed its side (or the buffer has no room left).
    public func read(into buffer: inout IOBuffer) async throws(IOError) -> Int {
        try await reg.read(into: &buffer)
    }

    /// Write all of `buffer`'s readable bytes.
    public func write(_ buffer: borrowing IOBuffer) async throws(IOError) {
        try await reg.write(UnsafeRawBufferPointer(start: buffer.base, count: buffer.count))
    }

    /// Write all of `bytes`. They must stay valid until this returns.
    public func write(_ bytes: UnsafeRawBufferPointer) async throws(IOError) {
        try await reg.write(bytes)
    }
    /// Write all of `head`, then all of `body`, in one system call where the
    /// socket has room (a header and a payload, say).
    public func write(_ head: borrowing IOBuffer, _ body: borrowing IOBuffer) async throws(IOError) {
        let a = UnsafeRawBufferPointer(start: head.base, count: head.count)
        let b = UnsafeRawBufferPointer(start: body.base, count: body.count)
        try await reg.write(parts: 2) { $0 == 0 ? a : b }
    }

    /// Write all of `parts` in order, gathered into as few system calls as
    /// possible. They must stay valid until this returns.
    public func write(vectored parts: UnsafeBufferPointer<UnsafeRawBufferPointer>) async throws(IOError) {
        try await reg.write(parts: parts.count) { parts[$0] }
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
