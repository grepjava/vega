#if os(Linux) || canImport(Darwin)
import CVega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

extension SocketAddress {
    /// A Unix socket's address: its path.
    public init(unixPath path: String) throws(IOError) {
        var raw = cv_sockaddr()
        let e = cv_unix_sockaddr(path, &raw)
        guard e == 0 else { throw IOError(code: e) }
        self.init(raw: raw)
    }
}

/// A Unix datagram socket: Tokio's `UnixDatagram`. Not on Windows, whose
/// Unix sockets are streams only.
///
/// ```swift
/// let server = try UnixDatagram.bind(path: "/tmp/echo.sock")
/// var buf = IOBuffer(capacity: 4096)
/// let (_, from) = try await server.receiveFrom(into: &buf)
/// ```
///
/// The path is left behind when the socket is dropped (remove it yourself,
/// as with Tokio). A datagram is delivered whole or not at all; one longer
/// than the buffer's spare capacity is cut short.
public struct UnixDatagram: ~Copyable, Sendable {
    let reg: IORegistration

    init(reg: IORegistration) { self.reg = reg }

    /// A socket bound to `path`, which must not exist yet. Call from a task
    /// on a Vega runtime.
    public static func bind(path: String) throws(IOError) -> UnixDatagram {
        let driver = try IODriver.current()
        var err: Int32 = 0
        let fd = cv_unix_dgram_bind(path, &err)
        guard fd >= 0 else { throw IOError(code: err) }
        return UnixDatagram(reg: try IORegistration(fd: fd, driver: driver))
    }

    /// A socket bound to no path: it can send, and receive replies only if
    /// it is connected (the peer has nowhere else to send them).
    public static func unbound() throws(IOError) -> UnixDatagram {
        let driver = try IODriver.current()
        var err: Int32 = 0
        let fd = cv_unix_dgram_bind(nil, &err)
        guard fd >= 0 else { throw IOError(code: err) }
        return UnixDatagram(reg: try IORegistration(fd: fd, driver: driver))
    }

    @frozen
    public struct Pair: ~Copyable, Sendable {
        public var first: UnixDatagram
        public var second: UnixDatagram
    }

    /// Two sockets connected to each other.
    public static func pair() throws(IOError) -> Pair {
        let driver = try IODriver.current()
        var fds: (Int32, Int32) = (-1, -1)
        let e = withUnsafeMutablePointer(to: &fds) {
            $0.withMemoryRebound(to: Int32.self, capacity: 2) { cv_unix_dgram_pair($0) }
        }
        guard e == 0 else { throw IOError(code: e) }
        let a: IORegistration
        do { a = try IORegistration(fd: fds.0, driver: driver) } catch {
            closeDescriptor(fds.1)
            throw error
        }
        let first = UnixDatagram(reg: a)
        return Pair(first: first, second: UnixDatagram(reg: try IORegistration(fd: fds.1, driver: driver)))
    }

    deinit { reg.close() }

    /// Its own address ("" for an unbound socket).
    public var localAddress: SocketAddress { get throws(IOError) { try reg.localAddress } }

    /// Set the default peer, for `send(_:)` and `receive(into:)`.
    public func connect(path: String) throws(IOError) {
        let to = try SocketAddress(unixPath: path)
        let e = withUnsafePointer(to: to.raw) { cv_connect_address(reg.fd, $0) }
        if e != 0 { throw IOError(code: e) }
    }

    /// Send one datagram to the default peer. Returns the bytes sent.
    @discardableResult
    public func send(_ bytes: UnsafeRawBufferPointer) async throws(IOError) -> Int {
        let fd = reg.fd
        return try await reg.perform(CV_IO_WRITE) { cv_send(fd, bytes.baseAddress, bytes.count) }
    }

    @discardableResult
    public func send(_ buffer: borrowing IOBuffer) async throws(IOError) -> Int {
        try await send(UnsafeRawBufferPointer(start: buffer.base, count: buffer.count))
    }

    /// Send one datagram to the socket at `path`.
    @discardableResult
    public func send(_ bytes: UnsafeRawBufferPointer, to path: String) async throws(IOError) -> Int {
        try await send(bytes, to: try SocketAddress(unixPath: path))
    }

    @discardableResult
    public func send(_ buffer: borrowing IOBuffer, to path: String) async throws(IOError) -> Int {
        try await send(UnsafeRawBufferPointer(start: buffer.base, count: buffer.count), to: path)
    }

    /// Send one datagram to `address` (a sender's, from `receiveFrom`).
    @discardableResult
    public func send(_ bytes: UnsafeRawBufferPointer, to address: SocketAddress) async throws(IOError) -> Int {
        let fd = reg.fd
        var to = address.raw
        return try await reg.perform(CV_IO_WRITE) { cv_sendto(fd, bytes.baseAddress, bytes.count, &to) }
    }

    /// Receive one datagram into `buffer`'s spare capacity: its length.
    public func receive(into buffer: inout IOBuffer) async throws(IOError) -> Int {
        precondition(buffer.spareCapacity > 0, "receive into a full IOBuffer")
        let fd = reg.fd
        let at = buffer.base + buffer.count, room = buffer.spareCapacity
        let n = try await reg.perform(CV_IO_READ) { cv_recv(fd, at, room) }
        buffer.count += n
        return n
    }

    /// Receive one datagram, with its sender's address (its `host` is the
    /// sender's path, "" for an unbound sender).
    public func receiveFrom(into buffer: inout IOBuffer) async throws(IOError) -> (count: Int, from: SocketAddress) {
        precondition(buffer.spareCapacity > 0, "receive into a full IOBuffer")
        let fd = reg.fd
        let at = buffer.base + buffer.count, room = buffer.spareCapacity
        var from = cv_sockaddr()
        let n = try await reg.perform(CV_IO_READ) { cv_recvfrom(fd, at, room, &from) }
        buffer.count += n
        return (n, SocketAddress(raw: from))
    }
}
#endif
