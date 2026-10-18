#if os(Linux) || canImport(Darwin) || os(Windows)
import CVega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#elseif os(Windows)
import ucrt
#endif

/// A UDP socket.
///
/// ```swift
/// let socket = try UDPSocket.bind(host: "0.0.0.0", port: 5353)
/// var buf = IOBuffer(capacity: 1500)
/// while true {
///     let (_, from) = try await socket.receiveFrom(into: &buf)
///     _ = try await socket.send(buf, to: from)
///     buf.clear()
/// }
/// ```
///
/// Each receive takes one datagram; one longer than the buffer's spare
/// capacity is cut short. Closing is dropping.
public struct UDPSocket: ~Copyable, Sendable {
    let reg: IORegistration

    /// Bind to `host` (an address or name; empty for all interfaces) and
    /// `port` (0 picks a free one). Call from a task on a Vega runtime.
    /// `reuseAddress` sets SO_REUSEADDR before binding, as a socket joining a
    /// multicast group usually wants (not on Windows, where it would let
    /// another socket take the port).
    public static func bind(host: String = "", port: Int,
                            reusePort: Bool = false, reuseAddress: Bool = false) throws(IOError) -> UDPSocket {
        let driver = try IODriver.current()
        var err: Int32 = 0
        let reuse = (reusePort ? CV_UDP_REUSEPORT : 0) | (reuseAddress ? CV_UDP_REUSEADDR : 0)
        let fd = cv_udp_bind(host, Int32(port), Int32(reuse), &err)
        guard fd >= 0 else { throw IOError(code: err) }
        return UDPSocket(reg: try IORegistration(fd: fd, driver: driver))
    }

    /// A socket on a free local port whose default peer is `host`:`port`,
    /// for `send(_:)` and `receive(into:)`. Datagrams from other addresses
    /// are dropped by the kernel. A name is looked up on the blocking pool
    /// and the first address it resolves to is used.
    public static func connect(host: String, port: Int) async throws(IOError) -> UDPSocket {
        _ = try IODriver.current()
        return try connect(to: try await SocketAddress.lookup(host: host, port: port)[0])
    }

    /// A socket on a free local port whose default peer is `address`.
    public static func connect(to address: SocketAddress) throws(IOError) -> UDPSocket {
        let driver = try IODriver.current()
        var err: Int32 = 0
        let fd = withUnsafePointer(to: address.raw) { cv_connect_new($0, socketDatagram, &err) }
        guard fd >= 0 else { throw IOError(code: err) }
        return UDPSocket(reg: try IORegistration(fd: fd, driver: driver))
    }

    deinit { reg.close() }

    public var localAddress: SocketAddress { get throws(IOError) { try reg.localAddress } }

    /// Set the default peer (see `connect(host:port:)`).
    public func connect(to address: SocketAddress) throws(IOError) {
        let e = withUnsafePointer(to: address.raw) { cv_connect_address(reg.fd, $0) }
        if e != 0 { throw IOError(code: e) }
    }

    /// Send one datagram to the default peer. Returns the bytes sent.
    @discardableResult
    public func send(_ bytes: UnsafeRawBufferPointer) async throws(IOError) -> Int {
        let fd = reg.fd
        #if os(Windows)
        let io = reg.io
        return try await reg.perform(CV_IO_WRITE, kind: CV_OVL_SENDTO) {
            cv_send(fd, bytes.baseAddress, bytes.count)
        } overlapped: { waiter, res in
            cv_ovl_sendto(io, waiter, bytes.baseAddress, bytes.count, nil, res)
        }
        #else
        return try await reg.perform(CV_IO_WRITE) { cv_send(fd, bytes.baseAddress, bytes.count) }
        #endif
    }

    @discardableResult
    public func send(_ buffer: borrowing IOBuffer) async throws(IOError) -> Int {
        try await send(UnsafeRawBufferPointer(start: buffer.base, count: buffer.count))
    }

    /// Send one datagram to `address`. Returns the bytes sent.
    @discardableResult
    public func send(_ bytes: UnsafeRawBufferPointer, to address: SocketAddress) async throws(IOError) -> Int {
        let fd = reg.fd
        var to = address.raw
        #if os(Windows)
        let io = reg.io
        return try await reg.perform(CV_IO_WRITE, kind: CV_OVL_SENDTO) {
            cv_sendto(fd, bytes.baseAddress, bytes.count, &to)
        } overlapped: { waiter, res in
            cv_ovl_sendto(io, waiter, bytes.baseAddress, bytes.count, &to, res)
        }
        #else
        return try await reg.perform(CV_IO_WRITE) {
            cv_sendto(fd, bytes.baseAddress, bytes.count, &to)
        }
        #endif
    }

    @discardableResult
    public func send(_ buffer: borrowing IOBuffer, to address: SocketAddress) async throws(IOError) -> Int {
        try await send(UnsafeRawBufferPointer(start: buffer.base, count: buffer.count), to: address)
    }

    /// Receive one datagram into `buffer`'s spare capacity. Returns its
    /// length (0 is an empty datagram, not end of stream).
    public func receive(into buffer: inout IOBuffer) async throws(IOError) -> Int {
        precondition(buffer.spareCapacity > 0, "receive into a full IOBuffer")
        let fd = reg.fd
        let at = buffer.base + buffer.count, room = buffer.spareCapacity
        #if os(Windows)
        let io = reg.io
        let n = try await reg.perform(CV_IO_READ, kind: CV_OVL_RECVFROM) { cv_recvfrom(fd, at, room, nil) }
            overlapped: { waiter, res in cv_ovl_recvfrom(io, waiter, at, room, res) }
        #else
        let n = try await reg.perform(CV_IO_READ) { cv_recv(fd, at, room) }
        #endif
        buffer.readable += n
        return n
    }

    /// Receive one datagram into `buffer`'s spare capacity, with its sender.
    public func receiveFrom(into buffer: inout IOBuffer) async throws(IOError) -> (count: Int, from: SocketAddress) {
        precondition(buffer.spareCapacity > 0, "receive into a full IOBuffer")
        let fd = reg.fd
        let at = buffer.base + buffer.count, room = buffer.spareCapacity
        var from = cv_sockaddr()
        #if os(Windows)
        let io = reg.io
        // The overlapped request leaves the sender in the request, for
        // cv_ovl_sender once it has completed.
        var waited = false
        let n = try await reg.perform(CV_IO_READ, kind: CV_OVL_RECVFROM) { cv_recvfrom(fd, at, room, &from) }
            overlapped: { waiter, res in
                waited = true
                return cv_ovl_recvfrom(io, waiter, at, room, res)
            }
        if waited { cv_ovl_sender(io, &from) }
        #else
        let n = try await reg.perform(CV_IO_READ) { cv_recvfrom(fd, at, room, &from) }
        #endif
        buffer.readable += n
        return (n, SocketAddress(raw: from))
    }
}
#endif
