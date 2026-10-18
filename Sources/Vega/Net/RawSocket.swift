#if os(Linux) || canImport(Darwin)
import CVega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// A raw IP socket: whole packets of one IP protocol, below TCP and UDP, as
/// socket2's `Type::RAW` gives Tokio. Linux and Darwin (Windows restricts
/// raw sends and has no ping socket).
///
/// ```swift
/// let ping = try RawSocket.ping(.ipv4)          // no privilege needed
/// try await ping.send(echoRequest, to: SocketAddress(numericHost: "127.0.0.1", port: 0)!)
/// var buf = IOBuffer(capacity: 1500)
/// let (n, from) = try await ping.receiveFrom(into: &buf)
/// ```
///
/// Two kinds:
///
/// - ``open(_:protocol:)``: SOCK_RAW. Needs root or CAP_NET_RAW; without
///   them the open throws EPERM (or EACCES), so a program can fall back. An
///   IPv4 socket receives each packet with its IP header in front; an IPv6
///   one without (the kernel strips it). Sends carry the payload only,
///   unless `SocketOption.headerIncluded` is on (IPv4).
/// - ``ping(_:)``: the unprivileged ICMP socket (SOCK_DGRAM, IPPROTO_ICMP),
///   for echo requests only. Linux allows it to the groups in
///   `net.ipv4.ping_group_range` (none by default on many distributions:
///   EACCES), fills in the checksum, and sets the echo identifier to the
///   socket's own; receives carry the ICMP message alone. Darwin allows it
///   to everyone, and an IPv4 receive there carries the IP header too.
///
/// Addresses are `SocketAddress`es whose port means nothing (give 0). Each
/// receive takes one packet; one longer than the buffer's spare capacity
/// is cut short. Closing is dropping.
public struct RawSocket: ~Copyable, Sendable {
    let reg: IORegistration

    init(reg: IORegistration) { self.reg = reg }

    /// The IP version of a raw socket.
    public enum Family: Sendable {
        case ipv4, ipv6
    }

    /// A SOCK_RAW socket for IP protocol number `protocol` (1 for ICMP, 58
    /// for ICMPv6, 17 for UDP, ...). Throws EPERM or EACCES without the
    /// privilege. Call from a task on a Vega runtime.
    public static func open(_ family: Family, protocol: Int) throws(IOError) -> RawSocket {
        let driver = try IODriver.current()
        var err: Int32 = 0
        let fd = cv_raw_socket(family == .ipv6 ? 1 : 0, 0, Int32(`protocol`), &err)
        guard fd >= 0 else { throw IOError(code: err) }
        return RawSocket(reg: try IORegistration(fd: fd, driver: driver))
    }

    /// An ICMP (ICMPv6 for `.ipv6`) echo socket that needs no privilege
    /// where the system allows it (see the type's notes). Throws EACCES
    /// where it doesn't. Call from a task on a Vega runtime.
    public static func ping(_ family: Family = .ipv4) throws(IOError) -> RawSocket {
        let driver = try IODriver.current()
        var err: Int32 = 0
        let fd = cv_raw_socket(family == .ipv6 ? 1 : 0, 1, 0, &err)
        guard fd >= 0 else { throw IOError(code: err) }
        return RawSocket(reg: try IORegistration(fd: fd, driver: driver))
    }

    deinit { reg.close() }

    public var localAddress: SocketAddress { get throws(IOError) { try reg.localAddress } }

    /// Take only packets sent to `address` (a local address). On a Linux
    /// ping socket the port is the echo identifier to use (0: any free one).
    public func bind(to address: SocketAddress) throws(IOError) {
        let e = withUnsafePointer(to: address.raw) { cv_bind_address(reg.fd, $0) }
        if e != 0 { throw IOError(code: e) }
    }

    /// Set the default peer, for `send(_:)` and `receive(into:)`: packets
    /// from other addresses are then dropped by the kernel.
    public func connect(to address: SocketAddress) throws(IOError) {
        let e = withUnsafePointer(to: address.raw) { cv_connect_address(reg.fd, $0) }
        if e != 0 { throw IOError(code: e) }
    }

    /// Send one packet to the default peer. Returns the bytes sent.
    @discardableResult
    public func send(_ bytes: UnsafeRawBufferPointer) async throws(IOError) -> Int {
        let fd = reg.fd
        return try await reg.perform(CV_IO_WRITE) { cv_send(fd, bytes.baseAddress, bytes.count) }
    }

    @discardableResult
    public func send(_ buffer: borrowing IOBuffer) async throws(IOError) -> Int {
        try await send(UnsafeRawBufferPointer(start: buffer.base, count: buffer.count))
    }

    /// Send one packet to `address`. Returns the bytes sent.
    @discardableResult
    public func send(_ bytes: UnsafeRawBufferPointer, to address: SocketAddress) async throws(IOError) -> Int {
        let fd = reg.fd
        var to = address.raw
        return try await reg.perform(CV_IO_WRITE) { cv_sendto(fd, bytes.baseAddress, bytes.count, &to) }
    }

    @discardableResult
    public func send(_ buffer: borrowing IOBuffer, to address: SocketAddress) async throws(IOError) -> Int {
        try await send(UnsafeRawBufferPointer(start: buffer.base, count: buffer.count), to: address)
    }

    /// Receive one packet into `buffer`'s spare capacity: its length.
    public func receive(into buffer: inout IOBuffer) async throws(IOError) -> Int {
        precondition(buffer.spareCapacity > 0, "receive into a full IOBuffer")
        let fd = reg.fd
        let at = buffer.base + buffer.count, room = buffer.spareCapacity
        let n = try await reg.perform(CV_IO_READ) { cv_recv(fd, at, room) }
        buffer.readable += n
        return n
    }

    /// Receive one packet, with the address it came from.
    public func receiveFrom(into buffer: inout IOBuffer) async throws(IOError) -> (count: Int, from: SocketAddress) {
        precondition(buffer.spareCapacity > 0, "receive into a full IOBuffer")
        let fd = reg.fd
        let at = buffer.base + buffer.count, room = buffer.spareCapacity
        var from = cv_sockaddr()
        let n = try await reg.perform(CV_IO_READ) { cv_recvfrom(fd, at, room, &from) }
        buffer.readable += n
        return (n, SocketAddress(raw: from))
    }
}
#endif
