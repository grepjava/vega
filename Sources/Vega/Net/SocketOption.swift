#if os(Linux) || canImport(Darwin) || os(Windows)
import CVega

/// A socket option, for the methods of ``SocketHandle``.
///
/// ```swift
/// try stream.setOption(.keepAlive, to: true)
/// try stream.setOption(.keepAliveIdle, to: 30)
/// let size = try socket.option(.receiveBufferSize)
/// ```
///
/// Values are integers: 0 and 1 for flags, seconds or bytes where noted.
/// An option the platform lacks throws `ENOPROTOOPT`.
public struct SocketOption: Sendable, Hashable {
    let id: Int32

    private init(_ id: Int) { self.id = Int32(id) }

    /// TCP_NODELAY: send small writes at once (Vega sets it on every TCP socket).
    public static let noDelay = SocketOption(CV_OPT_TCP_NODELAY)
    /// SO_KEEPALIVE: probe an idle connection to find a dead peer.
    public static let keepAlive = SocketOption(CV_OPT_KEEPALIVE)
    /// Seconds idle before the first keep-alive probe.
    public static let keepAliveIdle = SocketOption(CV_OPT_TCP_KEEPIDLE)
    /// Seconds between keep-alive probes.
    public static let keepAliveInterval = SocketOption(CV_OPT_TCP_KEEPINTVL)
    /// Unanswered probes before the connection is dropped.
    public static let keepAliveCount = SocketOption(CV_OPT_TCP_KEEPCNT)
    /// TCP_USER_TIMEOUT: milliseconds sent data may stay unacknowledged
    /// before the connection is dropped (Linux).
    public static let userTimeout = SocketOption(CV_OPT_TCP_USER_TIMEOUT)
    /// TCP_QUICKACK: acknowledge at once instead of delaying (Linux; the
    /// kernel may turn it off again).
    public static let quickAck = SocketOption(CV_OPT_TCP_QUICKACK)
    /// TCP_FASTOPEN on a listener: how many Fast Open requests may queue.
    public static let fastOpen = SocketOption(CV_OPT_TCP_FASTOPEN)
    /// SO_RCVBUF, in bytes (Linux doubles what you set and reports that).
    public static let receiveBufferSize = SocketOption(CV_OPT_RCVBUF)
    /// SO_SNDBUF, in bytes (Linux doubles what you set and reports that).
    public static let sendBufferSize = SocketOption(CV_OPT_SNDBUF)
    public static let reuseAddress = SocketOption(CV_OPT_REUSEADDR)
    public static let reusePort = SocketOption(CV_OPT_REUSEPORT)
    /// SO_BROADCAST: allow sending to a broadcast address.
    public static let broadcast = SocketOption(CV_OPT_BROADCAST)
    /// IPV6_V6ONLY: an IPv6 socket that does not also take IPv4.
    public static let ipv6Only = SocketOption(CV_OPT_IPV6_V6ONLY)
    /// IP_TTL: hop limit of outgoing IPv4 packets.
    public static let timeToLive = SocketOption(CV_OPT_IP_TTL)
    /// IP_TOS: the IPv4 type-of-service byte (DSCP and ECN).
    public static let typeOfService = SocketOption(CV_OPT_IP_TOS)
    /// IPV6_UNICAST_HOPS: hop limit of outgoing IPv6 packets.
    public static let hopLimit = SocketOption(CV_OPT_IPV6_UNICAST_HOPS)
    /// IPV6_TCLASS: the IPv6 traffic class byte.
    public static let trafficClass = SocketOption(CV_OPT_IPV6_TCLASS)
    /// IP_MULTICAST_TTL: hop limit of outgoing IPv4 multicast.
    public static let multicastTimeToLive = SocketOption(CV_OPT_IP_MULTICAST_TTL)
    /// IP_MULTICAST_LOOP: deliver our own IPv4 multicast back to us.
    public static let multicastLoop = SocketOption(CV_OPT_IP_MULTICAST_LOOP)
    /// IPV6_MULTICAST_HOPS: hop limit of outgoing IPv6 multicast.
    public static let multicastHopLimit = SocketOption(CV_OPT_IPV6_MULTICAST_HOPS)
    /// IPV6_MULTICAST_LOOP: deliver our own IPv6 multicast back to us.
    public static let multicastLoopV6 = SocketOption(CV_OPT_IPV6_MULTICAST_LOOP)
    /// UDP_GRO: let the kernel coalesce datagrams from one sender; read
    /// them with `UDPSocket.receiveSegments(into:)` (Linux).
    public static let udpGRO = SocketOption(CV_OPT_UDP_GRO)
    /// SO_LINGER, in seconds; -1 turns it off (the default). 0 makes close
    /// reset the connection instead of a graceful FIN.
    public static let linger = SocketOption(CV_OPT_LINGER)
}

/// A Vega socket: options, and the OS handle for anything Vega doesn't wrap.
public protocol SocketHandle: ~Copyable {
    /// The socket's file descriptor. Vega owns it: don't close it, and keep
    /// it non-blocking.
    var fileDescriptor: Int32 { get }
}

extension SocketHandle where Self: ~Copyable {
    public func setOption(_ option: SocketOption, to value: Int) throws(IOError) {
        // No fd: a Network.framework socket (IOBackend.network).
        guard fileDescriptor >= 0 else { throw .unsupported }
        let e = cv_sockopt_set(fileDescriptor, option.id, Int32(clamping: value))
        if e != 0 { throw IOError(code: e) }
    }

    public func setOption(_ option: SocketOption, to value: Bool) throws(IOError) {
        try setOption(option, to: value ? 1 : 0)
    }

    public func option(_ option: SocketOption) throws(IOError) -> Int {
        guard fileDescriptor >= 0 else { throw .unsupported }
        var value: Int32 = 0
        let e = cv_sockopt_get(fileDescriptor, option.id, &value)
        if e != 0 { throw IOError(code: e) }
        return Int(value)
    }
}

// TCP sockets can be Network.framework connections (IOBackend.network),
// which have no fd: their options are read from how they were made.
extension TCPListener {
    public func setOption(_ option: SocketOption, to value: Int) throws(IOError) {
        try reg.setOption(option, to: value)
    }
    public func setOption(_ option: SocketOption, to value: Bool) throws(IOError) {
        try reg.setOption(option, to: value ? 1 : 0)
    }
    public func option(_ option: SocketOption) throws(IOError) -> Int { try reg.option(option) }
}

extension TCPStream {
    public func setOption(_ option: SocketOption, to value: Int) throws(IOError) {
        try reg.setOption(option, to: value)
    }
    public func setOption(_ option: SocketOption, to value: Bool) throws(IOError) {
        try reg.setOption(option, to: value ? 1 : 0)
    }
    public func option(_ option: SocketOption) throws(IOError) -> Int { try reg.option(option) }
}

extension IORegistration {
    func setOption(_ option: SocketOption, to value: Int) throws(IOError) {
        #if canImport(Network)
        if let nw { return try nwSetOption(nw, option, value) }
        #endif
        let e = cv_sockopt_set(fd, option.id, Int32(clamping: value))
        if e != 0 { throw IOError(code: e) }
    }

    func option(_ option: SocketOption) throws(IOError) -> Int {
        #if canImport(Network)
        if let nw { return try nwOption(nw, option) }
        #endif
        var value: Int32 = 0
        let e = cv_sockopt_get(fd, option.id, &value)
        if e != 0 { throw IOError(code: e) }
        return Int(value)
    }
}

extension TCPListener: SocketHandle { public var fileDescriptor: Int32 { reg.fd } }
extension TCPStream: SocketHandle { public var fileDescriptor: Int32 { reg.fd } }
extension UDPSocket: SocketHandle { public var fileDescriptor: Int32 { reg.fd } }
extension UnixListener: SocketHandle { public var fileDescriptor: Int32 { reg.fd } }
extension UnixStream: SocketHandle { public var fileDescriptor: Int32 { reg.fd } }
extension ReadHalf: SocketHandle { public var fileDescriptor: Int32 { reg.fd } }
extension WriteHalf: SocketHandle { public var fileDescriptor: Int32 { reg.fd } }

/// A stream that can say, without reading or waiting, whether a read would
/// return at once: bytes waiting, end of stream, or an error. For a pool
/// looking at an idle connection: anything there means the server has
/// spoken unasked, usually to say it is going away.
public protocol PendingInputProbing: ~Copyable {
    var hasPendingInput: Bool { get }
}

extension TCPStream: PendingInputProbing { public var hasPendingInput: Bool { reg.hasPendingInput } }
extension UnixStream: PendingInputProbing { public var hasPendingInput: Bool { reg.hasPendingInput } }
extension ReadHalf: PendingInputProbing { public var hasPendingInput: Bool { reg.hasPendingInput } }
#endif
