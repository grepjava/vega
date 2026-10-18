#if os(Linux)
import CVega
import Glibc

/// A vsock address: a context id (which machine: the host, a guest, this
/// one) and a port. vsock connects a virtual machine and its host without
/// a network between them, as tokio-vsock does for Tokio. Linux only:
/// Darwin has AF_VSOCK only inside Virtualization.framework guests.
public struct VsockAddress: Sendable, Hashable, CustomStringConvertible {
    public var cid: UInt32
    public var port: UInt32

    public init(cid: UInt32, port: UInt32) {
        self.cid = cid
        self.port = port
    }

    /// VMADDR_CID_ANY: bind to every context id this machine has.
    public static let anyCID: UInt32 = 0xFFFF_FFFF
    /// VMADDR_CID_HYPERVISOR.
    public static let hypervisorCID: UInt32 = 0
    /// VMADDR_CID_LOCAL: this machine, through the loopback transport
    /// (Linux's vsock_loopback module).
    public static let localCID: UInt32 = 1
    /// VMADDR_CID_HOST: the host, seen from a guest.
    public static let hostCID: UInt32 = 2
    /// VMADDR_PORT_ANY: bind to any free port.
    public static let anyPort: UInt32 = 0xFFFF_FFFF

    /// The vsock address in `address`, or nil if it is another family's.
    public init?(_ address: SocketAddress) {
        var cid: UInt32 = 0, port: UInt32 = 0
        guard withUnsafePointer(to: address.raw, { cv_vsock_parts($0, &cid, &port) }) == 0 else { return nil }
        self.init(cid: cid, port: port)
    }

    /// `vsock:3:1234`.
    public var description: String { "vsock:\(cid):\(port)" }
}

extension SocketAddress {
    /// A vsock address, for code that takes any `SocketAddress`.
    public init(vsock address: VsockAddress) {
        var raw = cv_sockaddr()
        cv_vsock_sockaddr(address.cid, address.port, &raw)
        self.init(raw: raw)
    }

    /// The vsock address, or nil for any other family. A vsock address has
    /// no `port` or `ipBytes` (both nil) and an empty `host`.
    public var vsock: VsockAddress? { VsockAddress(self) }
}

/// A listening vsock stream socket: tokio-vsock's `VsockListener`.
///
/// ```swift
/// let listener = try VsockListener.bind(port: 5000)   // any context id
/// while true {
///     let stream = try await listener.accept()
///     rt.spawn(with: stream) { stream in await serve(stream) }
/// }
/// ```
public struct VsockListener: ~Copyable, Sendable {
    let reg: IORegistration

    /// Listen on `cid` (``VsockAddress/anyCID`` for all of this machine's)
    /// and `port` (``VsockAddress/anyPort`` picks a free one). Throws
    /// EAFNOSUPPORT where the kernel has no vsock, EADDRNOTAVAIL for a
    /// context id that isn't this machine's. Call from a task on a Vega
    /// runtime.
    public static func bind(cid: UInt32 = VsockAddress.anyCID, port: UInt32,
                            backlog: Int = 1024) throws(IOError) -> VsockListener {
        let driver = try IODriver.current()
        let address = SocketAddress(vsock: VsockAddress(cid: cid, port: port))
        var err: Int32 = 0
        let fd = withUnsafePointer(to: address.raw) { cv_listen_address($0, Int32(backlog), &err) }
        guard fd >= 0 else { throw IOError(code: err) }
        return VsockListener(reg: try IORegistration(fd: fd, driver: driver))
    }

    deinit { reg.close() }

    public var localAddress: VsockAddress { get throws(IOError) { try reg.vsockAddress(local: true) } }

    /// Wait for the next connection.
    public func accept() async throws(IOError) -> VsockStream {
        // accept4 knows nothing of families: the Unix one serves.
        VsockStream(reg: try await reg.accept(cv_unix_accept))
    }
}

/// A vsock stream connection: the same API as `TCPStream` and `UnixStream`,
/// on the same machinery (epoll or io_uring; nothing in it is TCP's).
public struct VsockStream: ~Copyable, Sendable {
    @usableFromInline let reg: IORegistration

    init(reg: IORegistration) { self.reg = reg }

    /// Connect to `port` on context `cid`. Throws ENETUNREACH or ENODEV
    /// where no transport reaches `cid` (vsock_loopback not loaded, for
    /// ``VsockAddress/localCID``), ECONNRESET or ECONNREFUSED where nothing
    /// listens. Call from a task on a Vega runtime.
    public static func connect(cid: UInt32, port: UInt32) async throws(IOError) -> VsockStream {
        try await connect(to: VsockAddress(cid: cid, port: port))
    }

    public static func connect(to address: VsockAddress) async throws(IOError) -> VsockStream {
        let driver = try IODriver.current()
        let to = SocketAddress(vsock: address)
        var err: Int32 = 0
        let fd = withUnsafePointer(to: to.raw) { cv_connect_new($0, socketStream, &err) }
        guard fd >= 0 else { throw IOError(code: err) }
        let stream = VsockStream(reg: try IORegistration(fd: fd, driver: driver))
        try await stream.reg.connected(err)
        return stream
    }

    deinit { reg.close() }

    public var localAddress: VsockAddress { get throws(IOError) { try reg.vsockAddress(local: true) } }
    public var peerAddress: VsockAddress { get throws(IOError) { try reg.vsockAddress(local: false) } }

    /// Read into `buffer`'s spare capacity. Returns the bytes read: 0 means
    /// the peer closed its side; a full buffer throws `IOError.limitExceeded`.
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

    /// Wait until a read would return at once, without reading.
    public func readable() async throws(IOError) {
        _ = try await reg.waitReadable()
    }

    /// Wait until the peer closes its side and return true, or return
    /// false as soon as input arrives (see `TCPStream.peerClosed()`).
    public func peerClosed() async throws(IOError) -> Bool {
        try await reg.waitReadable()
    }

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

    /// Write all of `parts` in order, gathered into as few system calls as
    /// possible. They must stay valid until this returns.
    @inlinable
    public func write(vectored parts: UnsafeBufferPointer<UnsafeRawBufferPointer>) async throws(IOError) {
        var status: Int32 = 0
        let sent = reg.sendNow(vectored: parts, &status)
        if status != 0 { try await reg.writeRest(vectored: parts, sent: sent, status: status) }
    }

    /// Stop sending: the peer reads end-of-stream once it has the rest.
    public func shutdownWrite() throws(IOError) { try reg.shutdownWrite() }

    /// Split into halves that different tasks can use at once (see
    /// `TCPStream.split()`).
    public consuming func split() -> SplitStream {
        let reg = self.reg
        discard self
        cv_io_split(reg.io)
        return SplitStream(reader: ReadHalf(reg: reg), writer: WriteHalf(reg: reg))
    }
}

extension IORegistration {
    func vsockAddress(local: Bool) throws(IOError) -> VsockAddress {
        let address: SocketAddress
        if local { address = try localAddress } else { address = try peerAddress }
        // The kernel names a vsock socket's own family only.
        guard let vsock = address.vsock else { throw IOError(code: EAFNOSUPPORT) }
        return vsock
    }
}
#endif
