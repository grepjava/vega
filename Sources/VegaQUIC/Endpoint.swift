// VegaCrypto's platforms and traits only: QUIC's TLS 1.3 is built on it.
#if (os(Linux) || os(macOS) || os(Windows)) && (OpenSSL || BoringSSL)
//===----------------------------------------------------------------------===//
// QUIC on Vega's UDP sockets: VegaQUIC's connections, which do no I/O of
// their own, driven by one task per socket.
//
// The endpoint's task owns everything QUIC for its socket: the table from
// connection ID to connection, and every `QUICConnectionState`. Nothing else
// touches them, so none of it is locked. Its loop: receive a batch of
// datagrams, waiting no longer than the earliest QUIC timer; feed each to its
// connection (or accept a new one, or answer with version negotiation);
// handle what the connections report; run the timers that are due; take
// what the application's tasks posted; and send what the connections have
// to say, one connection's datagrams coalesced into segmented sends (UDP GSO)
// where the kernel allows.
//
// The application's tasks hold `QUICConnection`s and
// `QUICStream`s (Handles.swift). A read waits for bytes the endpoint
// hands over; a write queues bytes and posts the stream, which wakes the
// endpoint early from its wait on the socket.
//
// The same loop as Garuda's HTTP/3 endpoint, without the HTTP.
//
// A client endpoint (`bind` without a configuration, then `connect`) is the same loop on a socket
// of its own: its connections are the ones it began, found by the connection
// ID they chose for themselves, and it accepts none.
//===----------------------------------------------------------------------===//

import CVega
import Synchronization
import Vega
import VegaIO
@_spi(Garuda) @_exported import VegaQUICCore
@_spi(Garuda) import VegaWire

/// A UDP socket speaking QUIC: a server (`bind` with a configuration, then
/// `accept`) or a client (`bind` without one, then `connect`).
///
/// ```swift
/// let configuration = QUICServerConfiguration(certificateKey: key, applicationProtocols: ["echo"])
/// let endpoint = try QUICEndpoint.bind(port: 4433, configuration: configuration, runtime: rt)
/// while let connection = await endpoint.accept() {
///     rt.spawn {
///         while let stream = await connection.acceptStream() {
///             rt.spawn {
///                 let bytes = try await stream.readAll()
///                 try await stream.write(bytes)
///                 stream.finish()
///             }
///         }
///     }
/// }
/// ```
///
/// ```swift
/// let endpoint = try QUICEndpoint.bind(runtime: rt)
/// let connection = try await endpoint.connect(host: "example.com", port: 443,
///                                             configuration: QUICClientConfiguration(serverName: "example.com",
///                                                                                    applicationProtocols: ["h3"]))
/// let stream = try await connection.openStream()
/// ```
public final class QUICEndpoint: @unchecked Sendable {
    /// Datagrams taken from the socket per system call.
    static let batchSize = 32
    /// The largest datagram taken or sent.
    static let datagramSize = 1500
    /// The most datagrams in one segmented send.
    static let maxSegments = 32
    /// The most datagrams one connection sends before the others get a turn.
    static let datagramsPerTurn = 1024
    /// Bytes queued on a QUIC stream before more are moved onto it.
    static let sendBudget = 256 * 1024
    static let socketBufferSize = 2 * 1024 * 1024

    enum Post {
        case stream(QUICStream)
        case open(QUICConnection)
        case close(QUICConnection, UInt64, [UInt8])
        /// A client connection, made by `connect`, to start.
        case connect(QUICConnection)
    }

    struct Shared {
        var posts: [Post] = []
        var accepted: [QUICConnection] = []
        var acceptWaiter: UnsafeContinuation<QUICConnection?, Never>?
        var stopRequested = false
        var graceMs: UInt64 = 0
        var stopped = false
        var stopWaiters: [UnsafeContinuation<Void, Never>] = []
    }

    let runtime: Runtime
    let serverConfig: QUICServerConfiguration?
    let shared = Locked(Shared())
    let wake = IODeadlineTrigger()
    /// The port the socket is bound to.
    public let localPort: Int
    /// Whether the socket is IPv6, which decides which of a name's
    /// addresses a client connects to.
    let localIsIPv6: Bool

    // MARK: The endpoint task's own

    var connections: [QUICConnectionID: EndpointConnection] = [:]
    var live: [EndpointConnection] = []
    var touched: [EndpointConnection] = []
    var replies: [(bytes: [UInt8], to: SocketAddress, from: SocketAddress?)] = []
    let sendBuffer: UnsafeMutablePointer<UInt8>
    var pendingLength = 0
    var pendingSegment = 0
    var pendingCount = 0
    var pendingPeer: SocketAddress?
    var pendingLocal: SocketAddress?
    var nextTimerMs = UInt64.max
    var stopping = false
    var stopDeadlineMs = UInt64.max

    private init(runtime: Runtime, serverConfig: QUICServerConfiguration?, localPort: Int, localIsIPv6: Bool) {
        self.runtime = runtime
        self.serverConfig = serverConfig
        self.localPort = localPort
        self.localIsIPv6 = localIsIPv6
        sendBuffer = .allocate(capacity: QUICEndpoint.datagramSize * QUICEndpoint.maxSegments)
    }

    deinit {
        sendBuffer.deallocate()
    }

    /// Bind a UDP socket and serve QUIC on it, with `configuration`'s
    /// certificates and application protocols. Port 0 picks one
    /// (`localPort`).
    public static func bind(host: String = "", port: Int, configuration: QUICServerConfiguration,
                              runtime: Runtime) throws(IOError) -> QUICEndpoint {
        let socket = try UDPSocket.bind(host: host, port: port)
        configure(socket)
        let local = try socket.localAddress
        let endpoint = QUICEndpoint(runtime: runtime, serverConfig: configuration,
                                    localPort: local.port ?? port, localIsIPv6: local.isIPv6)
        runtime.spawn(with: socket) { socket in await endpoint.run(socket) }
        return endpoint
    }

    /// Bind a UDP socket for client connections (`connect`): `host` is the
    /// local address, an IPv4 one for all interfaces when empty -- pass
    /// "::" to reach IPv6 servers -- and port 0 picks one. One endpoint
    /// carries any number of connections, to any servers.
    public static func bind(host: String = "", port: Int = 0, runtime: Runtime) throws(IOError) -> QUICEndpoint {
        let socket = try UDPSocket.bind(host: host.isEmpty ? "0.0.0.0" : host, port: port)
        configure(socket)
        let local = try socket.localAddress
        let endpoint = QUICEndpoint(runtime: runtime, serverConfig: nil, localPort: local.port ?? port,
                                    localIsIPv6: local.isIPv6)
        runtime.spawn(with: socket) { socket in await endpoint.run(socket) }
        return endpoint
    }

    /// Connect to a QUIC server and return once the handshake is done: the
    /// server's certificate checked as `configuration` says, an application
    /// protocol agreed (`applicationProtocol`). `host` is a name, looked up off the
    /// workers, or an address; the first of its addresses in the socket's
    /// family is used. Open streams with `openStream`; the server's arrive
    /// at `acceptStream`.
    ///
    /// A server that never answers is given up on after the configuration's
    /// idle timeout. A refused handshake throws `.connectionClosed` with the
    /// code QUIC closed it with: 0x100 plus the TLS alert, 0x12a when the
    /// certificate was refused.
    public func connect(host: String, port: Int,
                        configuration: QUICClientConfiguration) async throws(QUICConnectionError) -> QUICConnection {
        let addresses: [SocketAddress]
        do throws(IOError) {
            addresses = try await SocketAddress.lookup(host: host, port: port)
        } catch {
            throw .io(error)
        }
        guard let peer = addresses.first(where: { $0.isIPv6 == localIsIPv6 }) else {
            throw .io(IOError(code: -3, message: "\(host) has no \(localIsIPv6 ? "IPv6" : "IPv4") address for this endpoint"))
        }
        guard let quic = QUICConnectionState(client: configuration, nowMs: Self.nowMs()) else {
            throw .connectionClosed(code: QUICErrorCode.internalError.rawValue, application: false)
        }
        let connection = EndpointConnection(endpoint: self, quic: quic, isServer: false, peer: peer, local: nil,
                                            localCID: quic.localCID, originalDCID: quic.originalDCID)
        // Held strongly here until the handshake is done, so the endpoint's
        // weak reference outlives the wait.
        let handle = connection.handle!
        post(.connect(handle))
        try await handle.handshake()
        return handle
    }

    static func configure(_ socket: borrowing UDPSocket) {
        try? socket.enablePathInfo()
        try? socket.setDontFragment()
        try? socket.setOption(.receiveBufferSize, to: socketBufferSize)
        try? socket.setOption(.sendBufferSize, to: socketBufferSize)
    }

    /// The next connection whose handshake is done; nil once the endpoint
    /// is closed.
    public func accept() async -> QUICConnection? {
        await withUnsafeContinuation { (c: UnsafeContinuation<QUICConnection?, Never>) in
            let now = shared.withLock { s -> (Bool, QUICConnection?) in
                if !s.accepted.isEmpty { return (true, s.accepted.removeFirst()) }
                if s.stopped || s.stopRequested { return (true, nil) }
                precondition(s.acceptWaiter == nil, "QUICEndpoint.accept() called while another call waits")
                s.acceptWaiter = c
                return (false, nil)
            }
            if now.0 { c.resume(returning: now.1) }
        }
    }

    /// Stop taking connections, close the open ones (application code 0)
    /// once their streams are done or `grace` has passed, and return when
    /// the socket is closed.
    public func close(grace: Duration = .seconds(5)) async {
        let ms = UInt64(max(0, grace.components.seconds)) * 1000 + UInt64(max(0, grace.components.attoseconds / 1_000_000_000_000_000))
        let acceptWaiter = shared.withLock { s in
            s.stopRequested = true
            s.graceMs = ms
            defer { s.acceptWaiter = nil }
            return s.acceptWaiter
        }
        acceptWaiter?.resume(returning: nil)
        wake.fire()
        await withUnsafeContinuation { (c: UnsafeContinuation<Void, Never>) in
            let done = shared.withLock { s -> Bool in
                if s.stopped { return true }
                s.stopWaiters.append(c)
                return false
            }
            if done { c.resume() }
        }
    }

    /// From any task: something for the endpoint.
    func post(_ post: Post) {
        shared.withLock { $0.posts.append(post) }
        wake.fire()
    }

    static func nowMs() -> UInt64 { cv_now_ns() / 1_000_000 }

    // MARK: The loop

    func run(_ socket: borrowing UDPSocket) async {
        var batch = DatagramBatch(capacity: QUICEndpoint.batchSize, slotSize: QUICEndpoint.datagramSize)
        var busy = false
        while true {
            var now = Self.nowMs()
            var received = 0
            do {
                let wait: Duration = busy ? .zero : waitBefore(now)
                received = try await Runtime.withIODeadline(wait, trigger: wake) { () async throws(IOError) -> Int in
                    try await socket.receive(&batch)
                }
            } catch let error where error == .timedOut {
                // A timer is due, or a task posted something.
            } catch let error where error == .cancelled {
                break
            } catch {
                // An ICMP error for an earlier send: nothing about the socket.
            }
            now = Self.nowMs()
            for i in 0..<received where !batch.isTruncated(at: i) {
                let bytes = batch[i]
                guard let from = batch.address(at: i), let base = bytes.baseAddress else { continue }
                handleDatagram(UnsafeMutablePointer(mutating: base.assumingMemoryBound(to: UInt8.self)), bytes.count,
                               from: from, to: batch.localAddress(at: i), ecn: batch.ecn(at: i), nowMs: now)
            }
            busy = service(nowMs: now)
            if await flush(socket, nowMs: now) { busy = true }
            nextTimerMs = earliestTimer(nowMs: now)
            if stopping && live.isEmpty { break }
        }
        for connection in live { connection.abandon(.endpointClosed) }
        live.removeAll()
        connections.removeAll()
        let (accepted, waiters) = shared.withLock { s in
            s.stopped = true
            defer {
                s.accepted.removeAll()
                s.stopWaiters.removeAll()
            }
            return (s.accepted, s.stopWaiters)
        }
        for handle in accepted { handle.fail(.endpointClosed) }
        for waiter in waiters { waiter.resume() }
    }

    func waitBefore(_ now: UInt64) -> Duration {
        var until = now &+ 1000
        if nextTimerMs < until { until = nextTimerMs }
        if stopDeadlineMs < until { until = stopDeadlineMs }
        return until <= now ? .zero : .milliseconds(Int64(until &- now))
    }

    /// Posts, events, timers, shutdown. True when there is more at once.
    func service(nowMs now: UInt64) -> Bool {
        takePosts()
        serviceTouched()
        runTimers(nowMs: now)
        serviceTouched()
        checkShutdown(nowMs: now)
        takePosts()
        serviceTouched()
        reap()
        return shared.withLock { !$0.posts.isEmpty } || !touched.isEmpty
    }

    func touch(_ connection: EndpointConnection) {
        if !connection.touched {
            connection.touched = true
            touched.append(connection)
        }
    }

    func serviceTouched() {
        var rounds = 0
        while !touched.isEmpty && rounds < 4 {
            rounds &+= 1
            let servicing = touched
            touched.removeAll(keepingCapacity: true)
            for connection in servicing {
                connection.touched = false
                connection.handleEvents()
            }
        }
    }

    func runTimers(nowMs now: UInt64) {
        guard now >= nextTimerMs else { return }
        for connection in live {
            if let at = connection.quic.nextTimeout(nowMs: now), now >= at {
                connection.quic.onTimeout(nowMs: now)
                touch(connection)
            }
        }
    }

    func earliestTimer(nowMs now: UInt64) -> UInt64 {
        var earliest = UInt64.max
        for connection in live {
            if let at = connection.quic.nextTimeout(nowMs: now), at < earliest { earliest = at }
        }
        return earliest
    }

    func takePosts() {
        let posts = shared.withLock { s in
            defer { s.posts.removeAll(keepingCapacity: true) }
            return s.posts
        }
        for post in posts {
            switch post {
            case .stream(let stream):
                stream.state.withLock { $0.posted = false }
                stream.connection.core.pump(stream)
            case .open(let handle):
                handle.core.openStreams(handle)
            case .close(let handle, let code, let reason):
                if !handle.core.quic.isClosed { handle.core.quic.close(code, application: true, reason: reason) }
                touch(handle.core)
            case .connect(let handle):
                let connection = handle.core
                if stopping {
                    connection.abandon(.endpointClosed)
                    continue
                }
                // The server's datagrams come to the connection ID it chose
                // for itself; nothing comes to the one it invented for the
                // server.
                connections[connection.localCID] = connection
                live.append(connection)
                touch(connection)
            }
        }
    }

    /// Lets go of closed connections.
    func reap() {
        var i = 0
        while i < live.count {
            let connection = live[i]
            if connection.quic.isClosed {
                connection.abandon(nil)
                if connections[connection.localCID] === connection { connections[connection.localCID] = nil }
                if connections[connection.originalDCID] === connection { connections[connection.originalDCID] = nil }
                live.swapAt(i, live.count - 1)
                live.removeLast()
                continue
            }
            i &+= 1
        }
    }

    func checkShutdown(nowMs now: UInt64) {
        if !stopping {
            let (requested, grace) = shared.withLock { ($0.stopRequested, $0.graceMs) }
            guard requested else { return }
            stopping = true
            stopDeadlineMs = now &+ grace
        }
        let forced = now >= stopDeadlineMs
        for connection in live where !connection.quic.isClosed {
            if forced || connection.isQuiet {
                connection.quic.close(0, application: true)
                touch(connection)
            }
        }
        if forced {
            // Closing was sent: a peer that misses it is not waited for.
            for connection in live where connection.quic.status == .closing && !connection.quic.hasOutput {
                connection.abandon(.endpointClosed)
            }
            live.removeAll { $0.abandoned }
        }
    }

    // MARK: Datagrams in

    func handleDatagram(_ p: UnsafeMutablePointer<UInt8>, _ n: Int, from peer: SocketAddress,
                        to local: SocketAddress?, ecn: UInt8, nowMs now: UInt64) {
        guard n > 0 else { return }
        if p[0] & 0x80 != 0 {
            guard n >= 5 else { return }
            let version = UInt32(p[1]) << 24 | UInt32(p[2]) << 16 | UInt32(p[3]) << 8 | UInt32(p[4])
            if version == QUICVersion.negotiation {
                // An answer to a client's first Initial (RFC 9000 section 6):
                // its connection decides what it means. A server ignores them.
                let header = QUICPacket.parseHeader(p, n, localCIDLength: quicLocalCIDLength)
                if header.isValid, let connection = connections[header.dcid], !connection.isServer,
                   peer == connection.peer {
                    connection.quic.receive(p, n, ecn: ecn, nowMs: now)
                    touch(connection)
                }
                return
            }
            if !QUICVersion.isSupported(version) {
                if serverConfig != nil { negotiateVersion(p, n, from: peer, to: local) }
                return
            }
        }
        let header = QUICPacket.parseHeader(p, n, localCIDLength: quicLocalCIDLength)
        guard header.isValid else { return }
        if let connection = connections[header.dcid] {
            let quic = connection.quic
            if peer == connection.peer {
                quic.receive(p, n, ecn: ecn, nowMs: now)
                if quic.acceptedNewPacket { connection.local = local }
            } else if !connection.isServer {
                // A server does not move (RFC 9000 section 9): a datagram for
                // a client's connection from anywhere but the address it
                // connected to is not the server's.
                return
            } else {
                // A connection ID is in clear on the wire: a datagram from
                // elsewhere is another path, which the connection moves to
                // only once it has answered a challenge (QUICPath.swift).
                let (path, made) = connection.path(for: peer, local: local)
                quic.receive(p, n, ecn: ecn, path: path, nowMs: now)
                if made && !quic.datagramAuthenticated { connection.forgetPath(path) }
            }
            touch(connection)
            return
        }
        guard let config = serverConfig, header.type == .initial else { return }
        // RFC 9000 sections 14.1 and 7.2.
        guard n >= QUICPacket.minimumInitialSize, header.dcid.length >= 8 else { return }
        guard !stopping else { return }
        let localCID = QUICConnectionID.random()
        guard let quic = QUICConnectionState(config: config, version: header.version, clientDCID: header.dcid,
                                        clientSCID: header.scid, localCID: localCID, nowMs: now) else { return }
        let connection = EndpointConnection(endpoint: self, quic: quic, isServer: true, peer: peer, local: local,
                                            localCID: localCID, originalDCID: header.dcid)
        connections[localCID] = connection
        connections[header.dcid] = connection
        live.append(connection)
        quic.receive(p, n, ecn: ecn, nowMs: now)
        touch(connection)
    }

    /// RFC 9000 section 6: the versions this endpoint speaks, statelessly.
    private func negotiateVersion(_ p: UnsafeMutablePointer<UInt8>, _ n: Int, from peer: SocketAddress,
                                  to local: SocketAddress?) {
        guard n >= QUICPacket.minimumInitialSize else { return }
        var at = 5
        let dcidLength = Int(p[at])
        at &+= 1
        guard n >= at &+ dcidLength &+ 1 else { return }
        let dcid = UnsafeBufferPointer(start: p + at, count: dcidLength)
        at &+= dcidLength
        let scidLength = Int(p[at])
        at &+= 1
        guard n >= at &+ scidLength else { return }
        let scid = UnsafeBufferPointer(start: p + at, count: scidLength)
        var out: [UInt8] = [0x80 | 0x40, 0, 0, 0, 0]
        out.append(UInt8(scidLength))
        out.append(contentsOf: scid)
        out.append(UInt8(dcidLength))
        out.append(contentsOf: dcid)
        for version in [QUICVersion.v1, QUICVersion.v2] {
            out.append(UInt8(truncatingIfNeeded: version >> 24))
            out.append(UInt8(truncatingIfNeeded: version >> 16))
            out.append(UInt8(truncatingIfNeeded: version >> 8))
            out.append(UInt8(truncatingIfNeeded: version))
        }
        replies.append((out, peer, local))
    }

    /// A connection finished its handshake.
    func established(_ connection: EndpointConnection, _ handle: QUICConnection) {
        connection.handedOver()
        // A client's goes back to the `connect` that waits on it.
        guard connection.isServer else { return }
        let waiter = shared.withLock { s -> UnsafeContinuation<QUICConnection?, Never>? in
            if let w = s.acceptWaiter {
                s.acceptWaiter = nil
                return w
            }
            s.accepted.append(handle)
            return nil
        }
        waiter?.resume(returning: handle)
    }

    // MARK: Datagrams out

    func flush(_ socket: borrowing UDPSocket, nowMs now: UInt64) async -> Bool {
        if !replies.isEmpty {
            let sending = replies
            replies.removeAll(keepingCapacity: true)
            for reply in sending {
                let n = reply.bytes.count
                reply.bytes.withUnsafeBufferPointer { sendBuffer.update(from: $0.baseAddress!, count: n) }
                _ = try? await socket.send(segments: UnsafeRawBufferPointer(start: sendBuffer, count: n),
                                           segmentSize: n, to: reply.to, from: reply.from)
            }
        }
        var more = false
        for connection in live where connection.quic.hasOutput {
            if await writeAll(connection, socket, nowMs: now) { more = true }
        }
        for connection in live where connection.quic.hasProbes {
            await sendProbes(connection, socket, nowMs: now)
        }
        return more
    }

    private func sendProbes(_ connection: EndpointConnection, _ socket: borrowing UDPSocket, nowMs now: UInt64) async {
        for _ in 0..<QUICEndpoint.maxSegments {
            let (n, path) = connection.quic.nextProbeDatagram(sendBuffer, QUICEndpoint.datagramSize, nowMs: now)
            if n == 0 { break }
            guard let to = connection.paths.first(where: { $0.id == path }) else { continue }
            _ = try? await socket.send(segments: UnsafeRawBufferPointer(start: sendBuffer, count: n),
                                       segmentSize: n, to: to.peer, from: to.local)
        }
    }

    /// A connection's datagrams, built back to back into `sendBuffer` and
    /// sent a run of equal sizes at a time. True when its turn ran out.
    func writeAll(_ connection: EndpointConnection, _ socket: borrowing UDPSocket, nowMs now: UInt64) async -> Bool {
        var remaining = QUICEndpoint.datagramsPerTurn
        while remaining > 0 {
            remaining &-= 1
            let at = sendBuffer + pendingLength
            let n = connection.quic.nextDatagram(at, QUICEndpoint.datagramSize, nowMs: now)
            if n == 0 {
                remaining = -1
                break
            }
            if pendingLength == 0 {
                pendingPeer = connection.peer
                pendingLocal = connection.local
                pendingSegment = n
            } else if n > pendingSegment {
                let held = pendingLength
                await sendPending(socket, length: held)
                sendBuffer.update(from: sendBuffer + held, count: n)
                pendingPeer = connection.peer
                pendingLocal = connection.local
                pendingSegment = n
            }
            pendingLength &+= n
            pendingCount &+= 1
            if n < pendingSegment || pendingCount == QUICEndpoint.maxSegments {
                await sendPending(socket, length: pendingLength)
            }
        }
        await sendPending(socket, length: pendingLength)
        // Sending may have freed room on its streams.
        touch(connection)
        return remaining == 0
    }

    private func sendPending(_ socket: borrowing UDPSocket, length: Int) async {
        defer {
            pendingLength = 0
            pendingCount = 0
        }
        guard length > 0, let peer = pendingPeer else { return }
        let bytes = UnsafeRawBufferPointer(start: sendBuffer, count: length)
        _ = try? await socket.send(segments: bytes, segmentSize: pendingSegment, to: peer, from: pendingLocal)
    }
}

/// The endpoint task's side of one connection.
final class EndpointConnection {
    static let maxPaths = 4
    nonisolated(unsafe) private static let empty: UnsafeMutablePointer<UInt8> = .allocate(capacity: 1)

    unowned let endpoint: QUICEndpoint
    let quic: QUICConnectionState
    let isServer: Bool
    var peer: SocketAddress
    var local: SocketAddress?
    var paths: [(id: Int, peer: SocketAddress, local: SocketAddress?)] = []
    var nextPathID = 1
    let localCID: QUICConnectionID
    let originalDCID: QUICConnectionID
    var touched = false
    var announced = false
    var abandoned = false
    var streams: [UInt64: QUICStream] = [:]
    /// The application's handle. Held here until it is handed over (from
    /// `accept()` or `connect`), weakly after: a connection nobody holds,
    /// nor any of its streams, is closed.
    private var heldHandle: QUICConnection?
    private weak var weakHandle: QUICConnection?
    var handle: QUICConnection? { heldHandle ?? weakHandle }

    init(endpoint: QUICEndpoint, quic: QUICConnectionState, isServer: Bool, peer: SocketAddress, local: SocketAddress?,
         localCID: QUICConnectionID, originalDCID: QUICConnectionID) {
        self.endpoint = endpoint
        self.quic = quic
        self.isServer = isServer
        self.peer = peer
        self.local = local
        self.localCID = localCID
        self.originalDCID = originalDCID
        let handle = QUICConnection(endpoint: endpoint, core: self, remoteAddress: peer)
        heldHandle = handle
        weakHandle = handle
    }

    /// The handle has gone to the application.
    func handedOver() {
        heldHandle = nil
    }

    /// No stream left open: shutdown may close it now.
    var isQuiet: Bool { streams.isEmpty }

    func path(for address: SocketAddress, local: SocketAddress?) -> (id: Int, made: Bool) {
        if let known = paths.first(where: { $0.peer == address }) { return (known.id, false) }
        if paths.count == Self.maxPaths { paths.removeFirst() }
        let id = nextPathID
        nextPathID &+= 1
        paths.append((id, address, local))
        return (id, true)
    }

    func forgetPath(_ id: Int) {
        paths.removeAll { $0.id == id }
    }

    func handleEvents() {
        guard let handle else {
            // Dropped by the application, streams and all.
            if !quic.isClosed { quic.close(0, application: true) }
            quic.drainEvents { _ in }
            return
        }
        quic.drainEvents { event in
            switch event.kind {
            case .handshakeComplete:
                guard !announced else { return }
                announced = true
                handle.established(alpn: quic.selectedALPN, serverName: String(decoding: quic.serverName, as: UTF8.self))
                endpoint.established(self, handle)
                openStreams(handle)
            case .streamReadable, .streamFinished:
                readable(event.streamID, handle, finished: event.kind == .streamFinished)
            case .streamReset:
                if let stream = streams[event.streamID] {
                    stream.endRead(.failed(.streamReset(code: event.code)))
                    retireIfDone(stream)
                }
            case .stopSending:
                if let stream = streams[event.streamID] {
                    stream.endWrite(.stopSending(code: event.code))
                    // RFC 9000 section 3.5: answered with a reset.
                    quic.resetStream(event.streamID, code: event.code)
                    stream.state.withLock { $0.resetQueued = event.code }
                    retireIfDone(stream)
                }
            case .streamWritable:
                if let stream = streams[event.streamID] { pump(stream) }
            case .datagram:
                quic.incomingDatagrams.removeAll(keepingCapacity: true)
            case .closed:
                abandon(nil)
            case .pathValidated:
                guard let moved = paths.first(where: { $0.id == Int(event.code) }) else { return }
                let portOnly = moved.peer.host == peer.host
                peer = moved.peer
                local = moved.local
                paths.removeAll()
                quic.movedToValidatedPath(portOnly: portOnly)
            case .pathFailed:
                forgetPath(Int(event.code))
            }
        }
        if !quic.events.isEmpty { endpoint.touch(self) }
        // MAX_STREAMS may have raised what can be opened.
        openStreams(handle)
        // Room freed by acknowledgements lets queued bytes move.
        for stream in streams.values where stream.state.withLock({ $0.outbox.count > $0.outStart }) { pump(stream) }
    }

    /// A stream the peer opened, made on first sight.
    private func incoming(_ id: UInt64, _ handle: QUICConnection) -> QUICStream? {
        if let stream = streams[id] { return stream }
        let peerOpened = QUICStreamKind.isClientInitiated(id) == isServer
        guard peerOpened, announced else { return nil }
        let stream = QUICStream(id: id, connection: handle)
        if QUICStreamKind.isUnidirectional(id) {
            stream.state.withLock { s in
                s.writeEnd = .stopSending(code: 0)
                s.finQueued = true
            }
        }
        streams[id] = stream
        handle.deliver(stream)
        return stream
    }

    /// `finished`: the peer's FIN. Not `receive.finished`, which a reset
    /// sets too.
    private func readable(_ id: UInt64, _ handle: QUICConnection, finished: Bool) {
        guard let stream = incoming(id, handle), let q = quic.stream(id) else { return }
        let ready = q.receive.ready.readableBytes
        if ready > 0 {
            stream.received(q.receive.ready.readPointer, ready)
            q.receive.ready.consume(ready)
        }
        if finished && q.receive.finished && q.receive.ready.readableBytes == 0 {
            q.receive.delivered = true
            stream.endRead(.fin)
        }
        extendWindow(stream, q)
        retireIfDone(stream)
    }

    private func extendWindow(_ stream: QUICStream, _ q: QUICStreamState) {
        let held = stream.state.withLock { UInt64($0.inbox.count - $0.inStart) }
        let received = q.receive.received
        let consumed = received &- min(received, UInt64(q.receive.ready.readableBytes) &+ held)
        quic.extendStreamWindow(stream.id, consumed: consumed)
    }

    /// Move a stream's queued bytes, end and reset onto the transport.
    func pump(_ stream: QUICStream) {
        guard let q = quic.stream(stream.id) else { return }
        let id = stream.id
        let (writer, stop) = stream.state.withLock { s -> (UnsafeContinuation<Void, Never>?, UInt64?) in
            if let code = s.resetQueued {
                if q.send.resetCode == nil { quic.resetStream(id, code: code) }
            } else {
                let held = s.outbox.count - s.outStart
                let room = QUICEndpoint.sendBudget &- q.send.data.readableBytes
                if held > 0 && room > 0 {
                    let n = min(held, room)
                    let start = s.outStart
                    s.outbox.withUnsafeBufferPointer { quic.send(id, $0.baseAddress! + start, n, fin: false) }
                    s.outStart += n
                    if s.outStart == s.outbox.count {
                        s.outbox.removeAll(keepingCapacity: true)
                        s.outStart = 0
                    }
                }
                if s.finQueued && s.outbox.isEmpty && s.writeEnd == nil && !q.send.finQueued {
                    quic.send(id, Self.empty, 0, fin: true)
                }
            }
            var writer: UnsafeContinuation<Void, Never>?
            if s.outbox.count - s.outStart <= QUICStream.lowWater {
                writer = s.writer
                s.writer = nil
            }
            let stop = s.stopQueued
            s.stopQueued = nil
            return (writer, stop)
        }
        writer?.resume()
        if let stop { quic.stopSending(id, code: stop) }
        extendWindow(stream, q)
        retireIfDone(stream)
    }

    /// Both directions over, and the application has had everything.
    private func retireIfDone(_ stream: QUICStream) {
        guard let q = quic.stream(stream.id) else {
            streams[stream.id] = nil
            return
        }
        let done = stream.state.withLock { s -> Bool in
            let readDone = s.readEnd != nil && s.inbox.count == s.inStart
            let writeDone = s.resetQueued != nil || s.writeEnd != nil || (s.finQueued && s.outbox.isEmpty)
            return readDone && writeDone
        }
        if done {
            streams[stream.id] = nil
            quic.releaseStream(stream.id)
            _ = q
        }
    }

    /// Opens the application asked for, as far as the peer's limits allow.
    func openStreams(_ handle: QUICConnection) {
        guard announced, !quic.isClosed else { return }
        let opens = handle.takeOpens()
        for open in opens {
            guard let id = quic.openStream(unidirectional: open.unidirectional) else {
                handle.requeue(open)
                continue
            }
            let stream = QUICStream(id: id, connection: handle)
            if open.unidirectional { stream.state.withLock { $0.readEnd = .fin } }
            streams[id] = stream
            open.waiter.resume(returning: .success(stream))
        }
    }

    /// The connection is over: everything waiting on it fails.
    func abandon(_ error: QUICConnectionError?) {
        guard !abandoned else { return }
        abandoned = true
        let reason = error ?? .connectionClosed(code: quic.closeError, application: quic.closeIsApplication)
        for stream in streams.values { stream.fail(reason) }
        streams.removeAll()
        handle?.fail(reason)
        heldHandle = nil
    }
}
#endif
