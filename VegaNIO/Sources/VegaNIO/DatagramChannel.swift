import NIOConcurrencyHelpers
import NIOCore
import Synchronization
import class Vega.Runtime
import struct Vega.IOBuffer
import struct Vega.UDPSocket
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// A UDP socket as a NIO `Channel` of `AddressedEnvelope<ByteBuffer>`, over
/// a Vega `UDPSocket`.
///
/// As with a TCP channel, two Vega tasks do the I/O: a reader that receives
/// one datagram whenever the pipeline asks for a read, and a writer that
/// sends flushed datagrams in order. Each write's promise completes once its
/// datagram has gone. A datagram the network refuses (an ICMP error for an
/// earlier send, say) fails only its own write, or comes up as an error
/// while reading, and doesn't close the channel, as on NIO.
///
/// A connected channel (`VegaDatagramBootstrap.connect`, or `connect(to:)`
/// on a bound one) also takes plain `ByteBuffer` writes, as NIO's does, and
/// refuses an envelope for any other address.
final class VegaDatagramChannel: Channel, ChannelCore, @unchecked Sendable {
    let loop: VegaEventLoop
    let parent: Channel? = nil
    let allocator = ByteBufferAllocator()
    private var _pipeline: ChannelPipeline!
    private let closePromise: EventLoopPromise<Void>

    // On the loop.
    private enum Lifecycle { case fresh, registered, active, closed }
    private var lifecycle = Lifecycle.fresh
    private var options = Options()
    /// Written, not yet flushed.
    private var unflushed = CircularBuffer<(Datagram, EventLoopPromise<Void>?)>()
    /// Flushed, not yet sent: the writer reports them in order.
    private var inFlight = CircularBuffer<(Int, EventLoopPromise<Void>?)>()
    private var queuedBytes = 0
    private var io: DatagramIO?
    private var fd: Int32 = -1
    /// The default peer, once connected.
    private var peer: SocketAddress?
    /// The last address written to, converted: most channels write to a
    /// few peers, often one.
    private var lastTarget: (SocketAddress, VegaAddress)?

    private let active = Atomic<Bool>(false)
    private let writable = Atomic<Bool>(true)
    private let addresses = NIOLockedValueBox<(local: SocketAddress?, remote: SocketAddress?)>((nil, nil))

    init(loop: VegaEventLoop) {
        self.loop = loop
        closePromise = loop.makePromise()
        _pipeline = ChannelPipeline(channel: self)
    }

    // MARK: Channel

    var eventLoop: EventLoop { loop }
    var pipeline: ChannelPipeline { _pipeline }
    var closeFuture: EventLoopFuture<Void> { closePromise.futureResult }
    var _channelCore: ChannelCore { self }
    var isActive: Bool { active.load(ordering: .relaxed) }
    var isWritable: Bool { writable.load(ordering: .relaxed) }
    var localAddress: SocketAddress? { addresses.withLockedValue { $0.local } }
    var remoteAddress: SocketAddress? { addresses.withLockedValue { $0.remote } }
    var syncOptions: NIOSynchronousChannelOptions? { SyncOptions(channel: self) }

    func setOption<Option: ChannelOption>(_ option: Option, value: Option.Value) -> EventLoopFuture<Void> {
        if loop.inEventLoop { return loop.makeCompletedFuture { try setOption0(option, value: value) } }
        return loop.submit { try self.setOption0(option, value: value) }
    }

    func getOption<Option: ChannelOption>(_ option: Option) -> EventLoopFuture<Option.Value> {
        if loop.inEventLoop { return loop.makeCompletedFuture { try getOption0(option) } }
        return loop.submit { try self.getOption0(option) }
    }

    private struct SyncOptions: NIOSynchronousChannelOptions {
        let channel: VegaDatagramChannel
        func setOption<Option: ChannelOption>(_ option: Option, value: Option.Value) throws {
            channel.loop.preconditionInEventLoop()
            try channel.setOption0(option, value: value)
        }
        func getOption<Option: ChannelOption>(_ option: Option) throws -> Option.Value {
            channel.loop.preconditionInEventLoop()
            return try channel.getOption0(option)
        }
    }

    private func setOption0<Option: ChannelOption>(_ option: Option, value: Option.Value) throws {
        guard lifecycle != .closed else { throw ChannelError.ioOnClosedChannel }
        switch option {
        case let option as ChannelOptions.Types.SocketOption:
            // Kept for bind, which sets SO_REUSEADDR and SO_REUSEPORT before
            // binding; the rest go on the socket as well, once there is one.
            let value = value as! SocketOptionValue
            options.set(option, value)
            if fd >= 0 { try setSocketOption(fd, option, value) }
        case is ChannelOptions.Types.AutoReadOption:
            let on = value as! Bool
            let was = options.autoRead
            options.autoRead = on
            if on && !was { readIfNeeded() }
        case is ChannelOptions.Types.WriteBufferWaterMarkOption:
            options.waterMark = value as! ChannelOptions.Types.WriteBufferWaterMark
            updateWritability()
        case is ChannelOptions.Types.RecvAllocatorOption:
            options.recvAllocator = value as! RecvByteBufferAllocator
        // Batching knobs: each read takes one datagram here, whatever they say.
        case is ChannelOptions.Types.MaxMessagesPerReadOption, is ChannelOptions.Types.WriteSpinOption,
             is ChannelOptions.Types.AllocatorOption, is ChannelOptions.Types.DatagramVectorReadMessageCountOption:
            break
        default:
            throw ChannelError.operationUnsupported
        }
    }

    private func getOption0<Option: ChannelOption>(_ option: Option) throws -> Option.Value {
        guard lifecycle != .closed else { throw ChannelError.ioOnClosedChannel }
        switch option {
        case let option as ChannelOptions.Types.SocketOption:
            if fd >= 0 { return try getSocketOption(fd, option) as! Option.Value }
            return (options.value(option) ?? 0) as! Option.Value
        case is ChannelOptions.Types.AutoReadOption: return options.autoRead as! Option.Value
        case is ChannelOptions.Types.WriteBufferWaterMarkOption: return options.waterMark as! Option.Value
        case is ChannelOptions.Types.RecvAllocatorOption: return options.recvAllocator as! Option.Value
        case is ChannelOptions.Types.MaxMessagesPerReadOption: return UInt(1) as! Option.Value
        case is ChannelOptions.Types.WriteSpinOption: return UInt(0) as! Option.Value
        case is ChannelOptions.Types.AllocatorOption: return allocator as! Option.Value
        case is ChannelOptions.Types.DatagramVectorReadMessageCountOption: return 1 as! Option.Value
        case is ChannelOptions.Types.BufferedWritableBytesOption: return queuedBytes as! Option.Value
        default: throw ChannelError.operationUnsupported
        }
    }

    // MARK: ChannelCore

    func localAddress0() throws -> SocketAddress {
        guard let address = localAddress else { throw ChannelError.ioOnClosedChannel }
        return address
    }

    func remoteAddress0() throws -> SocketAddress {
        guard let address = remoteAddress else { throw ChannelError.ioOnClosedChannel }
        return address
    }

    func register0(promise: EventLoopPromise<Void>?) {
        guard lifecycle == .fresh else {
            promise?.fail(lifecycle == .closed ? ChannelError.ioOnClosedChannel : ChannelError.inappropriateOperationForState)
            return
        }
        do {
            try loop.register(self)
        } catch {
            promise?.fail(error)
            close0(error: error, mode: .all, promise: nil)
            return
        }
        lifecycle = .registered
        pipeline.fireChannelRegistered()
        promise?.succeed(())
    }

    func registerAlreadyConfigured0(promise: EventLoopPromise<Void>?) {
        promise?.fail(ChannelError.operationUnsupported)
    }

    func bind0(to address: SocketAddress, promise: EventLoopPromise<Void>?) {
        guard lifecycle == .registered else {
            promise?.fail(lifecycle == .closed ? ChannelError.ioOnClosedChannel : ChannelError.inappropriateOperationForState)
            return
        }
        // Unix datagram sockets: Vega has none yet.
        guard let host = address.ipAddress, let port = address.port else {
            promise?.fail(ChannelError.operationUnsupported)
            return
        }
        let socket: UDPSocket
        do throws(VegaIOError) {
            socket = try UDPSocket.bind(host: host, port: port, reusePort: isSet(.so_reuseport),
                                        reuseAddress: isSet(.so_reuseaddr))
        } catch {
            promise?.fail(nioError(error))
            return
        }
        becomeActive(socket, remote: nil, promise: promise)
    }

    /// Connect: on a channel not yet bound, a new socket on a free port
    /// whose default peer is `address`; on a bound one, set its default peer.
    func connect0(to address: SocketAddress, promise: EventLoopPromise<Void>?) {
        let target: VegaAddress
        do {
            target = try VegaAddress(address)
        } catch {
            promise?.fail(error)
            return
        }
        switch lifecycle {
        case .registered:
            let socket: UDPSocket
            do throws(VegaIOError) {
                socket = try UDPSocket.connect(to: target)
            } catch {
                promise?.fail(nioError(error))
                return
            }
            becomeActive(socket, remote: address, promise: promise)
        case .active:
            do throws(VegaIOError) {
                try io!.connect(to: target)
            } catch {
                promise?.fail(nioError(error))
                return
            }
            peer = address
            addresses.withLockedValue { $0.remote = address }
            promise?.succeed(())
        case .fresh, .closed:
            promise?.fail(lifecycle == .closed ? ChannelError.ioOnClosedChannel : ChannelError.inappropriateOperationForState)
        }
    }

    private func isSet(_ name: NIOBSDSocket.Option) -> Bool {
        (options.value(ChannelOptions.socketOption(name)) ?? 0) != 0
    }

    private func becomeActive(_ socket: consuming UDPSocket, remote: SocketAddress?, promise: EventLoopPromise<Void>?) {
        fd = socket.fileDescriptor
        for (option, value) in options.socket where fd >= 0 {
            try? setSocketOption(fd, option, value)
        }
        let local = (try? socket.localAddress).flatMap { try? SocketAddress($0) }
        addresses.withLockedValue { $0 = (local, remote) }
        peer = remote
        lifecycle = .active
        active.store(true, ordering: .relaxed)
        io = DatagramIO(socket, channel: self)
        promise?.succeed(())
        pipeline.fireChannelActive()
        readIfNeeded()
    }

    func write0(_ data: NIOAny, promise: EventLoopPromise<Void>?) {
        guard lifecycle == .active else {
            promise?.fail(ChannelError.ioOnClosedChannel)
            return
        }
        let datagram: Datagram
        if let envelope = tryUnwrapData(data, as: AddressedEnvelope<ByteBuffer>.self) {
            if let peer {
                // Connected: the kernel sends to the peer, and only there.
                guard envelope.remoteAddress == peer else {
                    promise?.fail(ChannelError.operationUnsupported)
                    return
                }
                datagram = Datagram(data: envelope.data, to: nil)
            } else {
                let to: VegaAddress
                if let (nio, vega) = lastTarget, nio == envelope.remoteAddress {
                    to = vega
                } else {
                    do {
                        to = try VegaAddress(envelope.remoteAddress)
                    } catch {
                        promise?.fail(error)
                        return
                    }
                    lastTarget = (envelope.remoteAddress, to)
                }
                datagram = Datagram(data: envelope.data, to: to)
            }
        } else {
            guard peer != nil else {
                promise?.fail(DatagramChannelError.WriteOnUnconnectedSocketWithoutAddress())
                return
            }
            datagram = Datagram(data: unwrapData(data, as: ByteBuffer.self), to: nil)
        }
        unflushed.append((datagram, promise))
        queuedBytes += datagram.data.readableBytes
        updateWritability()
    }

    func flush0() {
        guard lifecycle == .active, let io, !unflushed.isEmpty else { return }
        var batch: [Datagram] = []
        batch.reserveCapacity(unflushed.count)
        while let (datagram, promise) = unflushed.popFirst() {
            inFlight.append((datagram.data.readableBytes, promise))
            batch.append(datagram)
        }
        io.send(batch)
    }

    func read0() {
        guard lifecycle == .active, let io else { return }
        io.wantRead()
    }

    func close0(error: Error, mode: CloseMode, promise: EventLoopPromise<Void>?) {
        guard mode == .all else {
            promise?.fail(ChannelError.operationUnsupported)
            return
        }
        guard lifecycle != .closed else {
            promise?.fail(ChannelError.alreadyClosed)
            return
        }
        let was = lifecycle
        lifecycle = .closed
        active.store(false, ordering: .relaxed)
        while let (datagram, promise) = unflushed.popFirst() {
            queuedBytes -= datagram.data.readableBytes
            promise?.fail(error)
        }
        // What was flushed still goes, as on a TCP channel.
        io?.close(linger: VegaSocketChannel.closeLinger, runtime: loop.runtime)
        if was == .active { pipeline.fireChannelInactive() }
        if was != .fresh {
            loop.deregister(self)
            pipeline.fireChannelUnregistered()
        }
        promise?.succeed(())
        loop.execute { [self] in
            removeHandlers(pipeline: pipeline)
            closePromise.succeed(())
        }
    }

    func triggerUserOutboundEvent0(_ event: Any, promise: EventLoopPromise<Void>?) {
        promise?.fail(ChannelError.operationUnsupported)
    }

    func channelRead0(_ data: NIOAny) {}

    func errorCaught0(error: Error) {}

    // MARK: From the I/O tasks (on the loop)

    func readIfNeeded() {
        if options.autoRead && lifecycle == .active { pipeline.read() }
    }

    func didRead(_ envelope: AddressedEnvelope<ByteBuffer>) {
        guard lifecycle == .active else { return }
        pipeline.fireChannelRead(envelope)
        pipeline.fireChannelReadComplete()
        readIfNeeded()
    }

    /// A receive failed. An error about the network (an ICMP message for an
    /// earlier send) is reported and reading goes on; any other closes.
    func readFailed(_ error: VegaIOError) {
        guard lifecycle == .active else { return }
        pipeline.fireErrorCaught(nioError(error))
        if isTransient(error) {
            readIfNeeded()
        } else {
            close0(error: nioError(error), mode: .all, promise: nil)
        }
    }

    /// The writer sent the first `results.count` datagrams it was handed:
    /// nil for each that went.
    func didWrite(_ results: [VegaIOError?]) {
        var fatal: VegaIOError?
        for result in results {
            guard let (bytes, promise) = inFlight.popFirst() else { break }
            queuedBytes -= bytes
            if let result {
                promise?.fail(nioError(result))
                if !isTransient(result) { fatal = result }
            } else {
                promise?.succeed(())
            }
        }
        updateWritability()
        if let fatal, lifecycle == .active {
            pipeline.fireErrorCaught(nioError(fatal))
            close0(error: nioError(fatal), mode: .all, promise: nil)
        }
    }

    private func isTransient(_ error: VegaIOError) -> Bool {
        switch error.code {
        case ECONNREFUSED, ENETUNREACH, EHOSTUNREACH, EHOSTDOWN, ENETDOWN, EMSGSIZE, ENOBUFS, EACCES, EPERM,
             EADDRNOTAVAIL, EAFNOSUPPORT, EINVAL, ECONNRESET:
            true
        default:
            false
        }
    }

    private func updateWritability() {
        let was = writable.load(ordering: .relaxed)
        let now = was ? queuedBytes < options.waterMark.high : queuedBytes < options.waterMark.low
        guard now != was else { return }
        writable.store(now, ordering: .relaxed)
        if lifecycle == .active { pipeline.fireChannelWritabilityChanged() }
    }
}

/// A datagram to send: to the default peer when `to` is nil.
struct Datagram: Sendable {
    var data: ByteBuffer
    var to: VegaAddress?
}

/// The socket, which the reader and writer tasks use at once: Vega keeps a
/// waiter for each direction.
final class SocketBox: Sendable {
    let socket: UDPSocket
    init(_ socket: consuming UDPSocket) { self.socket = socket }
}

/// What a datagram channel's loop and its reader and writer share.
final class DatagramIO: Sendable {
    private struct Shared {
        var wantRead = false
        var reader: UnsafeContinuation<Bool, Never>?
        /// Flushed and not sent, for the writer.
        var writes: [Datagram] = []
        var writer: UnsafeContinuation<Bool, Never>?
        var closed = false
    }

    private let shared = NIOLockedValueBox(Shared())
    private let readerTask = NIOLockedValueBox<Task<Void, Never>?>(nil)
    private let writerTask = NIOLockedValueBox<Task<Void, Never>?>(nil)
    /// The tasks own the socket; this is for `connect(to:)` and goes at
    /// close, so the socket closes as soon as they are done with it.
    private let box: NIOLockedValueBox<SocketBox?>

    init(_ socket: consuming UDPSocket, channel: VegaDatagramChannel) {
        let loop = channel.loop
        let box = SocketBox(socket)
        self.box = NIOLockedValueBox(box)
        let reader = loop.runtime.spawn { [self] in
            // Room for the largest datagram, so none is cut short.
            var buffer = IOBuffer(capacity: 65_536)
            var last: (VegaAddress, SocketAddress)?
            while await waitToRead() {
                buffer.clear()
                let n: Int, from: VegaAddress
                do throws(VegaIOError) {
                    let received = try await box.socket.receiveFrom(into: &buffer)
                    n = received.count
                    from = received.from
                } catch {
                    if error == .cancelled { return }
                    await loop.run { channel.readFailed(error) }
                    continue
                }
                let sender: SocketAddress
                if let (vega, nio) = last, vega == from {
                    sender = nio
                } else {
                    guard let converted = try? SocketAddress(from) else { continue }
                    sender = converted
                    last = (from, converted)
                }
                var bytes = channel.allocator.buffer(capacity: n)
                buffer.withUnsafeBytes { _ = bytes.writeBytes($0) }
                let envelope = AddressedEnvelope(remoteAddress: sender, data: bytes)
                await loop.run { channel.didRead(envelope) }
            }
        }
        let writer = loop.runtime.spawn { [self] in
            while let batch = await waitToWrite() {
                var results: [VegaIOError?] = []
                results.reserveCapacity(batch.count)
                var cancelled = false
                for datagram in batch {
                    guard !cancelled else {
                        results.append(.cancelled)
                        continue
                    }
                    // The buffer's storage stays put while `batch` holds it.
                    let bytes = datagram.data.withUnsafeReadableBytes { $0 }
                    do throws(VegaIOError) {
                        if let to = datagram.to {
                            try await box.socket.send(bytes, to: to)
                        } else {
                            try await box.socket.send(bytes)
                        }
                        results.append(nil)
                    } catch {
                        // Closed, and out of time: the rest fail too.
                        if error == .cancelled { cancelled = true }
                        results.append(error)
                    }
                }
                await loop.run { [results] in channel.didWrite(results) }
                if cancelled { return }
            }
        }
        readerTask.withLockedValue { $0 = reader }
        writerTask.withLockedValue { $0 = writer }
    }

    /// Wait for the loop to want a read: false once closed.
    // Not inlined: Swift 6.3.3's optimizer miscompiles a continuation stored
    // under a pthread lock (NIOLock) once this is inlined into a loop whose
    // body also awaits; resuming it then jumps to address 0 (release only).
    @inline(never)
    private func waitToRead() async -> Bool {
        await withUnsafeContinuation { (c: UnsafeContinuation<Bool, Never>) in
            let now: Bool? = shared.withLockedValue { s in
                if s.closed { return false }
                if s.wantRead {
                    s.wantRead = false
                    return true
                }
                s.reader = c
                return nil
            }
            if let now { c.resume(returning: now) }
        }
    }

    /// Wait for datagrams to send: nil once closed with none left.
    private func waitToWrite() async -> [Datagram]? {
        while true {
            let taken = shared.withLockedValue { s -> [Datagram]?? in
                if !s.writes.isEmpty {
                    defer { s.writes.removeAll(keepingCapacity: true) }
                    return .some(s.writes)
                }
                return s.closed ? .some(nil) : nil
            }
            if let taken { return taken }
            await parkWriter()
        }
    }

    // Not inlined: see waitToRead.
    @inline(never)
    private func parkWriter() async {
        _ = await withUnsafeContinuation { (c: UnsafeContinuation<Bool, Never>) in
            let ready = shared.withLockedValue { s -> Bool in
                if s.closed || !s.writes.isEmpty { return true }
                s.writer = c
                return false
            }
            if ready { c.resume(returning: true) }
        }
    }

    /// Set the default peer.
    func connect(to address: VegaAddress) throws(VegaIOError) {
        guard let box = box.withLockedValue({ $0 }) else { throw .cancelled }
        try box.socket.connect(to: address)
    }

    func wantRead() {
        let c = shared.withLockedValue { s -> UnsafeContinuation<Bool, Never>? in
            if let r = s.reader {
                s.reader = nil
                return r
            }
            s.wantRead = true
            return nil
        }
        c?.resume(returning: true)
    }

    /// Hand `batch` to the writer.
    func send(_ batch: [Datagram]) {
        shared.withLockedValue { s -> UnsafeContinuation<Bool, Never>? in
            s.writes.append(contentsOf: batch)
            defer { s.writer = nil }
            return s.writer
        }?.resume(returning: true)
    }

    /// Stop reading now; let the writer send what it has, for up to `linger`.
    func close(linger: Duration, runtime: Runtime) {
        let (r, w, pending) = shared.withLockedValue {
            s -> (UnsafeContinuation<Bool, Never>?, UnsafeContinuation<Bool, Never>?, Bool) in
            s.closed = true
            defer {
                s.reader = nil
                s.writer = nil
            }
            // A parked writer has nothing in hand; one that isn't may.
            return (s.reader, s.writer, s.writer == nil || !s.writes.isEmpty)
        }
        r?.resume(returning: false)
        w?.resume(returning: false)
        box.withLockedValue { $0 = nil }
        readerTask.withLockedValue { $0?.cancel() }
        let writer = writerTask.withLockedValue { $0 }
        guard let writer, pending else { return }
        runtime.spawn {
            try? await Runtime.sleep(for: linger)
            writer.cancel()
        }
    }
}
