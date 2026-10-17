import NIOConcurrencyHelpers
import NIOCore
import Synchronization
import class Vega.Runtime
import struct Vega.TCPListener
import struct Vega.UnixListener

/// A listening TCP socket as a NIO server `Channel`, over a Vega
/// `TCPListener`, or a Unix one over a `UnixListener`. Each accepted
/// connection comes down the pipeline as a `Channel` on a loop of the child
/// group, and registers there once it has passed through.
final class VegaServerSocketChannel: Channel, ChannelCore, @unchecked Sendable {
    let loop: VegaEventLoop
    let childGroup: EventLoopGroup
    let parent: Channel? = nil
    let allocator = ByteBufferAllocator()
    private var _pipeline: ChannelPipeline!
    private let closePromise: EventLoopPromise<Void>

    // On the loop.
    private enum Lifecycle { case fresh, registered, active, closed }
    private var lifecycle = Lifecycle.fresh
    private var options = Options()
    private var acceptor: Acceptor?
    private var fd: Int32 = -1

    private let active = Atomic<Bool>(false)
    private let address = NIOLockedValueBox<SocketAddress?>(nil)

    init(loop: VegaEventLoop, childGroup: EventLoopGroup) {
        self.loop = loop
        self.childGroup = childGroup
        closePromise = loop.makePromise()
        _pipeline = ChannelPipeline(channel: self)
    }

    var eventLoop: EventLoop { loop }
    var pipeline: ChannelPipeline { _pipeline }
    var closeFuture: EventLoopFuture<Void> { closePromise.futureResult }
    var _channelCore: ChannelCore { self }
    var isActive: Bool { active.load(ordering: .relaxed) }
    var isWritable: Bool { false }
    var localAddress: SocketAddress? { address.withLockedValue { $0 } }
    var remoteAddress: SocketAddress? { nil }

    func setOption<Option: ChannelOption>(_ option: Option, value: Option.Value) -> EventLoopFuture<Void> {
        if loop.inEventLoop { return loop.makeCompletedFuture { try setOption0(option, value: value) } }
        return loop.submit { try self.setOption0(option, value: value) }
    }

    func getOption<Option: ChannelOption>(_ option: Option) -> EventLoopFuture<Option.Value> {
        if loop.inEventLoop { return loop.makeCompletedFuture { try getOption0(option) } }
        return loop.submit { try self.getOption0(option) }
    }

    private func setOption0<Option: ChannelOption>(_ option: Option, value: Option.Value) throws {
        guard lifecycle != .closed else { throw ChannelError.ioOnClosedChannel }
        switch option {
        case let option as ChannelOptions.Types.SocketOption:
            let value = value as! SocketOptionValue
            options.set(option, value)
            if fd >= 0 { try setSocketOption(fd, option, value) }
        case is ChannelOptions.Types.AutoReadOption:
            let on = value as! Bool
            let was = options.autoRead
            options.autoRead = on
            if on && !was { readIfNeeded() }
        case is ChannelOptions.Types.BacklogOption:
            options.backlog = value as! ChannelOptions.Types.BacklogOption.Value
        case is ChannelOptions.Types.MaxMessagesPerReadOption, is ChannelOptions.Types.AllocatorOption,
             is ChannelOptions.Types.RecvAllocatorOption:
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
        case is ChannelOptions.Types.BacklogOption: return options.backlog as! Option.Value
        case is ChannelOptions.Types.MaxMessagesPerReadOption: return UInt(1) as! Option.Value
        case is ChannelOptions.Types.AllocatorOption: return allocator as! Option.Value
        default: throw ChannelError.operationUnsupported
        }
    }

    // MARK: ChannelCore

    func localAddress0() throws -> SocketAddress {
        guard let address = localAddress else { throw ChannelError.ioOnClosedChannel }
        return address
    }

    func remoteAddress0() throws -> SocketAddress { throw ChannelError.operationUnsupported }

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
        if let path = address.pathname {
            bindUnix(path: path, address: address, promise: promise)
            return
        }
        guard let host = address.ipAddress, let port = address.port else {
            promise?.fail(ChannelError.operationUnsupported)
            return
        }
        let reusePort = options.socket.contains { option, value in
            option == ChannelOptions.socketOption(.so_reuseport) && value != 0
        }
        let listener: TCPListener
        do throws(VegaIOError) {
            listener = try TCPListener.bind(host: host, port: port, backlog: Int(options.backlog), reusePort: reusePort)
        } catch {
            promise?.fail(nioError(error))
            return
        }
        fd = listener.fileDescriptor
        for (option, value) in options.socket where fd >= 0 {
            try? setSocketOption(fd, option, value)
        }
        let bound = (try? listener.localAddress).flatMap { try? SocketAddress($0) }
        becomeActive(Acceptor(listener, channel: self), address: bound, promise: promise)
    }

    /// Listen on a Unix socket at `path`, which must not exist yet. It is
    /// left behind when the channel closes, as on NIO.
    private func bindUnix(path: String, address: SocketAddress, promise: EventLoopPromise<Void>?) {
        let listener: UnixListener
        do throws(VegaIOError) {
            listener = try UnixListener.bind(path: path, backlog: Int(options.backlog))
        } catch {
            promise?.fail(nioError(error))
            return
        }
        fd = listener.fileDescriptor
        for (option, value) in options.socket where fd >= 0 {
            try? setSocketOption(fd, option, value)
        }
        becomeActive(Acceptor(UnixPathListener(listener: listener, address: address), channel: self),
                     address: address, promise: promise)
    }

    private func becomeActive(_ acceptor: Acceptor, address bound: SocketAddress?, promise: EventLoopPromise<Void>?) {
        self.address.withLockedValue { $0 = bound }
        lifecycle = .active
        active.store(true, ordering: .relaxed)
        self.acceptor = acceptor
        promise?.succeed(())
        pipeline.fireChannelActive()
        readIfNeeded()
    }

    func connect0(to address: SocketAddress, promise: EventLoopPromise<Void>?) {
        promise?.fail(ChannelError.operationUnsupported)
    }

    func write0(_ data: NIOAny, promise: EventLoopPromise<Void>?) {
        promise?.fail(ChannelError.operationUnsupported)
    }

    func flush0() {}

    func read0() {
        guard lifecycle == .active else { return }
        acceptor?.wantAccept()
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
        acceptor?.close()
        acceptor = nil
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

    /// An accepted channel made it through the pipeline: register it on its
    /// own loop.
    func channelRead0(_ data: NIOAny) {
        let child = unwrapData(data, as: VegaSocketChannel.self)
        child.loop.execute {
            let promise = child.loop.makePromise(of: Void.self)
            promise.futureResult.whenFailure { _ in child.close(promise: nil) }
            child.registerAlreadyConfigured0(promise: promise)
        }
    }

    func errorCaught0(error: Error) {}

    // MARK: From the acceptor (on the loop)

    func readIfNeeded() {
        if options.autoRead && lifecycle == .active { pipeline.read() }
    }

    func didAccept(_ child: VegaSocketChannel) {
        guard lifecycle == .active else {
            child.close(promise: nil)
            return
        }
        pipeline.fireChannelRead(child)
        pipeline.fireChannelReadComplete()
        readIfNeeded()
    }

    func acceptFailed(_ error: Error) {
        guard lifecycle == .active else { return }
        pipeline.fireErrorCaught(error)
        readIfNeeded()
    }
}

/// A listener an `Acceptor` takes connections from.
protocol StreamListener: ~Copyable, Sendable {
    func acceptStream() async throws(VegaIOError) -> StreamBox
}

extension TCPListener: StreamListener {
    func acceptStream() async throws(VegaIOError) -> StreamBox {
        StreamBox(try await accept())
    }
}

/// A Unix listener, with the address its connections are accepted at.
struct UnixPathListener: StreamListener, ~Copyable {
    let listener: UnixListener
    let address: SocketAddress

    func acceptStream() async throws(VegaIOError) -> StreamBox {
        StreamBox(try await listener.accept(), local: address, remote: nil)
    }
}

/// The task accepting a listener's connections, when its channel wants them.
final class Acceptor: Sendable {
    private struct Shared {
        var wanted = false
        var waiter: UnsafeContinuation<Bool, Never>?
        var closed = false
    }

    private let shared = NIOLockedValueBox(Shared())
    private let task = NIOLockedValueBox<Task<Void, Never>?>(nil)

    init<Listener: StreamListener & ~Copyable>(_ listener: consuming Listener, channel: VegaServerSocketChannel) {
        let loop = channel.loop, childGroup = channel.childGroup
        let task = loop.runtime.spawn(with: listener) { [self] listener in
            while await waitToAccept() {
                let stream: StreamBox
                do throws(VegaIOError) {
                    stream = try await listener.acceptStream()
                } catch {
                    if error == .cancelled { return }
                    await loop.run { channel.acceptFailed(nioError(error)) }
                    // Out of descriptors, say: don't spin.
                    try? await Runtime.sleep(for: .milliseconds(10))
                    continue
                }
                let childLoop = childGroup.next() as! VegaEventLoop
                let child = VegaSocketChannel(loop: childLoop, parent: channel, accepted: stream)
                await loop.run { channel.didAccept(child) }
            }
        }
        self.task.withLockedValue { $0 = task }
    }

    // Not inlined: Swift 6.3.3's optimizer miscompiles a continuation stored
    // under a pthread lock (NIOLock) once this is inlined into a loop whose
    // body also awaits; resuming it then jumps to address 0 (release only).
    @inline(never)
    private func waitToAccept() async -> Bool {
        await withUnsafeContinuation { (c: UnsafeContinuation<Bool, Never>) in
            let now: Bool? = shared.withLockedValue { s in
                if s.closed { return false }
                if s.wanted {
                    s.wanted = false
                    return true
                }
                s.waiter = c
                return nil
            }
            if let now { c.resume(returning: now) }
        }
    }

    func wantAccept() {
        let c = shared.withLockedValue { s -> UnsafeContinuation<Bool, Never>? in
            if let w = s.waiter {
                s.waiter = nil
                return w
            }
            s.wanted = true
            return nil
        }
        c?.resume(returning: true)
    }

    func close() {
        let c = shared.withLockedValue { s -> UnsafeContinuation<Bool, Never>? in
            s.closed = true
            defer { s.waiter = nil }
            return s.waiter
        }
        c?.resume(returning: false)
        task.withLockedValue { $0?.cancel() }
    }
}
