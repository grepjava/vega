import NIOCore

/// NIO's `ServerBootstrap`, for a `VegaEventLoopGroup`: listens on TCP and
/// sets up each accepted connection's channel.
///
/// ```swift
/// let channel = try await VegaServerBootstrap(group: group)
///     .serverChannelOption(.backlog, value: 256)
///     .childChannelInitializer { channel in
///         channel.pipeline.configureHTTPServerPipeline().flatMap {
///             channel.pipeline.addHandler(HelloHandler())
///         }
///     }
///     .bind(host: "0.0.0.0", port: 8080).get()
/// ```
public final class VegaServerBootstrap {
    private let group: VegaEventLoopGroup
    private let childGroup: VegaEventLoopGroup
    private var serverChannelInit: (@Sendable (Channel) -> EventLoopFuture<Void>)?
    private var childChannelInit: (@Sendable (Channel) -> EventLoopFuture<Void>)?
    private var serverChannelOptions = ChannelOptions.Storage()
    private var childChannelOptions = ChannelOptions.Storage()

    public convenience init(group: VegaEventLoopGroup) {
        self.init(group: group, childGroup: group)
    }

    public init(group: VegaEventLoopGroup, childGroup: VegaEventLoopGroup) {
        self.group = group
        self.childGroup = childGroup
        childChannelOptions.append(key: ChannelOptions.tcpOption(.tcp_nodelay), value: 1)
    }

    /// nil unless both groups are `VegaEventLoopGroup`s.
    public convenience init?(validatingGroup group: EventLoopGroup, childGroup: EventLoopGroup? = nil) {
        guard let group = group as? VegaEventLoopGroup,
              let childGroup = (childGroup ?? group) as? VegaEventLoopGroup else { return nil }
        self.init(group: group, childGroup: childGroup)
    }

    /// Set up the listening channel's pipeline, before it binds.
    public func serverChannelInitializer(_ initializer: @escaping @Sendable (Channel) -> EventLoopFuture<Void>) -> Self {
        serverChannelInit = initializer
        return self
    }

    /// Set up each accepted channel's pipeline, on its loop.
    public func childChannelInitializer(_ initializer: @escaping @Sendable (Channel) -> EventLoopFuture<Void>) -> Self {
        childChannelInit = initializer
        return self
    }

    public func serverChannelOption<Option: ChannelOption>(_ option: Option, value: Option.Value) -> Self {
        serverChannelOptions.append(key: option, value: value)
        return self
    }

    public func childChannelOption<Option: ChannelOption>(_ option: Option, value: Option.Value) -> Self {
        childChannelOptions.append(key: option, value: value)
        return self
    }

    public func bind(host: String, port: Int) -> EventLoopFuture<Channel> {
        let address: SocketAddress
        do {
            address = try SocketAddress.makeAddressResolvingHost(host, port: port)
        } catch {
            return group.next().makeFailedFuture(error)
        }
        return bind(to: address)
    }

    public func bind(to address: SocketAddress) -> EventLoopFuture<Channel> {
        let loop = group.next() as! VegaEventLoop
        let serverChannel = VegaServerSocketChannel(loop: loop, childGroup: childGroup)
        let serverChannelInit = self.serverChannelInit
        let childChannelInit = self.childChannelInit
        let serverChannelOptions = self.serverChannelOptions
        let childChannelOptions = self.childChannelOptions
        return loop.flatSubmit {
            serverChannelOptions.applyAllChannelOptions(to: serverChannel).flatMap {
                serverChannelInit?(serverChannel) ?? loop.makeSucceededVoidFuture()
            }.flatMapThrowing {
                try serverChannel.pipeline.syncOperations.addHandler(
                    AcceptHandler(childChannelInitializer: childChannelInit, childChannelOptions: childChannelOptions),
                    name: "AcceptHandler"
                )
            }.flatMap {
                serverChannel.register()
            }.flatMap {
                serverChannel.bind(to: address)
            }.map {
                serverChannel as Channel
            }.flatMapError { error in
                serverChannel.close0(error: error, mode: .all, promise: nil)
                return loop.makeFailedFuture(error)
            }
        }
    }

    /// Bind, and take the accepted connections as an async sequence, each
    /// set up by `childChannelInitializer` (on its own loop) first.
    ///
    /// ```swift
    /// let server = try await VegaServerBootstrap(group: group).bind(host: "0.0.0.0", port: 8080) { channel in
    ///     channel.eventLoop.makeCompletedFuture {
    ///         try NIOAsyncChannel<ByteBuffer, ByteBuffer>(wrappingChannelSynchronously: channel)
    ///     }
    /// }
    /// try await server.executeThenClose { inbound in
    ///     for try await connection in inbound { ... }
    /// }
    /// ```
    public func bind<Output: Sendable>(
        host: String,
        port: Int,
        serverBackPressureStrategy: NIOAsyncSequenceProducerBackPressureStrategies.HighLowWatermark? = nil,
        childChannelInitializer: @escaping @Sendable (Channel) -> EventLoopFuture<Output>
    ) async throws -> NIOAsyncChannel<Output, Never> {
        let address = try SocketAddress.makeAddressResolvingHost(host, port: port)
        return try await bind(to: address, serverBackPressureStrategy: serverBackPressureStrategy,
                              childChannelInitializer: childChannelInitializer)
    }

    public func bind<Output: Sendable>(
        to address: SocketAddress,
        serverBackPressureStrategy: NIOAsyncSequenceProducerBackPressureStrategies.HighLowWatermark? = nil,
        childChannelInitializer: @escaping @Sendable (Channel) -> EventLoopFuture<Output>
    ) async throws -> NIOAsyncChannel<Output, Never> {
        let loop = group.next() as! VegaEventLoop
        let serverChannel = VegaServerSocketChannel(loop: loop, childGroup: childGroup)
        let serverChannelInit = self.serverChannelInit
        let childChannelInit = self.childChannelInit
        let serverChannelOptions = self.serverChannelOptions
        let childChannelOptions = self.childChannelOptions
        return try await loop.flatSubmit {
            serverChannelOptions.applyAllChannelOptions(to: serverChannel).flatMap {
                serverChannelInit?(serverChannel) ?? loop.makeSucceededVoidFuture()
            }.flatMapThrowing {
                try serverChannel.pipeline.syncOperations.addHandler(
                    AcceptHandler(childChannelInitializer: childChannelInit, childChannelOptions: childChannelOptions),
                    name: "AcceptHandler"
                )
                return try NIOAsyncChannel<Output, Never>._wrapAsyncChannelWithTransformations(
                    wrappingChannelSynchronously: serverChannel,
                    backPressureStrategy: serverBackPressureStrategy,
                    channelReadTransformation: { channel in
                        channel.eventLoop.flatSubmit { childChannelInitializer(channel) }
                    }
                )
            }.flatMap { asyncChannel in
                serverChannel.register().flatMap {
                    serverChannel.bind(to: address)
                }.map { asyncChannel }
            }.flatMapError { error in
                serverChannel.close0(error: error, mode: .all, promise: nil)
                return loop.makeFailedFuture(error)
            }
        }.get()
    }
}

@available(*, unavailable)
extension VegaServerBootstrap: Sendable {}

/// NIO's `ClientBootstrap`, for a `VegaEventLoopGroup`.
///
/// Conforms to `NIOClientTCPBootstrapProtocol`, so it slots into
/// `NIOClientTCPBootstrap` for code written against that.
public final class VegaClientBootstrap: NIOClientTCPBootstrapProtocol {
    private let group: VegaEventLoopGroup
    private var channelInit: (@Sendable (Channel) -> EventLoopFuture<Void>)?
    private var protocolHandlers: (@Sendable () -> [ChannelHandler])?
    private var channelOptions = ChannelOptions.Storage()
    private var timeout: TimeAmount?

    public init(group: VegaEventLoopGroup) {
        self.group = group
        channelOptions.append(key: ChannelOptions.tcpOption(.tcp_nodelay), value: 1)
    }

    /// nil unless `group` is a `VegaEventLoopGroup` or one of its loops.
    public convenience init?(validatingGroup group: EventLoopGroup) {
        guard let group = group as? VegaEventLoopGroup else { return nil }
        self.init(group: group)
    }

    public func channelInitializer(_ handler: @escaping @Sendable (Channel) -> EventLoopFuture<Void>) -> Self {
        channelInit = handler
        return self
    }

    public func protocolHandlers(_ handlers: @escaping @Sendable () -> [ChannelHandler]) -> Self {
        precondition(protocolHandlers == nil, "protocol handlers can only be set once")
        protocolHandlers = handlers
        return self
    }

    public func channelOption<Option: ChannelOption>(_ option: Option, value: Option.Value) -> Self {
        channelOptions.append(key: option, value: value)
        return self
    }

    public func connectTimeout(_ timeout: TimeAmount) -> Self {
        self.timeout = timeout
        return self
    }

    /// Connect to `host`, resolving it and racing its addresses (Happy Eyeballs).
    public func connect(host: String, port: Int) -> EventLoopFuture<Channel> {
        connect0 { channel, promise in channel.connect0(host: host, port: port, promise: promise) }
    }

    public func connect(to address: SocketAddress) -> EventLoopFuture<Channel> {
        connect0 { channel, promise in channel.connect(to: address, promise: promise) }
    }

    public func connect(unixDomainSocketPath: String) -> EventLoopFuture<Channel> {
        group.next().makeFailedFuture(ChannelError.operationUnsupported)
    }

    /// Connect, then wrap the channel as `channelInitializer` says (in an
    /// `NIOAsyncChannel`, say) once it is active.
    public func connect<Output: Sendable>(
        host: String,
        port: Int,
        channelInitializer: @escaping @Sendable (Channel) -> EventLoopFuture<Output>
    ) async throws -> Output {
        let channel = try await connect(host: host, port: port).get()
        return try await channel.eventLoop.flatSubmit { channelInitializer(channel) }.get()
    }

    public func connect<Output: Sendable>(
        to address: SocketAddress,
        channelInitializer: @escaping @Sendable (Channel) -> EventLoopFuture<Output>
    ) async throws -> Output {
        let channel = try await connect(to: address).get()
        return try await channel.eventLoop.flatSubmit { channelInitializer(channel) }.get()
    }

    private func connect0(
        _ connect: @escaping @Sendable (VegaSocketChannel, EventLoopPromise<Void>) -> Void
    ) -> EventLoopFuture<Channel> {
        let loop = group.next() as! VegaEventLoop
        let channel = VegaSocketChannel(loop: loop)
        let channelInit = self.channelInit
        let protocolHandlers = self.protocolHandlers
        let options = self.channelOptions
        let timeout = self.timeout
        return loop.flatSubmit {
            var setUp = options.applyAllChannelOptions(to: channel)
            if let timeout {
                setUp = setUp.flatMap { channel.setOption(.connectTimeout, value: timeout) }
            }
            return setUp.flatMapThrowing {
                if let handlers = protocolHandlers?() {
                    try channel.pipeline.syncOperations.addHandlers(handlers)
                }
            }.flatMap {
                channelInit?(channel) ?? loop.makeSucceededVoidFuture()
            }.flatMap {
                channel.register()
            }.flatMap {
                let promise = loop.makePromise(of: Void.self)
                connect(channel, promise)
                return promise.futureResult
            }.map {
                channel as Channel
            }.flatMapError { error in
                channel.close(promise: nil)
                return loop.makeFailedFuture(error)
            }
        }
    }
}

@available(*, unavailable)
extension VegaClientBootstrap: Sendable {}

/// Applies the child options and initializer to each accepted channel, on
/// its own loop, before passing it on.
final class AcceptHandler: ChannelInboundHandler {
    typealias InboundIn = Channel
    typealias InboundOut = Channel

    private let childChannelInitializer: (@Sendable (Channel) -> EventLoopFuture<Void>)?
    private let childChannelOptions: ChannelOptions.Storage

    init(childChannelInitializer: (@Sendable (Channel) -> EventLoopFuture<Void>)?,
         childChannelOptions: ChannelOptions.Storage) {
        self.childChannelInitializer = childChannelInitializer
        self.childChannelOptions = childChannelOptions
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let child = unwrapInboundIn(data)
        let childLoop = child.eventLoop
        let initializer = childChannelInitializer
        let options = childChannelOptions
        let setUp = childLoop.flatSubmit {
            options.applyAllChannelOptions(to: child).flatMap {
                initializer?(child) ?? childLoop.makeSucceededVoidFuture()
            }
        }.hop(to: context.eventLoop)
        setUp.assumeIsolated().whenComplete { result in
            switch result {
            case .success:
                guard context.channel.isActive else {
                    child.close(promise: nil)
                    return
                }
                context.fireChannelRead(self.wrapInboundOut(child))
            case .failure(let error):
                child.close(promise: nil)
                context.fireErrorCaught(error)
            }
        }
    }
}

@available(*, unavailable)
extension AcceptHandler: Sendable {}
