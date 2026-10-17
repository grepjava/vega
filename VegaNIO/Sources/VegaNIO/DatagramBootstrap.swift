import NIOCore

/// NIO's `DatagramBootstrap`, for a `VegaEventLoopGroup`: a UDP channel
/// that reads and writes `AddressedEnvelope<ByteBuffer>`.
///
/// ```swift
/// let channel = try await VegaDatagramBootstrap(group: group)
///     .channelOption(.socketOption(.so_reuseaddr), value: 1)
///     .channelInitializer { channel in
///         channel.pipeline.addHandler(DNSHandler())
///     }
///     .bind(host: "0.0.0.0", port: 5353).get()
/// ```
///
/// SO_REUSEADDR and SO_REUSEPORT set here apply before the socket binds,
/// where they matter; other socket options go on once it exists. Unix
/// datagram sockets are not supported yet.
public final class VegaDatagramBootstrap {
    private let group: VegaEventLoopGroup
    private var channelInit: (@Sendable (Channel) -> EventLoopFuture<Void>)?
    private var channelOptions = ChannelOptions.Storage()

    public init(group: VegaEventLoopGroup) {
        self.group = group
    }

    /// nil unless `group` is a `VegaEventLoopGroup`.
    public convenience init?(validatingGroup group: EventLoopGroup) {
        guard let group = group as? VegaEventLoopGroup else { return nil }
        self.init(group: group)
    }

    /// Set up the channel's pipeline, before it binds or connects.
    public func channelInitializer(_ handler: @escaping @Sendable (Channel) -> EventLoopFuture<Void>) -> Self {
        channelInit = handler
        return self
    }

    public func channelOption<Option: ChannelOption>(_ option: Option, value: Option.Value) -> Self {
        channelOptions.append(key: option, value: value)
        return self
    }

    /// Bind to `host` (an address or a name, resolved here) and `port`, 0
    /// for any free one.
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
        open({ channel, promise in channel.bind(to: address, promise: promise) },
             channelInitializer: { channel in channel.eventLoop.makeSucceededFuture(channel) })
    }

    /// Not yet: fails with `ChannelError.operationUnsupported`.
    public func bind(unixDomainSocketPath: String) -> EventLoopFuture<Channel> {
        group.next().makeFailedFuture(ChannelError.operationUnsupported)
    }

    /// A connected channel: on a free local port, sending to and hearing
    /// from `host`:`port` only. It takes plain `ByteBuffer` writes as well
    /// as envelopes.
    public func connect(host: String, port: Int) -> EventLoopFuture<Channel> {
        let address: SocketAddress
        do {
            address = try SocketAddress.makeAddressResolvingHost(host, port: port)
        } catch {
            return group.next().makeFailedFuture(error)
        }
        return connect(to: address)
    }

    public func connect(to address: SocketAddress) -> EventLoopFuture<Channel> {
        open({ channel, promise in channel.connect(to: address, promise: promise) },
             channelInitializer: { channel in channel.eventLoop.makeSucceededFuture(channel) })
    }

    /// Not yet: fails with `ChannelError.operationUnsupported`.
    public func connect(unixDomainSocketPath: String) -> EventLoopFuture<Channel> {
        group.next().makeFailedFuture(ChannelError.operationUnsupported)
    }

    /// Bind, with the channel wrapped as `channelInitializer` says (in an
    /// `NIOAsyncChannel`, say) before it goes active, so that no datagram
    /// comes in ahead of it.
    ///
    /// ```swift
    /// let channel = try await VegaDatagramBootstrap(group: group).bind(host: "127.0.0.1", port: 0) { channel in
    ///     channel.eventLoop.makeCompletedFuture {
    ///         try NIOAsyncChannel<AddressedEnvelope<ByteBuffer>, AddressedEnvelope<ByteBuffer>>(
    ///             wrappingChannelSynchronously: channel)
    ///     }
    /// }
    /// ```
    public func bind<Output: Sendable>(
        host: String,
        port: Int,
        channelInitializer: @escaping @Sendable (Channel) -> EventLoopFuture<Output>
    ) async throws -> Output {
        let address = try SocketAddress.makeAddressResolvingHost(host, port: port)
        return try await bind(to: address, channelInitializer: channelInitializer)
    }

    public func bind<Output: Sendable>(
        to address: SocketAddress,
        channelInitializer: @escaping @Sendable (Channel) -> EventLoopFuture<Output>
    ) async throws -> Output {
        try await open({ channel, promise in channel.bind(to: address, promise: promise) },
                       channelInitializer: channelInitializer).get()
    }

    /// Connect, with the channel wrapped as `channelInitializer` says
    /// before it goes active.
    public func connect<Output: Sendable>(
        host: String,
        port: Int,
        channelInitializer: @escaping @Sendable (Channel) -> EventLoopFuture<Output>
    ) async throws -> Output {
        let address = try SocketAddress.makeAddressResolvingHost(host, port: port)
        return try await connect(to: address, channelInitializer: channelInitializer)
    }

    public func connect<Output: Sendable>(
        to address: SocketAddress,
        channelInitializer: @escaping @Sendable (Channel) -> EventLoopFuture<Output>
    ) async throws -> Output {
        try await open({ channel, promise in channel.connect(to: address, promise: promise) },
                       channelInitializer: channelInitializer).get()
    }

    /// Options, then both initializers, then register, then bind or connect.
    private func open<Output: Sendable>(
        _ activate: @escaping @Sendable (VegaDatagramChannel, EventLoopPromise<Void>) -> Void,
        channelInitializer: @escaping @Sendable (Channel) -> EventLoopFuture<Output>
    ) -> EventLoopFuture<Output> {
        let loop = group.next() as! VegaEventLoop
        let channel = VegaDatagramChannel(loop: loop)
        let channelInit = self.channelInit
        let options = self.channelOptions
        return loop.flatSubmit {
            options.applyAllChannelOptions(to: channel).flatMap {
                channelInit?(channel) ?? loop.makeSucceededVoidFuture()
            }.flatMap {
                channelInitializer(channel)
            }.flatMap { output in
                channel.register().flatMap {
                    let promise = loop.makePromise(of: Void.self)
                    activate(channel, promise)
                    return promise.futureResult
                }.map { output }
            }.flatMapError { error in
                channel.close(promise: nil)
                return loop.makeFailedFuture(error)
            }
        }
    }
}

@available(*, unavailable)
extension VegaDatagramBootstrap: Sendable {}
