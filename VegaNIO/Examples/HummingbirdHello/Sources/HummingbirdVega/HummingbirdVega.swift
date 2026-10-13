import Hummingbird
import HummingbirdCore
import NIOCore
import VegaNIO

extension VegaServerBootstrap: @retroactive ServerBootstrapProtocol {
    public func bind<Output: Sendable>(
        unixDomainSocketPath: String,
        cleanupExistingSocketFile: Bool,
        serverBackPressureStrategy: NIOAsyncSequenceProducerBackPressureStrategies.HighLowWatermark?,
        childChannelInitializer: @escaping @Sendable (any Channel) -> EventLoopFuture<Output>
    ) async throws -> NIOAsyncChannel<Output, Never> {
        throw ChannelError.operationUnsupported
    }
}

extension ApplicationConfiguration {
    /// Serve with VegaNIO when the application's group is a
    /// `VegaEventLoopGroup`, with the options Hummingbird's own
    /// sockets bootstrap sets.
    public mutating func useVega() {
        let backlog = Int32(self.backlog), reuseAddress = self.reuseAddress
        makeBootstrap = { group in
            VegaServerBootstrap(validatingGroup: group)?
                .serverChannelOption(.backlog, value: backlog)
                .serverChannelOption(.socketOption(.so_reuseaddr), value: reuseAddress ? 1 : 0)
                .childChannelOption(.allowRemoteHalfClosure, value: true)
        }
    }
}
