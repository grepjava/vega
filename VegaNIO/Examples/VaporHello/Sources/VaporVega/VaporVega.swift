import NIOCore
import Vapor
import VegaNIO

extension VegaServerBootstrap: @retroactive HTTPServerBootstrap {}

extension HTTPServer.Configuration {
    /// Serve with VegaNIO when the application's group is a
    /// `VegaEventLoopGroup`.
    public mutating func useVega() {
        makeBootstrap = { VegaServerBootstrap(validatingGroup: $0) }
    }
}
