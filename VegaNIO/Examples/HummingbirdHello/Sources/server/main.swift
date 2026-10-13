// the-benchmarker/web-frameworks' swift/hummingbird-framework entry, with
// VEGANIO=1 serving it on VegaNIO instead of NIOPosix.
import Hummingbird
import HummingbirdVega
import NIOCore
import VegaNIO

let env = Environment()
let serverHostName = env.get("SERVER_HOSTNAME") ?? "127.0.0.1"
let serverPort = env.get("SERVER_PORT", as: Int.self) ?? 8080

let router = Router()
router.get("/") { _, _ in
    HTTPResponse.Status.ok
}
router.get("user/:id") { _, ctx -> String in
    ctx.parameters.get("id") ?? ""
}
router.post("user") { _, _ in
    HTTPResponse.Status.ok
}

var configuration = ApplicationConfiguration(address: .hostname(serverHostName, port: serverPort))
let app: Application<RouterResponder<BasicRequestContext>>
if env.get("VEGANIO") == "1" {
    configuration.useVega()
    app = Application(router: router, configuration: configuration,
                      eventLoopGroupProvider: .shared(VegaEventLoopGroup()))
} else {
    app = Application(router: router, configuration: configuration)
}
try await app.run()
