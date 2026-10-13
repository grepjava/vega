import Hummingbird
import HummingbirdVega
import VegaNIO

let group = VegaEventLoopGroup()
let router = Router()
router.get("/") { _, _ in "Hello from Hummingbird on Vega\n" }
router.get("/user/:name") { _, context in "Hello, \(context.parameters.get("name") ?? "?")\n" }

var configuration = ApplicationConfiguration(address: .hostname("127.0.0.1", port: 8080))
configuration.useVega()
let app = Application(router: router, configuration: configuration, eventLoopGroupProvider: .shared(group))
try await app.runService()
