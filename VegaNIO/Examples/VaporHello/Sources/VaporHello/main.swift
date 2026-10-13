import Vapor
import VaporVega
import VegaNIO

let group = VegaEventLoopGroup()
let app = try await Application.make(.detect(), .shared(group))
app.http.server.configuration.useVega()
app.http.server.configuration.hostname = "127.0.0.1"
app.get { _ in "Hello from Vapor on Vega\n" }
app.get("user", ":name") { req in "Hello, \(req.parameters.get("name") ?? "?")\n" }
try await app.execute()
try await app.asyncShutdown()
