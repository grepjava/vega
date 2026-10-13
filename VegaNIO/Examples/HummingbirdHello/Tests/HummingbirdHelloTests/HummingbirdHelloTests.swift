import Hummingbird
import HummingbirdTesting
import HummingbirdVega
import NIOCore
import Testing
import VegaNIO

@Suite struct HummingbirdOnVegaTests {
    /// Hummingbird's live test framework: a real server on a port, a real
    /// client (NIOPosix's) talking to it.
    @Test func live() async throws {
        let group = VegaEventLoopGroup(loops: 2)
        let router = Router()
        router.get("/") { _, _ in "Hello from Hummingbird on Vega" }
        router.get("/user/:name") { _, context in "Hello, \(context.parameters.get("name") ?? "?")" }
        router.post("/echo") { request, _ -> ByteBuffer in
            try await request.body.collect(upTo: 1 << 20)
        }
        router.get("/loop") { _, _ -> String in
            // Route handlers are ordinary async code: they run as tasks.
            try await Task.sleep(for: .milliseconds(5))
            return "slept"
        }
        var configuration = ApplicationConfiguration(address: .hostname("127.0.0.1", port: 0))
        configuration.useVega()
        let app = Application(router: router, configuration: configuration, eventLoopGroupProvider: .shared(group))
        try await app.test(.live) { client in
            try await client.execute(uri: "/", method: .get) { response in
                #expect(response.status == .ok)
                #expect(String(buffer: response.body) == "Hello from Hummingbird on Vega")
            }
            try await client.execute(uri: "/user/ada", method: .get) { response in
                #expect(String(buffer: response.body) == "Hello, ada")
            }
            let big = ByteBuffer(repeating: 0x5A, count: 300_000)
            try await client.execute(uri: "/echo", method: .post, body: big) { response in
                #expect(response.body == big)
            }
            try await client.execute(uri: "/loop", method: .get) { response in
                #expect(String(buffer: response.body) == "slept")
            }
            try await client.execute(uri: "/missing", method: .get) { response in
                #expect(response.status == .notFound)
            }
        }
        try await group.shutdownGracefully()
    }
}
