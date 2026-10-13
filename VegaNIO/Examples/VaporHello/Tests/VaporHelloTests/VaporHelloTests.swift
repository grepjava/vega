import AsyncHTTPClient
import NIOCore
import Testing
import Vapor
import VaporVega
import VegaNIO

@Suite struct VaporOnVegaTests {
    /// A real Vapor server on a VegaNIO group, and a real client
    /// (AsyncHTTPClient, on NIOPosix) talking to it.
    @Test func live() async throws {
        let group = VegaEventLoopGroup(loops: 2)
        let app = try await Application.make(.testing, .shared(group))
        app.http.server.configuration.useVega()
        app.get { _ in "Hello from Vapor on Vega" }
        app.get("user", ":name") { req in "Hello, \(req.parameters.get("name") ?? "?")" }
        app.on(.POST, "echo", body: .collect(maxSize: "1mb")) { req -> Response in
            Response(status: .ok, body: .init(buffer: req.body.data ?? ByteBuffer()))
        }
        app.get("sleep") { _ async throws -> String in
            try await Task.sleep(for: .milliseconds(5))
            return "slept"
        }
        try await app.server.start(address: .hostname("127.0.0.1", port: 0))
        let port = try #require(app.http.server.shared.localAddress?.port)
        let base = "http://127.0.0.1:\(port)"

        func get(_ path: String) async throws -> (UInt, String) {
            let response = try await HTTPClient.shared.execute(HTTPClientRequest(url: base + path), timeout: .seconds(10))
            let body = try await response.body.collect(upTo: 1 << 20)
            return (response.status.code, String(buffer: body))
        }
        #expect(try await get("/") == (200, "Hello from Vapor on Vega"))
        #expect(try await get("/user/ada") == (200, "Hello, ada"))
        #expect(try await get("/sleep") == (200, "slept"))
        #expect(try await get("/missing").0 == 404)

        var post = HTTPClientRequest(url: base + "/echo")
        post.method = .POST
        let big = ByteBuffer(repeating: 0x5A, count: 300_000)
        post.body = .bytes(big)
        let echoed = try await HTTPClient.shared.execute(post, timeout: .seconds(10))
        #expect(try await echoed.body.collect(upTo: 1 << 20) == big)

        await app.server.shutdown()
        try await app.asyncShutdown()
        try await group.shutdownGracefully()
    }
}
