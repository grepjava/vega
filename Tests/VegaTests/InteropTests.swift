#if (os(Linux) || os(macOS)) && (OpenSSL || BoringSSL)
import Testing
import Vega
import VegaIO
import VegaHTTP1
import VegaHTTP2
import VegaProcess
import VegaTLS

/// Whether curl is here and speaks HTTP/2.
private let curlHasHTTP2: Bool = {
    let rt = Runtime(workers: 1)
    defer { rt.shutdown() }
    let out = try? rt.block { () async throws(IOError) -> Output in try await Command("curl", arguments: ["--version"]).output() }
    return out?.stdoutString.contains("HTTP2") == true
}()

private let identity = try! TLSIdentity.selfSigned(names: ["127.0.0.1"])

/// The servers against curl (built on nghttp2): another implementation's
/// idea of the protocol, not just this package's own client.
@Suite(.enabled(if: curlHasHTTP2, "needs curl with HTTP/2"))
struct CurlInteropTests {
    /// Serve on a fresh port with `serve`, run curl with `arguments` (the
    /// URL base is `$URL`), and return its output.
    private func curl(tls: Bool, _ arguments: [String],
                      serve: @escaping @Sendable (consuming TCPStream) async -> Void) throws -> Output {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        return try rt.block { () async throws -> Output in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let base = "\(tls ? "https" : "http")://127.0.0.1:\(listener.localPort)"
            rt.spawn(with: listener) { l async in
                while let conn = try? await l.accept() {
                    rt.spawn(with: conn) { conn async in await serve(conn) }
                }
            }
            let args = arguments.map { $0.hasPrefix("$URL") ? base + $0.dropFirst(4) : $0 }
            return try await Command("curl", arguments: ["-sS", "--max-time", "20"] + args).output()
        }
    }

    private static let handler: @Sendable (HTTPRequest) async throws -> HTTPResponse = { request in
        HTTPResponse(fields: ["x-version": request.head.version.description],
                     body: "\(request.head.method) \(request.head.target) \(request.body.count)\n")
    }

    @Test func h2cPriorKnowledge() throws {
        let out = try curl(tls: false, ["--http2-prior-knowledge", "-w", "%{http_version}\n",
                                        "$URL/a", "$URL/b?x=1", "-d", "hello", "$URL/c"]) { conn in
            try? await HTTP2Server.serve(conn, Self.handler)
        }
        #expect(out.status.isSuccess, "\(out.stderrString)")
        #expect(out.stdoutString == "POST /a 5\n2\nPOST /b?x=1 5\n2\nPOST /c 5\n2\n")
    }

    @Test func h2OverTLSInParallel() throws {
        let server = try TLSContext(.server(identity: identity, applicationProtocols: ["h2"]))
        var arguments = ["-k", "--http2", "--parallel", "--parallel-max", "20", "-w", "v%{http_version};"]
        for i in 0..<40 { arguments.append("$URL/\(i)") }
        let out = try curl(tls: true, arguments) { conn in
            guard let tls = try? await TLSStream.accept(conn, context: server) else { return }
            try? await HTTP2Server.serve(tls.split(), Self.handler)
        }
        #expect(out.status.isSuccess, "\(out.stderrString)")
        let text = out.stdoutString
        for i in 0..<40 { #expect(text.contains("GET /\(i) 0\n"), "\(i): \(text)") }
        // Every exchange was HTTP/2.
        #expect(text.split(separator: ";").filter { $0.hasSuffix("v2") }.count == 40, "\(text)")
    }

    /// An upload far bigger than the 64 KiB windows curl starts with.
    @Test func bigUpload() throws {
        let server = try TLSContext(.server(identity: identity, applicationProtocols: ["h2"]))
        let out = try curl(tls: true, ["-k", "--http2", "--data-binary", String(repeating: "x", count: 100_000), "$URL/big"]) { conn in
            guard let tls = try? await TLSStream.accept(conn, context: server) else { return }
            try? await HTTP2Server.serve(tls.split(), Self.handler)
        }
        #expect(out.status.isSuccess, "\(out.stderrString)")
        #expect(out.stdoutString == "POST /big 100000\n")
    }

    @Test func http1() throws {
        let out = try curl(tls: false, ["-H", "Expect: 100-continue", "-d", "body", "$URL/one", "$URL/two"]) { conn in
            try? await HTTP1Server.serve(conn) { request in try await Self.handler(request) }
        }
        #expect(out.status.isSuccess, "\(out.stderrString)")
        #expect(out.stdoutString == "POST /one 4\nPOST /two 4\n")
    }
}
#endif
