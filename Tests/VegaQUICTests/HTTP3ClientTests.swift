// VegaCrypto's platforms and traits only: QUIC's TLS 1.3 is built on it.
#if (os(Linux) || os(macOS) || os(Windows)) && (OpenSSL || BoringSSL)
import Testing
import Vega
import VegaCrypto
import VegaTLS
import VegaHTTP1
import VegaQUIC
import VegaQUICNet
import VegaHTTP3Net

@Suite("HTTP3Client")
struct HTTP3ClientTests {
    /// Vega's client against Vega's server, many requests at once, the
    /// server's certificate checked against its own root.
    @Test func againstHTTP3Server() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let identity = try TLSIdentity.selfSigned(names: ["localhost"])
        let certificate = try CertificateKey(chainPEM: identity.certificateChain, keyPEM: identity.privateKey)
        let verifier = try CertificateVerifier(trustRoots: .certificates(identity.certificateChain))
        let responses = try rt.block { () async throws -> [HTTPResponse] in
            let server = try QUICEndpoint.listen(host: "127.0.0.1", port: 0,
                                                 configuration: HTTP3Server.quicConfiguration(certificate: certificate),
                                                 runtime: rt)
            let serving = rt.spawn {
                await HTTP3Server.serve(server) { request in
                    HTTPResponse(status: request.head.target == "/missing" ? 404 : 200,
                                 fields: ["x-host": request.head.fields["host"] ?? "-"],
                                 body: Array("\(request.head.method.rawValue) \(request.head.target) \(request.body.count)".utf8))
                }
            }
            let endpoint = try QUICEndpoint.client(runtime: rt)
            let responses = try await HTTP3Client.withConnection(endpoint, host: "localhost", port: server.localPort,
                                                                certificateVerification: .verifier(verifier)) { client in
                try await withThrowingTaskGroup(of: (Int, HTTPResponse).self) { group in
                    for i in 0..<20 {
                        group.addTask {
                            let request = i == 19 ? HTTPRequest(target: "/missing")
                                : HTTPRequest(method: i % 2 == 0 ? .get : .post, target: "/item/\(i)",
                                              body: i % 2 == 0 ? [] : Array(repeating: 1, count: i * 1000))
                            return (i, try await client.send(request))
                        }
                    }
                    var all = [HTTPResponse?](repeating: nil, count: 20)
                    for try await (i, r) in group { all[i] = r }
                    return all.map { $0! }
                }
            }
            await endpoint.close(grace: .zero)
            await server.close(grace: .milliseconds(100))
            await serving.value
            return responses
        }
        #expect(responses.count == 20)
        #expect(responses[0].status == 200)
        #expect(responses[0].text == "GET /item/0 0")
        #expect(responses[3].text == "POST /item/3 3000")
        // :authority reached the handler as Host.
        #expect(responses[0].head.fields["x-host"]?.hasPrefix("localhost:") == true)
        #expect(responses[19].status == 404)
    }
}
#endif
