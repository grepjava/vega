// The servers and clients the conformance suites test (ci/conformance.sh):
//   vega-conformance h2 PORT   HTTP/2 over cleartext, prior knowledge, for h2spec
//   vega-conformance ws PORT   a WebSocket echo server with permessage-deflate,
//                              for Autobahn's fuzzingclient
//   vega-conformance h3 PORT   HTTP/3 with a self-signed certificate for
//                              "localhost", for aioquic's client
//   vega-conformance h3get HOST PORT PATH [BODY_BYTES]
//                              one HTTP/3 request with Vega's client (no
//                              certificate check), printing the status and
//                              the body's length and checksum
// Servers serve until killed. Every response body is
// "METHOD TARGET BODY_LENGTH".

import Vega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#elseif os(Windows)
import ucrt
#endif
import VegaCrypto
import VegaHTTP1
import VegaHTTP2
import VegaHTTP3Net
import VegaQUIC
import VegaQUICNet
import VegaTLS
import VegaWebSocket

let args = CommandLine.arguments
func usage() -> Never {
    print("usage: vega-conformance h2|ws|h3 PORT | h3get HOST PORT PATH [BODY_BYTES]")
    exit(2)
}
guard args.count >= 3 else { usage() }
let mode = args[1]

let answer: @Sendable (HTTPRequest) async throws -> HTTPResponse = { request in
    HTTPResponse(status: 200, fields: ["content-type": "text/plain"],
                 body: "\(request.head.method.rawValue) \(request.head.target) \(request.body.count)")
}

let rt = Runtime()
do {
    try await_(rt) {
        switch mode {
        case "h2", "ws":
            guard let port = Int(args[2]) else { usage() }
            // Sockets belong to a runtime: bound on it.
            let listener = try TCPListener.bind(host: "0.0.0.0", port: port)
            print("vega-conformance: \(mode) on port \(listener.localPort)")
            while true {
                let conn = try await listener.accept()
                if mode == "h2" {
                    rt.spawn(with: conn) { conn in try? await HTTP2Server.serve(conn, answer) }
                } else {
                    rt.spawn(with: conn) { conn in
                        let config = WebSocketConfiguration(maxMessageSize: 64 << 20, maxFrameSize: 64 << 20, compression: true)
                        guard var ws = try? await WebSocket.accept(conn, configuration: config) else { return }
                        while true {
                            guard let message = try? await ws.receive() else { return }
                            guard (try? await ws.send(message)) != nil else { return }
                        }
                    }
                }
            }
        // QUIC is built on VegaCrypto, so h3 is on its platforms and traits only.
        #if (os(Linux) || os(macOS) || os(Windows)) && (OpenSSL || BoringSSL)
        case "h3":
            guard let port = Int(args[2]) else { usage() }
            let identity = try TLSIdentity.selfSigned(names: ["localhost"])
            let key = try CertificateKey(chainPEM: identity.certificateChain, keyPEM: identity.privateKey)
            let endpoint = try QUICEndpoint.listen(host: "0.0.0.0", port: port,
                                                   configuration: HTTP3Server.quicConfiguration(certificate: key),
                                                   runtime: rt)
            print("vega-conformance: h3 on port \(endpoint.localPort)")
            await HTTP3Server.serve(endpoint, answer)
        case "h3get":
            guard args.count >= 5, let port = Int(args[3]) else { usage() }
            let size = args.count > 5 ? Int(args[5]) ?? 0 : 0
            let endpoint = try QUICEndpoint.client(runtime: rt)
            let response = try await HTTP3Client.withConnection(endpoint, host: args[2], port: port,
                                                               certificateVerification: .insecureNoVerification) { client in
                try await client.send(HTTPRequest(method: size > 0 ? .post : .get, target: args[4],
                                                  body: [UInt8](repeating: 0x61, count: size)))
            }
            let sum = response.body.reduce(UInt32(0)) { $0 &* 31 &+ UInt32($1) }
            print("status \(response.status) length \(response.body.count) sum \(sum)")
            print(response.text.prefix(200))
            await endpoint.close(grace: .zero)
        #endif
        default:
            usage()
        }
    }
} catch {
    print("vega-conformance: \(error)")
    exit(1)
}

/// `rt.block`, for a body that throws any error.
func await_(_ rt: Runtime, _ body: @escaping @Sendable () async throws -> Void) throws {
    let result: Result<Void, any Error> = rt.block {
        do { try await body(); return .success(()) } catch { return .failure(error) }
    }
    try result.get()
}
