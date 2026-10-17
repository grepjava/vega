// The servers the conformance suites test (ci/conformance.sh):
//   vega-conformance h2 PORT   HTTP/2 over cleartext, prior knowledge, for h2spec
//   vega-conformance ws PORT   a WebSocket echo server with permessage-deflate,
//                              for Autobahn's fuzzingclient
// Each serves until killed.

import Vega
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#elseif os(Windows)
import ucrt
#endif
import VegaHTTP1
import VegaHTTP2
import VegaWebSocket

let args = CommandLine.arguments
guard args.count == 3, let port = Int(args[2]), ["h2", "ws"].contains(args[1]) else {
    print("usage: vega-conformance h2|ws PORT")
    exit(2)
}
let mode = args[1]
let rt = Runtime()
try rt.block { () async throws(IOError) in
    // Sockets belong to a runtime: bound on it.
    let listener = try TCPListener.bind(host: "0.0.0.0", port: port)
    print("vega-conformance: \(mode) on port \(listener.localPort)")
    while true {
        let conn = try await listener.accept()
        if mode == "h2" {
            rt.spawn(with: conn) { conn in
                try? await HTTP2Server.serve(conn) { request in
                    HTTPResponse(status: 200, fields: ["content-type": "text/plain"],
                                 body: "\(request.head.method.rawValue) \(request.head.target) \(request.body.count)")
                }
            }
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
}
