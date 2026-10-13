// vega-http over TLS: the-benchmarker's contract on VegaHTTP1 and VegaTLS,
// for comparing TLS libraries under the same server. GET / answers 200 with
// an empty body, GET /user/:id answers the id, POST /user answers 200.
//
//   SERVER_HOSTNAME=127.0.0.1 SERVER_PORT=3443 TLS_CERT=cert.pem TLS_KEY=key.pem \
//     vega-https [--workers N]
//
// Without TLS_CERT and TLS_KEY it makes a self-signed P-256 certificate.
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif
import Vega
import VegaHTTP1
import VegaTLS

var workers: Int?
var args = CommandLine.arguments.dropFirst()
while let a = args.popFirst() {
    switch a {
    case "--workers": workers = Int(args.popFirst()!)!
    default: fatalError("unknown option \(a)")
    }
}

func env(_ name: String) -> String? { getenv(name).map { String(cString: $0) } }
let host = env("SERVER_HOSTNAME") ?? "127.0.0.1"
let port = env("SERVER_PORT").flatMap { Int($0) } ?? 3443

let context: TLSContext
do {
    let identity: TLSIdentity
    if let cert = env("TLS_CERT"), let key = env("TLS_KEY") {
        identity = try TLSIdentity.files(chain: cert, key: key)
    } else {
        identity = try TLSIdentity.selfSigned(names: ["localhost", "127.0.0.1"])
    }
    context = try TLSContext(.server(identity: identity))
} catch {
    fatalError("vega-https: \(error)")
}
let rt = Runtime(workers: workers)

@Sendable func answer(_ request: HTTPRequest) -> HTTPResponse {
    let path = request.head.target
    if request.head.method == .get {
        if path == "/" { return HTTPResponse() }
        if path.hasPrefix("/user/") { return HTTPResponse(body: String(path.dropFirst(6))) }
    } else if request.head.method == .post, path == "/user" {
        return HTTPResponse()
    }
    return HTTPResponse(status: 404)
}

do {
    try rt.block { () async throws(IOError) -> Void in
        let listener = try TCPListener.bind(host: host, port: port, backlog: 4096)
        print("vega-https: \(host):\(port), \(rt.workerCount) workers")
        while true {
            let conn = try await listener.accept()
            rt.spawn(with: conn) { conn in
                guard let tls = try? await TLSStream.accept(conn, context: context) else { return }
                try? await HTTP1Server.serve(tls) { answer($0) }
                _ = try? await tls.close()
            }
        }
    }
} catch {
    fatalError("vega-https: \(error)")
}
