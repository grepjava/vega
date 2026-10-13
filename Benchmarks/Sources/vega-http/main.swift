// the-benchmarker/web-frameworks' contract on Vega's own HTTP/1 server, with
// no NIO: GET / answers 200 with an empty body, GET /user/:id answers the id,
// POST /user answers 200. One task per connection.
//
//   SERVER_HOSTNAME=127.0.0.1 SERVER_PORT=3000 vega-http [--workers N]
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif
import Vega
import VegaHTTP1

var workers: Int?
var args = CommandLine.arguments.dropFirst()
while let a = args.popFirst() {
    switch a {
    case "--workers": workers = Int(args.popFirst()!)!
    default: fatalError("unknown option \(a)")
    }
}

let env = ProcessInfoLite()
let host = env["SERVER_HOSTNAME"] ?? "127.0.0.1"
let port = env["SERVER_PORT"].flatMap { Int($0) } ?? 8080
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
        print("vega-http: \(host):\(port), \(rt.workerCount) workers")
        while true {
            let conn = try await listener.accept()
            rt.spawn(with: conn) { conn in
                try? await HTTP1Server.serve(conn) { answer($0) }
            }
        }
    }
} catch {
    fatalError("vega-http: \(error)")
}

/// The environment, without Foundation.
struct ProcessInfoLite {
    subscript(name: String) -> String? {
        getenv(name).map { String(cString: $0) }
    }
}
