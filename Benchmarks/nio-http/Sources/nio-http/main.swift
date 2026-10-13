// the-benchmarker/web-frameworks' contract on SwiftNIO with NIO's own HTTP/1
// handlers and no framework, the counterpart of vega-http: GET / answers 200
// with an empty body, GET /user/:id answers the id, POST /user answers 200.
// Responses carry only content-length, as vega-http's do.
//
//   SERVER_HOSTNAME=127.0.0.1 SERVER_PORT=3000 nio-http [--workers N]
import NIOCore
import NIOHTTP1
import NIOPosix
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

final class Handler: ChannelInboundHandler {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private var head: HTTPRequestHead?

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let h):
            head = h
        case .body:
            break
        case .end:
            guard let h = head else { return }
            head = nil
            respond(context: context, request: h)
        }
    }

    private func respond(context: ChannelHandlerContext, request: HTTPRequestHead) {
        var status = HTTPResponseStatus.ok
        var body = ""
        let path = request.uri
        if request.method == .GET {
            if path == "/" {
            } else if path.hasPrefix("/user/") {
                body = String(path.dropFirst(6))
            } else {
                status = .notFound
            }
        } else if request.method != .POST || path != "/user" {
            status = .notFound
        }
        let keepAlive = request.isKeepAlive
        var fields = HTTPHeaders()
        fields.add(name: "content-length", value: String(body.utf8.count))
        if !keepAlive { fields.add(name: "connection", value: "close") }
        context.write(wrapOutboundOut(.head(HTTPResponseHead(version: request.version, status: status, headers: fields))), promise: nil)
        if !body.isEmpty {
            var buffer = context.channel.allocator.buffer(capacity: body.utf8.count)
            buffer.writeString(body)
            context.write(wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)
        }
        if keepAlive {
            context.write(wrapOutboundOut(.end(nil)), promise: nil)
        } else {
            context.write(wrapOutboundOut(.end(nil))).whenComplete { _ in context.close(promise: nil) }
        }
    }

    func channelReadComplete(context: ChannelHandlerContext) {
        context.flush()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }
}

var workers = System.coreCount
var args = CommandLine.arguments.dropFirst()
while let a = args.popFirst() {
    switch a {
    case "--workers": workers = Int(args.popFirst()!)!
    default: fatalError("unknown option \(a)")
    }
}
let host = getenv("SERVER_HOSTNAME").map { String(cString: $0) } ?? "127.0.0.1"
let port = getenv("SERVER_PORT").flatMap { Int(String(cString: $0)) } ?? 8080

let group = MultiThreadedEventLoopGroup(numberOfThreads: workers)
let channel = try ServerBootstrap(group: group)
    .serverChannelOption(.backlog, value: 4096)
    .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
    .childChannelOption(.tcpOption(.tcp_nodelay), value: 1)
    .childChannelOption(.maxMessagesPerRead, value: 16)
    .childChannelInitializer { channel in
        channel.eventLoop.makeCompletedFuture {
            try channel.pipeline.syncOperations.configureHTTPServerPipeline()
            try channel.pipeline.syncOperations.addHandler(Handler())
        }
    }
    .bind(host: host, port: port)
    .wait()
print("nio-http: \(host):\(port), \(workers) event loops")
try channel.closeFuture.wait()
