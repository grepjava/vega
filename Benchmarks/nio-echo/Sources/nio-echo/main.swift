// TCP echo server on SwiftNIO, in NIO's fastest style: a channel handler that
// writes each read back and flushes when the read burst ends.
//
//   nio-echo [--port 7000] [--workers N]
import NIOCore
import NIOPosix
#if canImport(Glibc)
import Glibc
#endif

final class EchoHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        context.write(data, promise: nil)
    }

    func channelReadComplete(context: ChannelHandlerContext) {
        context.flush()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        if debug { logError("nio-echo: \(error)") }
        context.close(promise: nil)
    }
}

func logError(_ s: String) { fputs(s + "\n", stderr) }
let debug = CommandLine.arguments.contains("--debug")

var port = 7000
var workers = System.coreCount
var args = CommandLine.arguments.dropFirst()
while let a = args.popFirst() {
    switch a {
    case "--port": port = Int(args.popFirst()!)!
    case "--workers": workers = Int(args.popFirst()!)!
    case "--debug": break
    default: fatalError("unknown option \(a)")
    }
}

let group = MultiThreadedEventLoopGroup(numberOfThreads: workers)
let channel = try ServerBootstrap(group: group)
    .serverChannelOption(.backlog, value: 4096)
    .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
    .childChannelOption(.tcpOption(.tcp_nodelay), value: 1)
    .childChannelOption(.maxMessagesPerRead, value: 16)
    .childChannelInitializer { channel in
        channel.eventLoop.makeCompletedFuture {
            try channel.pipeline.syncOperations.addHandler(EchoHandler())
        }
    }
    .bind(host: "0.0.0.0", port: port)
    .wait()
print("nio echo: port \(port), \(workers) event loops")
try channel.closeFuture.wait()
