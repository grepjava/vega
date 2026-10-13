import NIOConcurrencyHelpers
import NIOCore
import NIOHTTP1
import Testing
import class Vega.Runtime
@testable import VegaNIO

private final class EchoHandler: ChannelInboundHandler, Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        context.write(data, promise: nil)
    }

    func channelReadComplete(context: ChannelHandlerContext) {
        context.flush()
    }
}

/// Collects what a client channel reads until `expected` bytes have come.
private final class Collector: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    private var received = ByteBuffer()
    private let expected: Int
    let done: EventLoopPromise<ByteBuffer>
    private(set) var events: [String] = []

    init(expected: Int, done: EventLoopPromise<ByteBuffer>) {
        self.expected = expected
        self.done = done
    }

    func channelActive(context: ChannelHandlerContext) {
        events.append("active")
        context.fireChannelActive()
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = unwrapInboundIn(data)
        received.writeBuffer(&buffer)
        if received.readableBytes >= expected { done.succeed(received) }
    }

    func channelInactive(context: ChannelHandlerContext) {
        events.append("inactive")
        done.fail(ChannelError.eof)
    }
}

@Suite struct ChannelTests {
    @Test func echo() throws {
        let group = VegaEventLoopGroup(loops: 2)
        defer { try? group.syncShutdownGracefully() }
        let server = try VegaServerBootstrap(group: group)
            .childChannelInitializer { $0.pipeline.addHandler(EchoHandler()) }
            .bind(host: "127.0.0.1", port: 0).wait()
        let port = try #require(server.localAddress?.port)

        let payload = ByteBuffer(bytes: (0..<300_000).map { UInt8(truncatingIfNeeded: $0 &* 7) })
        let loop = group.next()
        let done = loop.makePromise(of: ByteBuffer.self)
        let collector = Collector(expected: payload.readableBytes, done: done)
        let client = try VegaClientBootstrap(group: group)
            .channelInitializer { $0.pipeline.addHandler(collector) }
            .connect(host: "127.0.0.1", port: port).wait()
        #expect(client.isActive)
        #expect(client.remoteAddress?.port == port)
        // Lots of small writes, one flush.
        var rest = payload
        while rest.readableBytes > 0 {
            client.write(rest.readSlice(length: min(rest.readableBytes, 1000))!, promise: nil)
        }
        try client.writeAndFlush(ByteBuffer()).wait()
        let echoed = try done.futureResult.wait()
        #expect(echoed == payload)

        try client.close().wait()
        #expect(!client.isActive)
        try client.closeFuture.wait()
        #expect(throws: ChannelError.self) { try client.close().wait() }
        #expect(throws: ChannelError.self) { try client.writeAndFlush(ByteBuffer()).wait() }
        try server.close().wait()
    }

    @Test func connectionRefused() throws {
        let group = VegaEventLoopGroup(loops: 1)
        defer { try? group.syncShutdownGracefully() }
        // A port nothing listens on: bind one and close it.
        let server = try VegaServerBootstrap(group: group).bind(host: "127.0.0.1", port: 0).wait()
        let port = try #require(server.localAddress?.port)
        try server.close().wait()
        try group.next().scheduleTask(in: .milliseconds(20)) {}.futureResult.wait()
        #expect(throws: (any Error).self) {
            try VegaClientBootstrap(group: group).connect(host: "127.0.0.1", port: port).wait()
        }
    }

    /// Write, flush, close at once: what was flushed still arrives.
    @Test func writeThenClose() throws {
        let group = VegaEventLoopGroup(loops: 2)
        defer { try? group.syncShutdownGracefully() }
        let payload = ByteBuffer(repeating: 0x61, count: 1 << 20)
        final class WriteAndClose: ChannelInboundHandler, Sendable {
            typealias InboundIn = ByteBuffer
            let payload: ByteBuffer
            init(_ payload: ByteBuffer) { self.payload = payload }
            func channelActive(context: ChannelHandlerContext) {
                context.writeAndFlush(NIOAny(payload), promise: nil)
                context.close(promise: nil)
            }
        }
        let server = try VegaServerBootstrap(group: group)
            .childChannelInitializer { $0.pipeline.addHandler(WriteAndClose(payload)) }
            .bind(host: "127.0.0.1", port: 0).wait()
        let port = try #require(server.localAddress?.port)
        let done = group.next().makePromise(of: ByteBuffer.self)
        let collector = Collector(expected: payload.readableBytes, done: done)
        let client = try VegaClientBootstrap(group: group)
            .channelInitializer { $0.pipeline.addHandler(collector) }
            .connect(host: "127.0.0.1", port: port).wait()
        #expect(try done.futureResult.wait() == payload)
        try client.closeFuture.wait()
        try server.close().wait()
    }

    /// With remote half-closure allowed, end of stream is an event and the
    /// channel can still send.
    @Test func halfClosure() throws {
        let group = VegaEventLoopGroup(loops: 2)
        defer { try? group.syncShutdownGracefully() }
        final class ReplyOnEOF: ChannelInboundHandler, @unchecked Sendable {
            typealias InboundIn = ByteBuffer
            var count = 0
            func channelRead(context: ChannelHandlerContext, data: NIOAny) {
                count += unwrapInboundIn(data).readableBytes
            }
            func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
                guard case ChannelEvent.inputClosed = event else { return }
                context.writeAndFlush(NIOAny(ByteBuffer(string: "got \(count)"))).whenComplete { _ in
                    context.close(promise: nil)
                }
            }
        }
        let server = try VegaServerBootstrap(group: group)
            .childChannelOption(.allowRemoteHalfClosure, value: true)
            .childChannelInitializer { $0.pipeline.addHandler(ReplyOnEOF()) }
            .bind(host: "127.0.0.1", port: 0).wait()
        let port = try #require(server.localAddress?.port)
        let done = group.next().makePromise(of: ByteBuffer.self)
        let collector = Collector(expected: 5, done: done)
        let client = try VegaClientBootstrap(group: group)
            .channelOption(.allowRemoteHalfClosure, value: true)
            .channelInitializer { $0.pipeline.addHandler(collector) }
            .connect(host: "127.0.0.1", port: port).wait()
        try client.writeAndFlush(ByteBuffer(string: "hello")).wait()
        try client.close(mode: .output).wait()
        #expect(throws: ChannelError.self) { try client.writeAndFlush(ByteBuffer(string: "x")).wait() }
        #expect(String(buffer: try done.futureResult.wait()) == "got 5")
        try server.close().wait()
    }

    @Test func writability() throws {
        let group = VegaEventLoopGroup(loops: 2)
        defer { try? group.syncShutdownGracefully() }
        // A server that doesn't read: the client's writes back up.
        let server = try VegaServerBootstrap(group: group)
            .childChannelOption(.autoRead, value: false)
            .bind(host: "127.0.0.1", port: 0).wait()
        let port = try #require(server.localAddress?.port)
        let client = try VegaClientBootstrap(group: group)
            .channelOption(.writeBufferWaterMark, value: .init(low: 1024, high: 4096))
            .connect(host: "127.0.0.1", port: port).wait()
        #expect(client.isWritable)
        let unwritable = try client.eventLoop.submit {
            for _ in 0..<4 { client.write(ByteBuffer(repeating: 0, count: 1024), promise: nil) }
            return client.isWritable
        }.wait()
        #expect(!unwritable)
        let buffered = try client.getOption(.bufferedWritableBytes).wait()
        #expect(buffered == 4096)
        try client.close().wait()
        try server.close().wait()
    }

    @Test func socketOptions() throws {
        let group = VegaEventLoopGroup(loops: 1)
        defer { try? group.syncShutdownGracefully() }
        let server = try VegaServerBootstrap(group: group).bind(host: "127.0.0.1", port: 0).wait()
        let port = try #require(server.localAddress?.port)
        let client = try VegaClientBootstrap(group: group)
            .channelOption(.socketOption(.so_keepalive), value: 1)
            .connect(host: "127.0.0.1", port: port).wait()
        #expect(try client.getOption(.tcpOption(.tcp_nodelay)).wait() != 0)
        #expect(try client.getOption(.socketOption(.so_keepalive)).wait() != 0)
        #expect(try client.getOption(.autoRead).wait())
        try client.close().wait()
        try server.close().wait()
    }

    /// NIO's own HTTP/1 handlers, on Vega channels.
    @Test func http1() throws {
        let group = VegaEventLoopGroup(loops: 2)
        defer { try? group.syncShutdownGracefully() }
        final class Hello: ChannelInboundHandler, Sendable {
            typealias InboundIn = HTTPServerRequestPart
            typealias OutboundOut = HTTPServerResponsePart
            func channelRead(context: ChannelHandlerContext, data: NIOAny) {
                guard case .end = unwrapInboundIn(data) else { return }
                let body = ByteBuffer(string: "hello from vega")
                var head = HTTPResponseHead(version: .http1_1, status: .ok)
                head.headers.add(name: "content-length", value: "\(body.readableBytes)")
                context.write(wrapOutboundOut(.head(head)), promise: nil)
                context.write(wrapOutboundOut(.body(.byteBuffer(body))), promise: nil)
                context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
            }
        }
        final class Client: ChannelInboundHandler, @unchecked Sendable {
            typealias InboundIn = HTTPClientResponsePart
            var status: HTTPResponseStatus?
            var body = ""
            var responses: [String] = []
            let done: EventLoopPromise<[String]>
            let want: Int
            init(want: Int, done: EventLoopPromise<[String]>) {
                self.want = want
                self.done = done
            }
            func channelRead(context: ChannelHandlerContext, data: NIOAny) {
                switch unwrapInboundIn(data) {
                case .head(let head): status = head.status
                case .body(let b): body += String(buffer: b)
                case .end:
                    responses.append("\(status!.code) \(body)")
                    body = ""
                    if responses.count == want { done.succeed(responses) }
                }
            }
        }
        let server = try VegaServerBootstrap(group: group)
            .childChannelInitializer { channel in
                channel.pipeline.configureHTTPServerPipeline().flatMap { channel.pipeline.addHandler(Hello()) }
            }
            .bind(host: "127.0.0.1", port: 0).wait()
        let port = try #require(server.localAddress?.port)
        let done = group.next().makePromise(of: [String].self)
        let client = try VegaClientBootstrap(group: group)
            .channelInitializer { channel in
                channel.pipeline.addHTTPClientHandlers().flatMap { channel.pipeline.addHandler(Client(want: 3, done: done)) }
            }
            .connect(host: "127.0.0.1", port: port).wait()
        for _ in 0..<3 {
            var head = HTTPRequestHead(version: .http1_1, method: .GET, uri: "/")
            head.headers.add(name: "host", value: "localhost")
            client.write(HTTPClientRequestPart.head(head), promise: nil)
            client.write(HTTPClientRequestPart.end(nil), promise: nil)
        }
        client.flush()
        #expect(try done.futureResult.wait() == Array(repeating: "200 hello from vega", count: 3))
        try client.close().wait()
        try server.close().wait()
    }

    /// NIO's async API (`NIOAsyncChannel`) over Vega channels.
    @Test func asyncChannels() throws {
        let group = VegaEventLoopGroup(loops: 2)
        let rt = group.runtime
        defer { try? group.syncShutdownGracefully() }
        let replies = try rt.block {
            let server = try await VegaServerBootstrap(group: group).bind(host: "127.0.0.1", port: 0) { channel in
                channel.eventLoop.makeCompletedFuture {
                    try NIOAsyncChannel<ByteBuffer, ByteBuffer>(wrappingChannelSynchronously: channel)
                }
            }
            let port = server.channel.localAddress!.port!
            return try await withThrowingTaskGroup(of: [String].self) { tasks in
                tasks.addTask {
                    try await server.executeThenClose { inbound in
                        for try await connection in inbound {
                            try await connection.executeThenClose { inbound, outbound in
                                for try await chunk in inbound {
                                    try await outbound.write(ByteBuffer(string: "echo: " + String(buffer: chunk)))
                                }
                            }
                            break
                        }
                    }
                    return []
                }
                tasks.addTask {
                    let client = try await VegaClientBootstrap(group: group).connect(host: "127.0.0.1", port: port) { channel in
                        channel.eventLoop.makeCompletedFuture {
                            try NIOAsyncChannel<ByteBuffer, ByteBuffer>(wrappingChannelSynchronously: channel)
                        }
                    }
                    return try await client.executeThenClose { inbound, outbound in
                        var got: [String] = []
                        var iterator = inbound.makeAsyncIterator()
                        for word in ["one", "two", "three"] {
                            try await outbound.write(ByteBuffer(string: word))
                            got.append(String(buffer: try await iterator.next()!))
                        }
                        return got
                    }
                }
                var all: [String] = []
                for try await r in tasks { all += r }
                return all
            }
        }
        #expect(replies == ["echo: one", "echo: two", "echo: three"])
    }

    /// Group shutdown closes what is open.
    @Test func shutdownClosesChannels() throws {
        let group = VegaEventLoopGroup(loops: 2)
        let server = try VegaServerBootstrap(group: group)
            .childChannelInitializer { $0.pipeline.addHandler(EchoHandler()) }
            .bind(host: "127.0.0.1", port: 0).wait()
        let port = try #require(server.localAddress?.port)
        let client = try VegaClientBootstrap(group: group).connect(host: "127.0.0.1", port: port).wait()
        try group.syncShutdownGracefully()
        #expect(!server.isActive)
        #expect(!client.isActive)
    }
}

@Suite struct AddressTests {
    @Test func hostIsKept() throws {
        let group = VegaEventLoopGroup(loops: 1)
        defer { try? group.syncShutdownGracefully() }
        let server = try VegaServerBootstrap(group: group).bind(host: "127.0.0.1", port: 0).wait()
        #expect(server.localAddress?.ipAddress == "127.0.0.1")
        guard case .v4(let a) = server.localAddress else {
            Issue.record("not IPv4")
            return
        }
        #expect(a.host == "127.0.0.1")
        try server.close().wait()
    }
}
