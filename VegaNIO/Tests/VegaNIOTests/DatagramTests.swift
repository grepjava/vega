import NIOConcurrencyHelpers
import NIOCore
import Testing
@testable import VegaNIO
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// Sends each datagram back where it came from.
private final class DatagramEcho: ChannelInboundHandler, Sendable {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>
    typealias OutboundOut = AddressedEnvelope<ByteBuffer>

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        context.write(data, promise: nil)
    }

    func channelReadComplete(context: ChannelHandlerContext) {
        context.flush()
    }
}

/// Collects datagrams until `expected` have come.
private final class DatagramCollector: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>
    private var received: [AddressedEnvelope<ByteBuffer>] = []
    private let expected: Int
    let done: EventLoopPromise<[AddressedEnvelope<ByteBuffer>]>

    init(expected: Int, done: EventLoopPromise<[AddressedEnvelope<ByteBuffer>]>) {
        self.expected = expected
        self.done = done
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        received.append(unwrapInboundIn(data))
        if received.count == expected { done.succeed(received) }
    }
}

@Suite struct DatagramTests {
    /// Envelopes out to a bound server and back, from a bound client.
    @Test func addressedEcho() throws {
        let group = VegaEventLoopGroup(loops: 2)
        defer { try? group.syncShutdownGracefully() }
        let server = try VegaDatagramBootstrap(group: group)
            .channelInitializer { $0.pipeline.addHandler(DatagramEcho()) }
            .bind(host: "127.0.0.1", port: 0).wait()
        let serverAddress = try #require(server.localAddress)
        #expect(serverAddress.port != 0)

        let done = group.next().makePromise(of: [AddressedEnvelope<ByteBuffer>].self)
        let collector = DatagramCollector(expected: 3, done: done)
        let client = try VegaDatagramBootstrap(group: group)
            .channelInitializer { $0.pipeline.addHandler(collector) }
            .bind(host: "127.0.0.1", port: 0).wait()
        #expect(client.remoteAddress == nil)
        // Datagrams keep their bounds, up to a large one.
        let payloads = ["one", "two", String(repeating: "x", count: 60_000)]
        for p in payloads {
            client.write(AddressedEnvelope(remoteAddress: serverAddress, data: ByteBuffer(string: p)), promise: nil)
        }
        client.flush()
        let replies = try done.futureResult.wait()
        #expect(replies.map { String(buffer: $0.data) }.sorted() == payloads.sorted())
        #expect(replies.allSatisfy { $0.remoteAddress == serverAddress })

        try client.close().wait()
        #expect(!client.isActive)
        #expect(throws: ChannelError.self) { try client.close().wait() }
        try server.close().wait()
    }

    /// A connected client: plain buffers out, envelopes from the peer back,
    /// and no writing anywhere else.
    @Test func connectedEcho() throws {
        let group = VegaEventLoopGroup(loops: 2)
        defer { try? group.syncShutdownGracefully() }
        let server = try VegaDatagramBootstrap(group: group)
            .channelInitializer { $0.pipeline.addHandler(DatagramEcho()) }
            .bind(host: "127.0.0.1", port: 0).wait()
        let serverAddress = try #require(server.localAddress)
        let port = try #require(serverAddress.port)

        let done = group.next().makePromise(of: [AddressedEnvelope<ByteBuffer>].self)
        let collector = DatagramCollector(expected: 2, done: done)
        let client = try VegaDatagramBootstrap(group: group)
            .channelInitializer { $0.pipeline.addHandler(collector) }
            .connect(host: "127.0.0.1", port: port).wait()
        #expect(client.remoteAddress == serverAddress)
        try client.writeAndFlush(ByteBuffer(string: "plain")).wait()
        try client.writeAndFlush(AddressedEnvelope(remoteAddress: serverAddress, data: ByteBuffer(string: "envelope"))).wait()
        let replies = try done.futureResult.wait()
        #expect(replies.map { String(buffer: $0.data) }.sorted() == ["envelope", "plain"])
        #expect(replies.allSatisfy { $0.remoteAddress == serverAddress })

        let elsewhere = try SocketAddress(ipAddress: "127.0.0.1", port: port == 9 ? 10 : 9)
        #expect(throws: ChannelError.self) {
            try client.writeAndFlush(AddressedEnvelope(remoteAddress: elsewhere, data: ByteBuffer(string: "no"))).wait()
        }
        try client.close().wait()
        try server.close().wait()
    }

    /// A bound channel connected afterwards, as NIO allows.
    @Test func connectAfterBind() throws {
        let group = VegaEventLoopGroup(loops: 1)
        defer { try? group.syncShutdownGracefully() }
        let server = try VegaDatagramBootstrap(group: group)
            .channelInitializer { $0.pipeline.addHandler(DatagramEcho()) }
            .bind(host: "127.0.0.1", port: 0).wait()
        let serverAddress = try #require(server.localAddress)
        let done = group.next().makePromise(of: [AddressedEnvelope<ByteBuffer>].self)
        let collector = DatagramCollector(expected: 1, done: done)
        let client = try VegaDatagramBootstrap(group: group)
            .channelInitializer { $0.pipeline.addHandler(collector) }
            .bind(host: "127.0.0.1", port: 0).wait()
        // Unconnected: a plain buffer has nowhere to go.
        #expect(throws: DatagramChannelError.WriteOnUnconnectedSocketWithoutAddress.self) {
            try client.writeAndFlush(ByteBuffer(string: "lost")).wait()
        }
        try client.connect(to: serverAddress).wait()
        #expect(client.remoteAddress == serverAddress)
        try client.writeAndFlush(ByteBuffer(string: "found")).wait()
        #expect(try done.futureResult.wait().map { String(buffer: $0.data) } == ["found"])
        try client.close().wait()
        try server.close().wait()
    }

    /// SO_REUSEADDR set on the bootstrap applies before binding: two
    /// sockets can share a port only with it.
    @Test func reuseAddress() throws {
        let group = VegaEventLoopGroup(loops: 1)
        defer { try? group.syncShutdownGracefully() }
        let first = try VegaDatagramBootstrap(group: group)
            .channelOption(.socketOption(.so_reuseaddr), value: 1)
            .bind(host: "127.0.0.1", port: 0).wait()
        let port = try #require(first.localAddress?.port)
        #expect(try first.getOption(.socketOption(.so_reuseaddr)).wait() != 0)
        #expect(throws: (any Error).self) {
            try VegaDatagramBootstrap(group: group).bind(host: "127.0.0.1", port: port).wait()
        }
        let second = try VegaDatagramBootstrap(group: group)
            .channelOption(.socketOption(.so_reuseaddr), value: 1)
            .bind(host: "127.0.0.1", port: port).wait()
        #expect(second.localAddress?.port == port)
        // Other options go on the socket once it exists.
        try second.setOption(.socketOption(.so_rcvbuf), value: 65_536).wait()
        #expect(try second.getOption(.socketOption(.so_rcvbuf)).wait() >= 65_536)
        try second.close().wait()
        try first.close().wait()
    }

    /// The async bind: both ends as `NIOAsyncChannel`s.
    @Test func asyncChannels() throws {
        typealias Envelope = AddressedEnvelope<ByteBuffer>
        let group = VegaEventLoopGroup(loops: 2)
        let rt = group.runtime
        defer { try? group.syncShutdownGracefully() }
        let replies = try rt.block {
            let server = try await VegaDatagramBootstrap(group: group).bind(host: "127.0.0.1", port: 0) { channel in
                channel.eventLoop.makeCompletedFuture {
                    try NIOAsyncChannel<Envelope, Envelope>(wrappingChannelSynchronously: channel)
                }
            }
            let serverAddress = server.channel.localAddress!
            return try await withThrowingTaskGroup(of: [String].self) { tasks in
                tasks.addTask {
                    try await server.executeThenClose { inbound, outbound in
                        var count = 0
                        for try await datagram in inbound {
                            try await outbound.write(Envelope(remoteAddress: datagram.remoteAddress,
                                                              data: ByteBuffer(string: "echo: " + String(buffer: datagram.data))))
                            count += 1
                            if count == 3 { break }
                        }
                    }
                    return []
                }
                tasks.addTask {
                    let client = try await VegaDatagramBootstrap(group: group).connect(to: serverAddress) { channel in
                        channel.eventLoop.makeCompletedFuture {
                            try NIOAsyncChannel<Envelope, ByteBuffer>(wrappingChannelSynchronously: channel)
                        }
                    }
                    return try await client.executeThenClose { inbound, outbound in
                        var got: [String] = []
                        var iterator = inbound.makeAsyncIterator()
                        for word in ["one", "two", "three"] {
                            try await outbound.write(ByteBuffer(string: word))
                            got.append(String(buffer: try await iterator.next()!.data))
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
}

private func temporaryDatagramPath() -> String {
    "/tmp/veganio-dgram-\(getpid())-\(UInt32.random(in: 0...UInt32.max)).sock"
}

@Suite struct UnixDatagramTests {
    /// Envelopes addressed by path, between two bound sockets.
    @Test func addressedEcho() throws {
        let group = VegaEventLoopGroup(loops: 2)
        defer { try? group.syncShutdownGracefully() }
        let serverPath = temporaryDatagramPath(), clientPath = temporaryDatagramPath()
        defer {
            unlink(serverPath)
            unlink(clientPath)
        }
        let server = try VegaDatagramBootstrap(group: group)
            .channelInitializer { $0.pipeline.addHandler(DatagramEcho()) }
            .bind(unixDomainSocketPath: serverPath).wait()
        let serverAddress = try #require(server.localAddress)
        #expect(serverAddress.pathname == serverPath)

        let done = group.next().makePromise(of: [AddressedEnvelope<ByteBuffer>].self)
        let collector = DatagramCollector(expected: 3, done: done)
        let client = try VegaDatagramBootstrap(group: group)
            .channelInitializer { $0.pipeline.addHandler(collector) }
            .bind(unixDomainSocketPath: clientPath).wait()
        let payloads = ["one", "two", String(repeating: "y", count: 50_000)]
        for p in payloads {
            client.write(AddressedEnvelope(remoteAddress: serverAddress, data: ByteBuffer(string: p)), promise: nil)
        }
        client.flush()
        let replies = try done.futureResult.wait()
        #expect(replies.map { String(buffer: $0.data) }.sorted() == payloads.sorted())
        #expect(replies.allSatisfy { $0.remoteAddress.pathname == serverPath })
        try client.close().wait()
        try server.close().wait()
    }

    /// A connected client is unbound: it sends plain buffers, and the
    /// server sees an empty path as their sender. The bound path stays
    /// behind, and needs cleaning up to bind again.
    @Test func connectedAndCleanup() throws {
        let group = VegaEventLoopGroup(loops: 2)
        defer { try? group.syncShutdownGracefully() }
        let path = temporaryDatagramPath()
        defer { unlink(path) }
        let done = group.next().makePromise(of: [AddressedEnvelope<ByteBuffer>].self)
        let collector = DatagramCollector(expected: 2, done: done)
        let server = try VegaDatagramBootstrap(group: group)
            .channelInitializer { $0.pipeline.addHandler(collector) }
            .bind(unixDomainSocketPath: path).wait()
        let client = try VegaDatagramBootstrap(group: group).connect(unixDomainSocketPath: path).wait()
        #expect(client.remoteAddress?.pathname == path)
        #expect(client.localAddress == nil)
        try client.writeAndFlush(ByteBuffer(string: "plain")).wait()
        try client.writeAndFlush(AddressedEnvelope(remoteAddress: try SocketAddress(unixDomainSocketPath: path),
                                                   data: ByteBuffer(string: "envelope"))).wait()
        let got = try done.futureResult.wait()
        #expect(got.map { String(buffer: $0.data) } == ["plain", "envelope"])
        #expect(got.allSatisfy { $0.remoteAddress.pathname == "" })
        try client.close().wait()
        try server.close().wait()

        #expect(throws: (any Error).self) {
            try VegaDatagramBootstrap(group: group).bind(unixDomainSocketPath: path).wait()
        }
        let again = try VegaDatagramBootstrap(group: group)
            .bind(unixDomainSocketPath: path, cleanupExistingSocketFile: true).wait()
        try again.close().wait()
    }

    /// The async forms over Unix datagram sockets.
    @Test func asyncChannels() throws {
        typealias Envelope = AddressedEnvelope<ByteBuffer>
        let group = VegaEventLoopGroup(loops: 2)
        let rt = group.runtime
        defer { try? group.syncShutdownGracefully() }
        let path = temporaryDatagramPath()
        defer { unlink(path) }
        let received = try rt.block {
            let server = try await VegaDatagramBootstrap(group: group).bind(unixDomainSocketPath: path) { channel in
                channel.eventLoop.makeCompletedFuture {
                    try NIOAsyncChannel<Envelope, Envelope>(wrappingChannelSynchronously: channel)
                }
            }
            let client = try await VegaDatagramBootstrap(group: group).connect(unixDomainSocketPath: path) { channel in
                channel.eventLoop.makeCompletedFuture {
                    try NIOAsyncChannel<Envelope, ByteBuffer>(wrappingChannelSynchronously: channel)
                }
            }
            try await client.executeThenClose { _, outbound in
                for word in ["one", "two"] { try await outbound.write(ByteBuffer(string: word)) }
            }
            return try await server.executeThenClose { inbound, _ in
                var got: [String] = []
                for try await datagram in inbound {
                    got.append(String(buffer: datagram.data))
                    if got.count == 2 { break }
                }
                return got
            }
        }
        #expect(received == ["one", "two"])
    }
}
