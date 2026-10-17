import NIOConcurrencyHelpers
import NIOCore
import Testing
@testable import VegaNIO
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

private final class Echo: ChannelInboundHandler, Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        context.write(data, promise: nil)
    }

    func channelReadComplete(context: ChannelHandlerContext) {
        context.flush()
    }
}

/// Collects bytes until `expected` have come; end of input before then
/// fails it.
private final class Gather: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    private var received = ByteBuffer()
    private let expected: Int
    let done: EventLoopPromise<ByteBuffer>

    init(expected: Int, done: EventLoopPromise<ByteBuffer>) {
        self.expected = expected
        self.done = done
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = unwrapInboundIn(data)
        received.writeBuffer(&buffer)
        if received.readableBytes >= expected { done.succeed(received) }
    }

    func channelInactive(context: ChannelHandlerContext) {
        done.fail(ChannelError.eof)
    }
}

private func temporarySocketPath() -> String {
    "/tmp/veganio-\(getpid())-\(UInt32.random(in: 0...UInt32.max)).sock"
}

private func payload(_ count: Int) -> ByteBuffer {
    ByteBuffer(bytes: (0..<count).map { UInt8(truncatingIfNeeded: $0 &* 13) })
}

@Suite struct UnixSocketTests {
    @Test func echo() throws {
        let group = VegaEventLoopGroup(loops: 2)
        defer { try? group.syncShutdownGracefully() }
        let path = temporarySocketPath()
        defer { unlink(path) }
        let server = try VegaServerBootstrap(group: group)
            .childChannelInitializer { $0.pipeline.addHandler(Echo()) }
            .bind(unixDomainSocketPath: path).wait()
        #expect(server.localAddress?.pathname == path)

        let data = payload(300_000)
        let done = group.next().makePromise(of: ByteBuffer.self)
        let client = try VegaClientBootstrap(group: group)
            .channelInitializer { $0.pipeline.addHandler(Gather(expected: data.readableBytes, done: done)) }
            .connect(unixDomainSocketPath: path).wait()
        #expect(client.isActive)
        #expect(client.remoteAddress?.pathname == path)
        var rest = data
        while rest.readableBytes > 0 {
            client.write(rest.readSlice(length: min(rest.readableBytes, 1000))!, promise: nil)
        }
        try client.writeAndFlush(ByteBuffer()).wait()
        #expect(try done.futureResult.wait() == data)
        try client.close().wait()
        try server.close().wait()
    }

    /// The socket file stays behind; a second bind needs it cleaned up.
    @Test func cleanupExistingSocketFile() throws {
        let group = VegaEventLoopGroup(loops: 1)
        defer { try? group.syncShutdownGracefully() }
        let path = temporarySocketPath()
        defer { unlink(path) }
        let first = try VegaServerBootstrap(group: group).bind(unixDomainSocketPath: path).wait()
        try first.close().wait()
        #expect(throws: (any Error).self) {
            try VegaServerBootstrap(group: group).bind(unixDomainSocketPath: path).wait()
        }
        let second = try VegaServerBootstrap(group: group)
            .bind(unixDomainSocketPath: path, cleanupExistingSocketFile: true).wait()
        try second.close().wait()
        // Something there that isn't a socket is left alone.
        let file = path + ".txt"
        let fd = open(file, O_CREAT | O_WRONLY, 0o600)
        #expect(fd >= 0)
        close(fd)
        defer { unlink(file) }
        #expect(throws: (any Error).self) {
            try VegaServerBootstrap(group: group).bind(unixDomainSocketPath: file, cleanupExistingSocketFile: true).wait()
        }
        #expect(access(file, F_OK) == 0)
    }

    @Test func connectToNothing() throws {
        let group = VegaEventLoopGroup(loops: 1)
        defer { try? group.syncShutdownGracefully() }
        #expect(throws: (any Error).self) {
            try VegaClientBootstrap(group: group).connect(unixDomainSocketPath: temporarySocketPath()).wait()
        }
    }

    /// The async bind and connect over a Unix socket.
    @Test func asyncChannels() throws {
        let group = VegaEventLoopGroup(loops: 2)
        let rt = group.runtime
        defer { try? group.syncShutdownGracefully() }
        let path = temporarySocketPath()
        defer { unlink(path) }
        let replies = try rt.block {
            let server = try await VegaServerBootstrap(group: group).bind(unixDomainSocketPath: path) { channel in
                channel.eventLoop.makeCompletedFuture {
                    try NIOAsyncChannel<ByteBuffer, ByteBuffer>(wrappingChannelSynchronously: channel)
                }
            }
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
                    let client = try await VegaClientBootstrap(group: group).connect(unixDomainSocketPath: path) { channel in
                        channel.eventLoop.makeCompletedFuture {
                            try NIOAsyncChannel<ByteBuffer, ByteBuffer>(wrappingChannelSynchronously: channel)
                        }
                    }
                    return try await client.executeThenClose { inbound, outbound in
                        var got: [String] = []
                        var iterator = inbound.makeAsyncIterator()
                        for word in ["one", "two"] {
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
        #expect(replies == ["echo: one", "echo: two"])
    }
}

/// A pipe(2): (read end, write end).
private func makeRawPipe() throws -> (CInt, CInt) {
    var fds: [CInt] = [-1, -1]
    guard pipe(&fds) == 0 else { throw NIOCore.IOError(errnoCode: errno, reason: "pipe") }
    return (fds[0], fds[1])
}

@Suite struct PipeTests {
    /// Two pipe channels facing each other over two pipes: one echoes what
    /// the other sends.
    @Test func echoOverPipes() throws {
        let group = VegaEventLoopGroup(loops: 2)
        defer { try? group.syncShutdownGracefully() }
        let (aRead, bWrite) = try makeRawPipe() // b -> a
        let (bRead, aWrite) = try makeRawPipe() // a -> b
        let echo = try VegaPipeBootstrap(group: group)
            .channelInitializer { $0.pipeline.addHandler(Echo()) }
            .takingOwnershipOfDescriptors(input: bRead, output: bWrite).wait()
        let data = payload(300_000)
        let done = group.next().makePromise(of: ByteBuffer.self)
        let client = try VegaPipeBootstrap(group: group)
            .channelInitializer { $0.pipeline.addHandler(Gather(expected: data.readableBytes, done: done)) }
            .takingOwnershipOfDescriptors(input: aRead, output: aWrite).wait()
        #expect(client.isActive)
        #expect(client.localAddress == nil)
        var rest = data
        while rest.readableBytes > 0 {
            client.write(rest.readSlice(length: min(rest.readableBytes, 4000))!, promise: nil)
        }
        try client.writeAndFlush(ByteBuffer()).wait()
        #expect(try done.futureResult.wait() == data)

        // Closing the client closes its pipe ends; the echo channel sees
        // end of input and closes too.
        try client.close().wait()
        try echo.closeFuture.wait()
        #expect(!echo.isActive)
    }

    /// A writer-only channel and a reader-only one: closing the output
    /// closes the writer (it has nothing else), and the reader gets what
    /// was sent, then end of input.
    @Test func oneWay() throws {
        let group = VegaEventLoopGroup(loops: 2)
        defer { try? group.syncShutdownGracefully() }
        let (r, w) = try makeRawPipe()
        let done = group.next().makePromise(of: ByteBuffer.self)
        let reader = try VegaPipeBootstrap(group: group)
            .channelOption(.allowRemoteHalfClosure, value: true)
            .channelInitializer { $0.pipeline.addHandler(Gather(expected: 1 << 30, done: done)) }
            .takingOwnershipOfDescriptor(input: r).wait()
        let inputClosed = group.next().makePromise(of: Void.self)
        final class WatchInputClosed: ChannelInboundHandler, Sendable {
            typealias InboundIn = ByteBuffer
            let seen: EventLoopPromise<Void>
            init(_ seen: EventLoopPromise<Void>) { self.seen = seen }
            func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
                if case ChannelEvent.inputClosed = event { seen.succeed(()) }
                context.fireUserInboundEventTriggered(event)
            }
        }
        try reader.pipeline.addHandler(WatchInputClosed(inputClosed), position: .first).wait()
        #expect(throws: ChannelError.self) { try reader.writeAndFlush(ByteBuffer(string: "x")).wait() }

        let writer = try VegaPipeBootstrap(group: group).takingOwnershipOfDescriptor(output: w).wait()
        try writer.writeAndFlush(ByteBuffer(string: "hello, pipe")).wait()
        try writer.close(mode: .output).wait()
        try writer.closeFuture.wait()

        // End of input with half-closure allowed is an event, and with no
        // output either the channel then closes.
        try inputClosed.futureResult.wait()
        try reader.closeFuture.wait()
        #expect(throws: ChannelError.self) { try done.futureResult.wait() }
    }

    /// Closing a pipe channel's input alone: its read end goes, its write
    /// end stays.
    @Test func closeInput() throws {
        let group = VegaEventLoopGroup(loops: 1)
        defer { try? group.syncShutdownGracefully() }
        let (aRead, bWrite) = try makeRawPipe()
        let (bRead, aWrite) = try makeRawPipe()
        defer {
            close(bWrite)
            close(bRead)
        }
        let channel = try VegaPipeBootstrap(group: group).takingOwnershipOfDescriptors(input: aRead, output: aWrite).wait()
        try channel.close(mode: .input).wait()
        #expect(channel.isActive)
        // Its read end is closed: that pipe's write end reports an error
        // (polled rather than written, which would raise SIGPIPE).
        var attempts = 0
        var pfd = pollfd(fd: bWrite, events: Int16(POLLOUT), revents: 0)
        let broken = Int16(POLLERR) | Int16(POLLHUP)
        repeat {
            try group.next().scheduleTask(in: .milliseconds(5)) {}.futureResult.wait()
            pfd.revents = 0
            _ = poll(&pfd, 1, 0)
            attempts += 1
        } while pfd.revents & broken == 0 && attempts < 200
        #expect(pfd.revents & broken != 0)
        try channel.writeAndFlush(ByteBuffer(string: "still")).wait()
        var buffer = [UInt8](repeating: 0, count: 16)
        #expect(read(bRead, &buffer, 16) == 5)
        try channel.close().wait()
    }

    /// Regular files can't be waited on: refused, and left open.
    @Test func refusesRegularFiles() throws {
        let group = VegaEventLoopGroup(loops: 1)
        defer { try? group.syncShutdownGracefully() }
        let path = temporarySocketPath() + ".file"
        let fd = open(path, O_CREAT | O_RDWR, 0o600)
        #expect(fd >= 0)
        defer {
            close(fd)
            unlink(path)
        }
        #expect(throws: ChannelError.operationUnsupported) {
            try VegaPipeBootstrap(group: group).takingOwnershipOfDescriptor(input: fd).wait()
        }
        #expect(throws: ChannelError.operationUnsupported) {
            try VegaPipeBootstrap(group: group).takingOwnershipOfDescriptor(inputOutput: fd).wait()
        }
        #expect(fcntl(fd, F_GETFD) >= 0)
    }

    /// The async form: an `NIOAsyncChannel` over a socketpair, as one
    /// descriptor that both reads and writes.
    @Test func asyncInputOutput() throws {
        let group = VegaEventLoopGroup(loops: 2)
        let rt = group.runtime
        defer { try? group.syncShutdownGracefully() }
        var fds: [CInt] = [-1, -1]
        #if canImport(Glibc)
        let streamType = Int32(SOCK_STREAM.rawValue)
        #else
        let streamType = SOCK_STREAM
        #endif
        #expect(socketpair(AF_UNIX, streamType, 0, &fds) == 0)
        let (mine, theirs) = (fds[0], fds[1])
        let echo = try VegaPipeBootstrap(group: group)
            .channelInitializer { $0.pipeline.addHandler(Echo()) }
            .takingOwnershipOfDescriptor(inputOutput: theirs).wait()
        let got = try rt.block {
            let channel = try await VegaPipeBootstrap(group: group).takingOwnershipOfDescriptor(inputOutput: mine) { channel in
                channel.eventLoop.makeCompletedFuture {
                    try NIOAsyncChannel<ByteBuffer, ByteBuffer>(wrappingChannelSynchronously: channel)
                }
            }
            return try await channel.executeThenClose { inbound, outbound in
                try await outbound.write(ByteBuffer(string: "ping"))
                var iterator = inbound.makeAsyncIterator()
                return String(buffer: try await iterator.next()!)
            }
        }
        #expect(got == "ping")
        try echo.closeFuture.wait()
    }
}
