# Migrating from SwiftNIO

This guide is for code written against SwiftNIO (`NIOCore`, `NIOPosix`, `NIOExtras`, `NIOFileSystem`) that you want to move to Vega's native API.

Vega has no channel pipeline and no futures. A connection is a value you `await` on, protocol logic is a codec or a plain async function, and the runtime is a work-stealing scheduler that every task runs on. Most NIO code gets shorter in the move, because the state that handlers kept between callbacks becomes local variables in one async function.

If you need to keep NIO handlers running unchanged during a migration, the [`VegaNIO`](../VegaNIO/README.md) package provides NIO's `EventLoopGroup`, `Channel` and bootstraps on top of Vega's I/O. This guide covers the native API.

The Vega snippets below compile and run against Vega at the commit that added this guide; they were checked in a scratch package that depends on `Vega`, `VegaIO`, `VegaFS` and `VegaTest`. The NIO snippets show the usual pattern and are not compiled here.

## Concept map

| SwiftNIO | Vega | Module |
|---|---|---|
| `MultiThreadedEventLoopGroup` | `Runtime(workers:)` | `Vega` |
| `EventLoop.execute`, `submit` | `runtime.spawn { ... }` | `Vega` |
| `Channel` | `TCPStream` (or `UnixStream`), with `FramedRead` / `FramedWrite` on top | `Vega`, `VegaIO` |
| `ChannelHandler`, `ChannelPipeline` | A `Decoder` / `Encoder`, or a plain async function | `VegaIO` |
| `ByteToMessageDecoder`, `MessageToByteEncoder` | `Decoder`, `Encoder` | `VegaIO` |
| `LineBasedFrameDecoder`, `LengthFieldBasedFrameDecoder` | `LinesCodec`, `LengthDelimitedCodec` | `VegaIO` |
| `EventLoopFuture`, `EventLoopPromise` | `async` / `await`, `Task` | Swift |
| `EventLoop.scheduleTask(in:)` | `Runtime.sleep(for:)`, `Runtime.timeout(_:_:)`, `Runtime.withIODeadline(_:_:)` | `Vega` |
| `ServerBootstrap` | `TCPServer.bind(port:configuration:handler:)` | `Vega` |
| `ClientBootstrap` | `TCPClient(...).connect(host:port:)` (Happy Eyeballs v2) | `Vega` |
| `NIOAsyncChannel` | The stream itself: `read(into:)` / `write(_:)`, or `FramedRead.next()` / `FramedWrite.send(_:)` | `Vega`, `VegaIO` |
| `ByteBuffer` | `IOBuffer` | `Vega` |
| `NIOFileSystem`, `NIOFileHandle` | `FileSystem`, `File` | `VegaFS` |
| `NIOPipeBootstrap` | `makePipe()`, `PipeReader(adopting:)`, `PipeWriter(adopting:)` | `Vega` |
| `EmbeddedChannel`, `NIOAsyncTestingChannel` | `duplex()` in-memory streams, `MockClock` | `VegaTest` |
| `ServerQuiescingHelper` | `ShutdownSignal`, which `TCPServer.shutdown` triggers and the HTTP servers take | `Vega` |
| `HTTPResponseCompressor`, `NIOHTTPRequestDecompressor` | `HTTPCompression` (`wrap(_:)` a handler; `decompress(_:)`), `Compressor`, `Decompressor` | `VegaExtras` |

## The event loop group becomes a runtime

NIO:

```swift
let group = MultiThreadedEventLoopGroup(numberOfThreads: 4)
defer { try! group.syncShutdownGracefully() }

let answer = try group.next().submit { 6 * 7 }.wait()
```

Vega:

```swift
let runtime = Runtime(workers: 4)
defer { runtime.shutdown() }

try runtime.block { () async throws in
    let answer = await runtime.spawn { 6 * 7 }.value
    print(answer)
}
```

- `block` runs an async body on the runtime and waits for it from a thread that isn't one of the runtime's workers, such as `main`. Inside, structured concurrency (`async let`, task groups) stays on the runtime.
- `runtime.spawn` starts a task on the runtime. A plain `Task { }` started inside it does **not** inherit the runtime (Swift drops executor preferences for unstructured tasks). Use `spawn`, or on Linux make Vega the process's global executor with `Runtime.installGlobal()`.
- There is no `EventLoop` to hop between. Tasks run on whichever worker is free, and work stealing balances them.

## A server: bootstrap and handlers become one function

NIO, a line-based server that upper-cases each line:

```swift
final class UppercaseHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = unwrapInboundIn(data)
        let line = buffer.readString(length: buffer.readableBytes) ?? ""
        let reply = context.channel.allocator.buffer(string: line.uppercased() + "\n")
        context.writeAndFlush(wrapOutboundOut(reply), promise: nil)
    }
}

let server = try ServerBootstrap(group: group)
    .serverChannelOption(.backlog, value: 256)
    .childChannelInitializer { channel in
        channel.pipeline.addHandlers([
            ByteToMessageHandler(LineBasedFrameDecoder()),
            UppercaseHandler(),
        ])
    }
    .bind(host: "0.0.0.0", port: 8080)
    .wait()
try server.closeFuture.wait()
```

Vega:

```swift
let server = try TCPServer.bind(port: 8080) { stream in
    let halves = stream.split()
    var lines = FramedRead(reading: halves.reader, decoder: LinesCodec())
    var replies = FramedWrite(writing: halves.writer, encoder: LinesCodec())
    do {
        while let line = try await lines.next() {
            try await replies.send(line.uppercased())
        }
    } catch {
        // The peer went away, or sent a line over the codec's limit.
    }
}
await server.waitForShutdown()
```

- Call `TCPServer.bind` from a task on the runtime. Each connection runs the handler in its own task, and the connection closes when the handler returns.
- `TCPServer.Configuration` holds what the bootstrap's options held: `backlog`, `acceptors` (several accept loops sharing the port with `SO_REUSEPORT`), `maxConnections`, and socket options for the listener and for each connection.
- `server.shutdown(gracePeriod:)` stops accepting, lets open connections finish for the grace period, then cancels the rest: NIO's quiescing helper, built in. It first triggers the server's `ShutdownSignal`, which you can supply through `Configuration.shutdownSignal`. Pass the same signal to `HTTP1Server.serve(_:shutdown:)` or `HTTP2Server.serve(_:shutdown:)`. HTTP/1 then closes idle keep-alive connections at once, and answers a request already in progress with `connection: close`. HTTP/2 sends GOAWAY and finishes its open streams. Your own handlers can await `signal.wait()`, or wrap their wait for more input in `signal.cancelOnTrigger { }`.
- Backpressure needs no `isWritable` or `channelWritabilityChanged`. `send` returns once the bytes are written, so a slow peer slows the loop that writes to it. `FramedWrite.feed` buffers items, and `flush` writes them out, as with NIO's `write` and `flush`.
- `stream.split()` gives a read half and a write half that separate tasks can use at once.

## A client: the bootstrap becomes a connect call

NIO:

```swift
let channel = try ClientBootstrap(group: group)
    .connectTimeout(.seconds(5))
    .channelInitializer { channel in
        channel.pipeline.addHandlers([
            ByteToMessageHandler(LengthFieldBasedFrameDecoder(lengthFieldBitLength: .fourBytes)),
            LengthFieldPrepender(lengthFieldBitLength: .fourBytes),
            ReplyHandler(),
        ])
    }
    .connect(host: "example.com", port: 4000)
    .wait()
```

Vega:

```swift
let stream = try await TCPClient(connectTimeout: .seconds(5)).connect(host: "example.com", port: 4000)
let halves = stream.split()
var out = FramedWrite(writing: halves.writer, encoder: LengthDelimitedCodec())
var replies = FramedRead(reading: halves.reader, decoder: LengthDelimitedCodec())
try await out.send(Array("ping".utf8))
if let reply = try await replies.next() {
    print(String(decoding: reply, as: UTF8.self))
}
```

- `connect(host:port:)` resolves the name and races the addresses with Happy Eyeballs v2 (RFC 8305): IPv6 and IPv4 are interleaved, and a dead address costs `attemptDelay` (250 ms by default), not a full connect timeout.
- `TCPClient` also takes a `Resolver` (Vega's async DNS client) and socket options. `TCPStream.connect(host:port:)` is the same connect without the extra settings.

## Handlers become codecs or plain code

A `ByteToMessageDecoder` and a `MessageToByteEncoder` map to one value that conforms to `Decoder` and `Encoder`. `decode` sees the bytes not yet decoded and returns an item and how many bytes it used, or nil to wait for more. There is no buffer to move a reader index on.

NIO:

```swift
struct ShortStringDecoder: ByteToMessageDecoder {
    typealias InboundOut = String

    mutating func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        guard let length = buffer.getInteger(at: buffer.readerIndex, as: UInt16.self),
              buffer.readableBytes >= 2 + Int(length) else { return .needMoreData }
        buffer.moveReaderIndex(forwardBy: 2)
        let text = buffer.readString(length: Int(length))!
        context.fireChannelRead(wrapInboundOut(text))
        return .continue
    }
}
```

Vega:

```swift
/// A 2-byte big-endian length, then that many bytes of UTF-8.
struct ShortStringCodec: Decoder, Encoder {
    mutating func decode(_ bytes: UnsafeRawBufferPointer) throws(CodecError) -> (item: String, consumed: Int)? {
        guard bytes.count >= 2 else { return nil }
        let length = Int(bytes[0]) << 8 | Int(bytes[1])
        guard bytes.count >= 2 + length else { return nil }
        let text = String(decoding: UnsafeRawBufferPointer(rebasing: bytes[2..<2 + length]), as: UTF8.self)
        return (text, 2 + length)
    }

    mutating func encode(_ item: String, into buffer: inout IOBuffer) throws(CodecError) {
        let utf8 = Array(item.utf8)
        guard utf8.count <= 0xFFFF else { throw .frameTooLong(utf8.count) }
        let header: [UInt8] = [UInt8(utf8.count >> 8), UInt8(utf8.count & 0xFF)]
        header.withUnsafeBytes { buffer.write($0) }
        utf8.withUnsafeBytes { buffer.write($0) }
    }
}
```

- `FramedRead` reads into one buffer and decodes in place, so a frame costs no copy beyond what the decoder makes.
- Override `decodeAtEnd` to accept a partial last frame when the stream ends. By default, leftover bytes throw `CodecError.truncated`.
- Logic that sat in other handlers (authentication, routing, idle timeouts) becomes ordinary code in the connection's function. Put a deadline on any step with `Runtime.timeout`.

## Futures become async

NIO:

```swift
fetchGreeting(on: eventLoop)
    .flatMap { greeting in eventLoop.scheduleTask(in: .milliseconds(100)) { greeting }.futureResult }
    .whenComplete { result in print(result) }

let both = EventLoopFuture.whenAllSucceed([fetchGreeting(on: eventLoop), fetchGreeting(on: eventLoop)], on: eventLoop)
```

Vega:

```swift
let greeting = try await fetchGreeting()
try await Runtime.sleep(for: .milliseconds(100))
let late = try await Runtime.timeout(.seconds(2)) { try await fetchGreeting() }
async let a = fetchGreeting(), b = fetchGreeting()
let both = try await [a, b]
```

- Vega's I/O throws `IOError` with typed throws, so `do throws(IOError)` keeps the error concrete. `IOError.cancelled` reports a cancelled wait.
- Cancellation is task cancellation. Cancelling a task wakes any socket wait, sleep or lock wait it is in. There is no promise to fail.
- `Runtime.timeout` arms one timer on the runtime's wheel and unlinks it in O(1) when the operation finishes first.
- `Runtime.withIODeadline` bounds only the I/O waits inside it, and runs them in the calling task instead of a child task. On the bench box it costs about 0.5 µs, against about 2.7–3.3 µs for `timeout`. A wait still pending at the deadline throws `IOError.timedOut` and the task is not cancelled. Use it for a request and its reply on a connection; use `timeout` when the step also waits on other things, such as a channel or a lock.

## ByteBuffer becomes IOBuffer

`IOBuffer` is a non-copyable byte buffer: the bytes are `0..<count`, with spare capacity after them for reads to fill.

```swift
var buffer = IOBuffer(capacity: 64)
_ = buffer.append("hello, ")
"world".utf8CString.dropLast().withUnsafeBytes { buffer.write($0) }
print(buffer.count, buffer.string)
let first = buffer.withUnsafeBytes { $0[0] }
buffer.consume(7) // drop "hello, " from the front
```

| `ByteBuffer` | `IOBuffer` |
|---|---|
| `allocator.buffer(capacity:)` | `IOBuffer(capacity:)` |
| `writeString`, `writeBytes` | `append(_:)` (fails short when full), `write(_:)` (grows) |
| `readableBytes` | `count` |
| `readableBytesView`, `withUnsafeReadableBytes` | `withUnsafeBytes` |
| `moveReaderIndex(forwardBy:)` | `consume(_:)` |
| `clear()` | `clear()` |
| `writableBytes` | `spareCapacity` |

- `IOBuffer` is `~Copyable`: it has one owner, and copying it means saying so. There is no copy-on-write and no reference count on the hot path.
- Most protocol code doesn't touch buffers at all once it is written as a codec: items in and items out.

## NIOFileSystem becomes VegaFS

```swift
try await FileSystem.write("/tmp/notes.txt", contents: "one\ntwo\n")
let text = try await FileSystem.readString("/tmp/notes.txt")

let file = try await File.open("/tmp/notes.txt")
var buffer = IOBuffer(capacity: 4096)
_ = try await file.readToEnd(into: &buffer)
```

- On Linux with io_uring, file I/O goes through the ring. Elsewhere it runs on the runtime's blocking pool, so it never stalls a worker.
- `File` also has positional reads and writes (`read(into:at:)`, `write(_:at:)`), `sync`, `metadata` and `setLength`. `FileSystem` has `copyFile`, `rename`, links, directory listing and metadata.
- `File` conforms to `AsyncReader` and `AsyncWriter`, so `FramedRead`, codecs and `copy(from:to:)` work on files as they do on sockets.

## NIOPipeBootstrap becomes makePipe

```swift
let pipe = try makePipe()
var bytes = IOBuffer(capacity: 16)
_ = bytes.append("ping")
try await pipe.writer.write(bytes)
var received = IOBuffer(capacity: 16)
_ = try await pipe.reader.read(into: &received)
```

`PipeReader(adopting:)` and `PipeWriter(adopting:)` take over an fd you already have (a pipe inherited from a parent, say), which is what `NIOPipeBootstrap.takingOwnershipOfDescriptors` did. For child processes, `VegaProcess` sets up the pipes for you (`Command`, `Child`, `Output`).

## EmbeddedChannel becomes in-memory streams

`EmbeddedChannel` ran handlers without a network. In Vega, code under test takes any `AsyncReader & AsyncWriter`, and the test hands it one end of an in-memory `duplex()` pair:

```swift
func uppercaser<S: AsyncReader & AsyncWriter & ~Copyable>(_ stream: consuming S) async throws {
    var buffer = IOBuffer(capacity: 1024)
    while try await stream.read(into: &buffer) > 0 {
        let upper = buffer.string.uppercased()
        buffer.clear()
        var out = IOBuffer(capacity: upper.utf8.count)
        _ = out.append(upper)
        try await stream.write(out)
    }
}

let runtime = Runtime(workers: 2)
defer { runtime.shutdown() }
let reply = try runtime.block { () async throws -> String in
    let pair = duplex()
    let task = runtime.spawn(with: pair.second) { server in try? await uppercaser(server) }
    var lines = FramedWrite(writing: pair.first, encoder: LinesCodec())
    try await lines.send("hi")
    let client = lines.intoWriter()
    var reply = IOBuffer(capacity: 16)
    _ = try await client.read(into: &reply)
    client.shutdownWrite()
    await task.value
    return reply.string // "HI\n"
}
```

- `duplex(capacity:)` streams have a bounded buffer, so they exercise backpressure as a socket does.
- For code with timers, `MockClock(pausing: runtime)` pauses the runtime's time, and `advance(by:)` moves it, in place of `EmbeddedEventLoop.advanceTime`.

## Things that work differently

- **Streams are `~Copyable`.** A `TCPStream` has exactly one owner, and dropping it closes the socket. To hand one to another task, use `runtime.spawn(with: stream) { stream in ... }`, since a closure can't capture a non-copyable value.
- **No handler thread affinity.** NIO guaranteed that a channel's handlers ran on one event loop thread. A Vega connection's task may resume on any worker. That is safe because its state is local to the task, but code that relied on `assertInEventLoop` or on thread-local state needs another way, such as an actor or `AsyncMutex`.
- **Async calls stay on the caller's executor.** Vega is built with Swift's `NonisolatedNonsendingByDefault`, so its async functions, such as `read`, `write` and `withIODeadline`, run where they are called from, not on the generic executor. Returning from one is no executor hop, and on a runtime whose tasks prefer an executor every hop takes a lock. Called from an actor, they run on that actor until they suspend for I/O. Build your own code the same way to keep its hops down too.
- **Errors are typed.** Socket, file and pipe calls throw `IOError` (an errno plus named cases such as `.connectionRefused` and `.cancelled`). Framed reads and writes throw `FramedError`, which wraps either an `IOError` or a `CodecError`.
- **Platforms.** Vega runs on Linux (io_uring by default, or epoll) and macOS (kqueue). On macOS, Swift's executor SPI is unavailable, so `Runtime.installGlobal()` only routes global enqueues to Vega, and `Task.sleep` keeps the platform's timers. `Runtime.sleep` always uses Vega's timers.
