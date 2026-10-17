# VegaNIO

SwiftNIO's `EventLoopGroup`, `EventLoop`, `Channel` and bootstraps, running on Vega. NIO handlers, `ChannelPipeline`, `EventLoopFuture` and `NIOAsyncChannel` work as they do on NIO, while Vega does the scheduling and the I/O.

VegaNIO is its own package, so that Vega keeps no dependencies. It depends on Vega and on swift-nio's `NIOCore`.

```swift
import NIOCore
import NIOHTTP1
import VegaNIO

let group = VegaEventLoopGroup(loops: 8)
let server = try await VegaServerBootstrap(group: group)
    .childChannelInitializer { channel in
        channel.pipeline.configureHTTPServerPipeline().flatMap {
            channel.pipeline.addHandler(HelloHandler())
        }
    }
    .bind(host: "0.0.0.0", port: 8080).get()
```

| NIOPosix | VegaNIO |
|---|---|
| `MultiThreadedEventLoopGroup` | `VegaEventLoopGroup(loops:)`, or `VegaEventLoopGroup(runtime:loops:)` on a runtime you already have |
| `ServerBootstrap` | `VegaServerBootstrap`, including the async `bind(host:port:childChannelInitializer:)` that returns an `NIOAsyncChannel`; `bind(unixDomainSocketPath:cleanupExistingSocketFile:)` listens on a Unix domain socket |
| `ClientBootstrap` | `VegaClientBootstrap`, which is an `NIOClientTCPBootstrapProtocol`; `connect(host:port:)` races the host's addresses (Happy Eyeballs); `connect(unixDomainSocketPath:)` |
| `DatagramBootstrap` | `VegaDatagramBootstrap`: UDP channels of `AddressedEnvelope<ByteBuffer>`, bound (`bind(host:port:)`, `bind(to:)`) or connected (`connect(host:port:)`, `connect(to:)`, which also take plain `ByteBuffer` writes), with the async forms that wrap the channel in an `NIOAsyncChannel` before it goes active |
| `NIOPipeBootstrap` | `VegaPipeBootstrap`: `takingOwnershipOfDescriptors(input:output:)`, `takingOwnershipOfDescriptor(input:)`, `(output:)` and `(inputOutput:)`, and their async forms. Regular files are refused, as on NIO. Linux and macOS |

## How it runs

- **A loop is a serial queue, not a thread.** Handlers on one loop run one at a time and in order, as NIO promises, and `inEventLoop`, `preconditionInEventLoop` and `assumeIsolated` hold while they run. Whichever Vega worker picks up a loop's work runs it, so a loop doesn't stay on one thread from one tick to the next. NIOTransportServices' loops on Dispatch behave the same way. A group can have more loops than the runtime has workers.
- **Swift tasks isolated to a loop** (an actor whose `unownedExecutor` is `eventLoop.executor`) run on the loop, inline.
- **Each connection has a reader task and a writer task.** These are ordinary Vega tasks that any worker can steal. The reader reads when the pipeline asks for a read (`autoRead` asks after every delivery) and hands the bytes to the loop. When nobody else is running the loop, the reader delivers on its own task, so a quiet connection costs no hop. `flush()` sends what the socket takes there and then, as NIO's does (Vega's `tryWrite`, which never waits), and completes those write promises at once. Only what doesn't fit goes to the writer, which sends it when the socket has room and then reports back. While the writer is busy, later flushes queue behind it, so bytes always go out in order.
- **Unix sockets and pipes** run the same way, over Vega's `UnixStream` and its `PipeReader` and `PipeWriter`. A pipe has no write that never waits, so its `flush()` hands everything to the writer, and write promises complete once the writer has sent them. A pipe channel can close its input or its output on its own, and closes once neither is left.
- **A UDP channel** has a reader task that receives one datagram (up to 64 KiB, so none is cut short) whenever the pipeline asks for a read, and a writer task that sends flushed datagrams in order, completing each write's promise once its datagram has gone. A datagram the network refuses fails its own write, or comes up as an `errorCaught` while reading, and doesn't close the channel. `SO_REUSEADDR` and `SO_REUSEPORT` set as channel options apply before the socket binds.
- **Closing a channel** stops reading at once and fails writes that were never flushed. Flushed writes still go out, so write-then-close works as it does on NIO, but only for up to 10 seconds if the peer isn't taking them.
- **Scheduled tasks** use Vega's timer wheel. Cancelling a task from its loop before it runs means it never runs.

## Not yet

- Unix *datagram* sockets (`VegaDatagramBootstrap.bind(unixDomainSocketPath:)`), multicast (`MulticastChannel`), and UDP's vector reads, GSO, GRO and ECN options are not supported yet: each read takes one datagram, and `datagramVectorReadMessageCount` is accepted and ignored.
- `close(mode: .input)` works on pipe channels, not yet on sockets.
- Writing a `FileRegion` fails with `ChannelError.operationUnsupported`.
- Libraries that build `NIOPosix.ServerBootstrap` or `ClientBootstrap` themselves need a way to accept a different bootstrap, as they already do for NIOTransportServices. Hummingbird 2 and Vapor 4 each need a small patch for this; see [HUMMINGBIRD2.md](../docs/HUMMINGBIRD2.md) and [VAPOR.md](../docs/VAPOR.md), with working examples in `Examples/`.
- Linux and macOS. NIO's Windows support is partial, so Windows is not covered yet.

## Testing

```sh
cd VegaNIO
swift test
```

The suite covers event-loop ordering and serial execution, scheduled and repeated tasks, actors on a loop's executor, echo, connection refused, write-then-close, half-closure, writability and water marks, socket options, NIO's own HTTP/1 handlers, `NIOAsyncChannel` on both ends, and group shutdown; UDP echo, addressed and connected, `SO_REUSEADDR` and the async datagram bind; a Unix socket echo server and client, with socket-file cleanup; and pipe channels over pipe(2) and a socketpair, one way and both ways, closing input or output alone, and the refusal of regular files. It is clean under ThreadSanitizer.
