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
| `ServerBootstrap` | `VegaServerBootstrap`, including the async `bind(host:port:childChannelInitializer:)` that returns an `NIOAsyncChannel` |
| `ClientBootstrap` | `VegaClientBootstrap`, which is an `NIOClientTCPBootstrapProtocol`; `connect(host:port:)` races the host's addresses (Happy Eyeballs) |

## How it runs

- **A loop is a serial queue, not a thread.** Handlers on one loop run one at a time and in order, as NIO promises, and `inEventLoop`, `preconditionInEventLoop` and `assumeIsolated` hold while they run. Whichever Vega worker picks up a loop's work runs it, so a loop doesn't stay on one thread from one tick to the next. NIOTransportServices' loops on Dispatch behave the same way. A group can have more loops than the runtime has workers.
- **Swift tasks isolated to a loop** (an actor whose `unownedExecutor` is `eventLoop.executor`) run on the loop, inline.
- **Each connection has a reader task and a writer task.** These are ordinary Vega tasks that any worker can steal. The reader reads when the pipeline asks for a read (`autoRead` asks after every delivery) and hands the bytes to the loop. When nobody else is running the loop, the reader delivers on its own task, so a quiet connection costs no hop. The writer sends what `flush()` gives it and reports back when the bytes are out, which is when write promises complete and writability changes.
- **Closing a channel** stops reading at once and fails writes that were never flushed. Flushed writes still go out, so write-then-close works as it does on NIO, but only for up to 10 seconds if the peer isn't taking them.
- **Scheduled tasks** use Vega's timer wheel. Cancelling a task from its loop before it runs means it never runs.

## Not yet

- Only TCP so far. UDP (`DatagramBootstrap`), Unix domain sockets and `NIOPipeBootstrap` are still to come.
- Writing a `FileRegion` fails with `ChannelError.operationUnsupported`.
- Libraries that build `NIOPosix.ServerBootstrap` or `ClientBootstrap` themselves need a way to accept a different bootstrap, as they already do for NIOTransportServices.
- Linux and macOS. NIO's Windows support is partial, so Windows is not covered yet.

## Testing

```sh
cd VegaNIO
swift test
```

The suite covers event-loop ordering and serial execution, scheduled and repeated tasks, actors on a loop's executor, echo, connection refused, write-then-close, half-closure, writability and water marks, socket options, NIO's own HTTP/1 handlers, `NIOAsyncChannel` on both ends, and group shutdown. It is clean under ThreadSanitizer.
