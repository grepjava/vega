import NIOConcurrencyHelpers
import NIOCore
import Synchronization
import class Vega.Runtime
import struct Vega.TCPStream
import struct Vega.UnixStream
import struct Vega.IOBuffer
import struct Vega.SplitStream
import struct Vega.ReadHalf
import struct Vega.WriteHalf
import struct Vega.PipeReader
import struct Vega.PipeWriter
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// A TCP connection as a NIO `Channel`, over a Vega `TCPStream`; or a Unix
/// socket connection (`UnixStream`), or a pipe pair (`PipeReader` and
/// `PipeWriter`, for `VegaPipeBootstrap`), whose bytes move the same way.
///
/// Handlers run on the channel's loop, as NIO promises. The socket is read
/// and written by two Vega tasks, a reader and a writer, which are not tied
/// to the loop and can be stolen by any worker: the reader reads when the
/// pipeline asks (`read()`, which `autoRead` does after each delivery) and
/// hands what it read to the loop. `flush()` sends what the socket takes at
/// once, as NIO's does; the writer sends the rest when there is room and
/// tells the loop when it is out. A delivery runs on the reader's own
/// task when nobody is running the loop, so a quiet connection costs no
/// hop.
///
/// Closing stops the reader at once and fails writes that were never
/// flushed; flushed writes still go out (so write-then-close works as it
/// does in NIO) unless the peer doesn't take them within `closeLinger`.
final class VegaSocketChannel: Channel, ChannelCore, @unchecked Sendable {
    let loop: VegaEventLoop
    let parent: Channel?
    let allocator = ByteBufferAllocator()
    private var _pipeline: ChannelPipeline!
    private let closePromise: EventLoopPromise<Void>

    /// How long flushed writes may keep a closed connection's socket open.
    static let closeLinger: Duration = .seconds(10)

    // On the loop.
    private enum Lifecycle { case fresh, registered, connecting, active, closed }
    private var lifecycle = Lifecycle.fresh
    private var options = Options()
    private var inputClosed = false
    private var outputClosed = false
    /// Written, not yet flushed.
    private var unflushed = CircularBuffer<(ByteBuffer, EventLoopPromise<Void>?)>()
    /// Flushed, not yet written: the writer reports them done in order.
    private var inFlight = CircularBuffer<(Int, EventLoopPromise<Void>?)>()
    private var outputClosePromise: EventLoopPromise<Void>?
    private var queuedBytes = 0
    private var connectPromise: EventLoopPromise<Void>?
    private var connectTask: Task<Void, Never>?
    private var connectTimeout: Scheduled<Void>?
    /// The accepted stream, until the channel goes active.
    private var accepted: StreamBox?
    private var io: ChannelIO?
    /// The socket, for its options: -1 for a pipe.
    private var fd: Int32 = -1
    /// Over pipes, closing both directions closes the channel: there is
    /// nothing left to it.
    private var isPipe = false

    private let active = Atomic<Bool>(false)
    private let writable = Atomic<Bool>(true)
    private let addresses = NIOLockedValueBox<(local: SocketAddress?, remote: SocketAddress?)>((nil, nil))

    init(loop: VegaEventLoop, parent: Channel? = nil, accepted: StreamBox? = nil) {
        self.loop = loop
        self.parent = parent
        closePromise = loop.makePromise()
        self.accepted = accepted
        _pipeline = ChannelPipeline(channel: self)
    }

    // MARK: Channel

    var eventLoop: EventLoop { loop }
    var pipeline: ChannelPipeline { _pipeline }
    var closeFuture: EventLoopFuture<Void> { closePromise.futureResult }
    var _channelCore: ChannelCore { self }
    var isActive: Bool { active.load(ordering: .relaxed) }
    var isWritable: Bool { writable.load(ordering: .relaxed) }
    var localAddress: SocketAddress? { addresses.withLockedValue { $0.local } }
    var remoteAddress: SocketAddress? { addresses.withLockedValue { $0.remote } }
    var syncOptions: NIOSynchronousChannelOptions? { SyncOptions(channel: self) }

    func setOption<Option: ChannelOption>(_ option: Option, value: Option.Value) -> EventLoopFuture<Void> {
        if loop.inEventLoop { return loop.makeCompletedFuture { try setOption0(option, value: value) } }
        return loop.submit { try self.setOption0(option, value: value) }
    }

    func getOption<Option: ChannelOption>(_ option: Option) -> EventLoopFuture<Option.Value> {
        if loop.inEventLoop { return loop.makeCompletedFuture { try getOption0(option) } }
        return loop.submit { try self.getOption0(option) }
    }

    private struct SyncOptions: NIOSynchronousChannelOptions {
        let channel: VegaSocketChannel
        func setOption<Option: ChannelOption>(_ option: Option, value: Option.Value) throws {
            channel.loop.preconditionInEventLoop()
            try channel.setOption0(option, value: value)
        }
        func getOption<Option: ChannelOption>(_ option: Option) throws -> Option.Value {
            channel.loop.preconditionInEventLoop()
            return try channel.getOption0(option)
        }
    }

    private func setOption0<Option: ChannelOption>(_ option: Option, value: Option.Value) throws {
        guard lifecycle != .closed else { throw ChannelError.ioOnClosedChannel }
        switch option {
        case let option as ChannelOptions.Types.SocketOption:
            let value = value as! SocketOptionValue
            options.set(option, value)
            if fd >= 0 { try setSocketOption(fd, option, value) }
        case is ChannelOptions.Types.AutoReadOption:
            let on = value as! Bool
            let was = options.autoRead
            options.autoRead = on
            if on && !was { readIfNeeded() }
        case is ChannelOptions.Types.AllowRemoteHalfClosureOption:
            options.allowRemoteHalfClosure = value as! Bool
        case is ChannelOptions.Types.WriteBufferWaterMarkOption:
            options.waterMark = value as! ChannelOptions.Types.WriteBufferWaterMark
            updateWritability()
        case is ChannelOptions.Types.ConnectTimeoutOption:
            options.connectTimeout = value as! TimeAmount?
        case is ChannelOptions.Types.RecvAllocatorOption:
            options.recvAllocator = value as! RecvByteBufferAllocator
        case is ChannelOptions.Types.MaxMessagesPerReadOption, is ChannelOptions.Types.WriteSpinOption,
             is ChannelOptions.Types.AllocatorOption:
            break
        default:
            throw ChannelError.operationUnsupported
        }
    }

    private func getOption0<Option: ChannelOption>(_ option: Option) throws -> Option.Value {
        guard lifecycle != .closed else { throw ChannelError.ioOnClosedChannel }
        switch option {
        case let option as ChannelOptions.Types.SocketOption:
            if fd >= 0 { return try getSocketOption(fd, option) as! Option.Value }
            return (options.value(option) ?? 0) as! Option.Value
        case is ChannelOptions.Types.AutoReadOption: return options.autoRead as! Option.Value
        case is ChannelOptions.Types.AllowRemoteHalfClosureOption: return options.allowRemoteHalfClosure as! Option.Value
        case is ChannelOptions.Types.WriteBufferWaterMarkOption: return options.waterMark as! Option.Value
        case is ChannelOptions.Types.ConnectTimeoutOption: return options.connectTimeout as! Option.Value
        case is ChannelOptions.Types.RecvAllocatorOption: return options.recvAllocator as! Option.Value
        case is ChannelOptions.Types.MaxMessagesPerReadOption: return UInt(1) as! Option.Value
        case is ChannelOptions.Types.WriteSpinOption: return UInt(0) as! Option.Value
        case is ChannelOptions.Types.AllocatorOption: return allocator as! Option.Value
        case is ChannelOptions.Types.BufferedWritableBytesOption: return queuedBytes as! Option.Value
        default: throw ChannelError.operationUnsupported
        }
    }

    // MARK: ChannelCore

    func localAddress0() throws -> SocketAddress {
        guard let address = localAddress else { throw ChannelError.ioOnClosedChannel }
        return address
    }

    func remoteAddress0() throws -> SocketAddress {
        guard let address = remoteAddress else { throw ChannelError.ioOnClosedChannel }
        return address
    }

    func register0(promise: EventLoopPromise<Void>?) {
        guard lifecycle == .fresh else {
            promise?.fail(lifecycle == .closed ? ChannelError.ioOnClosedChannel : ChannelError.inappropriateOperationForState)
            return
        }
        do {
            try loop.register(self)
        } catch {
            promise?.fail(error)
            close0(error: error, mode: .all, promise: nil)
            return
        }
        lifecycle = .registered
        pipeline.fireChannelRegistered()
        promise?.succeed(())
    }

    /// An accepted connection: registered and active at once.
    func registerAlreadyConfigured0(promise: EventLoopPromise<Void>?) {
        register0(promise: nil)
        guard lifecycle == .registered, let box = accepted else {
            promise?.fail(ChannelError.inappropriateOperationForState)
            return
        }
        accepted = nil
        becomeActive(box, promise: promise)
    }

    func bind0(to address: SocketAddress, promise: EventLoopPromise<Void>?) {
        promise?.fail(ChannelError.operationUnsupported)
    }

    func connect0(to address: SocketAddress, promise: EventLoopPromise<Void>?) {
        if let path = address.pathname {
            connect(promise: promise) { () async throws(VegaIOError) in
                StreamBox(try await UnixStream.connect(path: path), local: nil, remote: address)
            }
            return
        }
        let target: VegaAddress
        do {
            target = try VegaAddress(address)
        } catch {
            promise?.fail(error)
            return
        }
        connect(promise: promise) { () async throws(VegaIOError) in StreamBox(try await TCPStream.connect(to: target)) }
    }

    /// Connect to `host`, resolving it and racing its addresses (Happy
    /// Eyeballs). On the loop.
    func connect0(host: String, port: Int, promise: EventLoopPromise<Void>?) {
        connect(promise: promise) { () async throws(VegaIOError) in
            StreamBox(try await TCPStream.connect(host: host, port: port))
        }
    }

    private func connect(promise: EventLoopPromise<Void>?,
                         _ open: @escaping @Sendable () async throws(VegaIOError) -> StreamBox) {
        guard lifecycle == .registered else {
            promise?.fail(lifecycle == .closed ? ChannelError.ioOnClosedChannel : ChannelError.inappropriateOperationForState)
            return
        }
        lifecycle = .connecting
        connectPromise = promise
        if let timeout = options.connectTimeout {
            connectTimeout = loop.scheduleTask(in: timeout) { [self] in
                guard lifecycle == .connecting else { return }
                close0(error: ChannelError.connectTimeout(timeout), mode: .all, promise: nil)
            }
        }
        connectTask = loop.runtime.spawn { [self, loop] in
            do throws(VegaIOError) {
                let box = try await open()
                await loop.run { self.connected(box) }
            } catch {
                await loop.run { self.connectFailed(nioError(error)) }
            }
        }
    }

    private func connected(_ box: StreamBox) {
        connectTimeout?.cancel()
        connectTask = nil
        guard lifecycle == .connecting else { return }
        let promise = connectPromise
        connectPromise = nil
        becomeActive(box, promise: promise)
    }

    private func connectFailed(_ error: Error) {
        connectTask = nil
        guard lifecycle == .connecting else { return }
        close0(error: error, mode: .all, promise: nil)
    }

    private func becomeActive(_ box: StreamBox, promise: EventLoopPromise<Void>?) {
        let halves = box.halves.take()!
        fd = box.fd
        // An option the socket lacks is skipped: TCP_NODELAY, which the
        // bootstraps set, on a Unix socket.
        for (option, value) in options.socket where fd >= 0 {
            try? setSocketOption(fd, option, value)
        }
        addresses.withLockedValue { $0 = (box.local, box.remote) }
        lifecycle = .active
        active.store(true, ordering: .relaxed)
        io = .socket(StreamIO(reader: halves.reader, writer: halves.writer, channel: self))
        promise?.succeed(())
        pipeline.fireChannelActive()
        readIfNeeded()
    }

    /// Go active over a pipe's descriptors, which the channel now owns. One
    /// may be missing, for a channel that only reads or only writes. On the
    /// loop, once registered.
    func activatePipe(input: Int32?, output: Int32?, promise: EventLoopPromise<Void>?) {
        guard lifecycle == .registered else {
            if let input { closeDescriptor(input) }
            if let output { closeDescriptor(output) }
            promise?.fail(lifecycle == .closed ? ChannelError.ioOnClosedChannel : ChannelError.inappropriateOperationForState)
            return
        }
        var reader: PipeReader?
        var writer: PipeWriter?
        do throws(VegaIOError) {
            // Each closes its descriptor if it fails.
            if let input {
                do throws(VegaIOError) {
                    reader = try PipeReader(adopting: input)
                } catch {
                    if let output { closeDescriptor(output) }
                    throw error
                }
            }
            if let output { writer = try PipeWriter(adopting: output) }
        } catch {
            promise?.fail(nioError(error))
            close0(error: nioError(error), mode: .all, promise: nil)
            return
        }
        isPipe = true
        inputClosed = input == nil
        outputClosed = output == nil
        lifecycle = .active
        active.store(true, ordering: .relaxed)
        io = .pipe(StreamIO(reader: reader.take(), writer: writer.take(), channel: self))
        promise?.succeed(())
        pipeline.fireChannelActive()
        readIfNeeded()
    }

    func write0(_ data: NIOAny, promise: EventLoopPromise<Void>?) {
        guard lifecycle == .active, !outputClosed else {
            promise?.fail(outputClosed ? ChannelError.outputClosed : ChannelError.ioOnClosedChannel)
            return
        }
        let buffer: ByteBuffer
        switch unwrapData(data, as: IOData.self) {
        case .byteBuffer(let b): buffer = b
        case .fileRegion:
            promise?.fail(ChannelError.operationUnsupported)
            return
        }
        unflushed.append((buffer, promise))
        queuedBytes += buffer.readableBytes
        updateWritability()
    }

    func flush0() {
        guard lifecycle == .active, let io, !unflushed.isEmpty else { return }
        var buffers: [ByteBuffer] = []
        buffers.reserveCapacity(unflushed.count)
        while let (buffer, promise) = unflushed.popFirst() {
            inFlight.append((buffer.readableBytes, promise))
            buffers.append(buffer)
        }
        // What the socket took at once is done now, as on NIO.
        let sent = io.send(buffers)
        if sent > 0 { didWrite(sent) }
    }

    func read0() {
        guard lifecycle == .active, !inputClosed, let io else { return }
        io.wantRead()
    }

    func close0(error: Error, mode: CloseMode, promise: EventLoopPromise<Void>?) {
        switch mode {
        case .all:
            closeAll(error: error, promise: promise)
        case .output:
            guard lifecycle == .active, let io else {
                promise?.fail(ChannelError.ioOnClosedChannel)
                return
            }
            guard !outputClosed else {
                promise?.fail(ChannelError.outputClosed)
                return
            }
            outputClosed = true
            failUnflushed(ChannelError.outputClosed)
            outputClosePromise = promise
            io.shutdownOutput()
        case .input:
            // A pipe's read end can go on its own; a socket's can't (yet).
            guard isPipe else {
                promise?.fail(ChannelError.operationUnsupported)
                return
            }
            guard lifecycle == .active, let io else {
                promise?.fail(ChannelError.ioOnClosedChannel)
                return
            }
            guard !inputClosed else {
                promise?.fail(ChannelError.inputClosed)
                return
            }
            inputClosed = true
            io.shutdownInput()
            promise?.succeed(())
            pipeline.fireUserInboundEventTriggered(ChannelEvent.inputClosed)
            closeIfPipeDone()
        }
    }

    /// A pipe channel with neither direction left closes.
    private func closeIfPipeDone() {
        if isPipe && inputClosed && outputClosed && lifecycle == .active {
            close0(error: ChannelError.eof, mode: .all, promise: nil)
        }
    }

    private func closeAll(error: Error, promise: EventLoopPromise<Void>?) {
        guard lifecycle != .closed else {
            promise?.fail(ChannelError.alreadyClosed)
            return
        }
        let was = lifecycle
        lifecycle = .closed
        active.store(false, ordering: .relaxed)
        connectTimeout?.cancel()
        connectTask?.cancel()
        connectTask = nil
        accepted = nil
        failUnflushed(error)
        if let p = outputClosePromise {
            outputClosePromise = nil
            p.fail(error)
        }
        if let connectPromise {
            self.connectPromise = nil
            connectPromise.fail(error)
        }
        io?.close(linger: Self.closeLinger, runtime: loop.runtime)
        if was == .active {
            pipeline.fireChannelInactive()
        }
        if was != .fresh {
            loop.deregister(self)
            pipeline.fireChannelUnregistered()
        }
        promise?.succeed(())
        // Keep the pipeline for one more tick: work may already be using it.
        loop.execute { [self] in
            removeHandlers(pipeline: pipeline)
            closePromise.succeed(())
        }
    }

    private func failUnflushed(_ error: Error) {
        while let (buffer, promise) = unflushed.popFirst() {
            queuedBytes -= buffer.readableBytes
            promise?.fail(error)
        }
        updateWritability()
    }

    func triggerUserOutboundEvent0(_ event: Any, promise: EventLoopPromise<Void>?) {
        promise?.fail(ChannelError.operationUnsupported)
    }

    func channelRead0(_ data: NIOAny) {}

    func errorCaught0(error: Error) {}

    // MARK: From the I/O tasks (on the loop)

    func readIfNeeded() {
        if options.autoRead && lifecycle == .active && !inputClosed { pipeline.read() }
    }

    /// The reader got `buffer`, or end of stream (nil).
    func didRead(_ buffer: ByteBuffer?) {
        guard lifecycle == .active, !inputClosed else { return }
        guard let buffer else {
            if options.allowRemoteHalfClosure {
                inputClosed = true
                pipeline.fireUserInboundEventTriggered(ChannelEvent.inputClosed)
                closeIfPipeDone()
            } else {
                close0(error: ChannelError.eof, mode: .all, promise: nil)
            }
            return
        }
        pipeline.fireChannelRead(buffer)
        pipeline.fireChannelReadComplete()
        readIfNeeded()
    }

    func readFailed(_ error: Error) {
        guard lifecycle == .active else { return }
        pipeline.fireErrorCaught(error)
        close0(error: error, mode: .all, promise: nil)
    }

    /// The writer sent the first `count` buffers it was handed.
    func didWrite(_ count: Int) {
        for _ in 0..<count {
            guard let (bytes, promise) = inFlight.popFirst() else { break }
            queuedBytes -= bytes
            promise?.succeed(())
        }
        updateWritability()
    }

    /// The writer failed: everything it was handed fails.
    func writeFailed(_ error: Error) {
        while let (bytes, promise) = inFlight.popFirst() {
            queuedBytes -= bytes
            promise?.fail(error)
        }
        if let p = outputClosePromise {
            outputClosePromise = nil
            p.fail(error)
        }
        guard lifecycle == .active else { return }
        pipeline.fireErrorCaught(error)
        close0(error: error, mode: .all, promise: nil)
    }

    /// The writer shut down the sending side.
    func didShutdownOutput() {
        outputClosePromise?.succeed(())
        outputClosePromise = nil
        guard lifecycle == .active else { return }
        pipeline.fireUserInboundEventTriggered(ChannelEvent.outputClosed)
        closeIfPipeDone()
    }

    private func updateWritability() {
        let was = writable.load(ordering: .relaxed)
        let now = was ? queuedBytes < options.waterMark.high : queuedBytes < options.waterMark.low
        guard now != was else { return }
        writable.store(now, ordering: .relaxed)
        if lifecycle == .active { pipeline.fireChannelWritabilityChanged() }
    }
}

/// A channel's settings that aren't the socket's own.
struct Options {
    var socket: [(ChannelOptions.Types.SocketOption, SocketOptionValue)] = []

    mutating func set(_ option: ChannelOptions.Types.SocketOption, _ value: SocketOptionValue) {
        if let i = socket.firstIndex(where: { $0.0 == option }) { socket[i].1 = value } else { socket.append((option, value)) }
    }

    func value(_ option: ChannelOptions.Types.SocketOption) -> SocketOptionValue? {
        socket.first { $0.0 == option }?.1
    }
    var autoRead = true
    var allowRemoteHalfClosure = false
    var waterMark = ChannelOptions.Types.WriteBufferWaterMark(low: 32 * 1024, high: 64 * 1024)
    var connectTimeout: TimeAmount? = .seconds(10)
    var recvAllocator: RecvByteBufferAllocator = AdaptiveRecvByteBufferAllocator()
    var backlog: Int32 = 256
}

/// A connected stream on its way to its channel, split into halves, with
/// what the channel needs to know about it.
final class StreamBox: @unchecked Sendable {
    var halves: SplitStream?
    /// The socket, for options: -1 without one (Network.framework).
    let fd: Int32
    let local: SocketAddress?
    let remote: SocketAddress?

    init(_ stream: consuming TCPStream) {
        fd = stream.fileDescriptor
        local = (try? stream.localAddress).flatMap { try? SocketAddress($0) }
        remote = (try? stream.peerAddress).flatMap { try? SocketAddress($0) }
        halves = .some(stream.split())
    }

    /// A Unix connection. Its ends have no address but the path the
    /// listener is bound to: `local` on the accepting side, `remote` on the
    /// connecting one.
    init(_ stream: consuming UnixStream, local: SocketAddress?, remote: SocketAddress?) {
        fd = stream.fileDescriptor
        self.local = local
        self.remote = remote
        halves = .some(stream.split())
    }
}

/// What a stream channel reads: a socket's read half, or a pipe.
protocol ByteSource: ~Copyable, Sendable {
    func read(into buffer: inout IOBuffer) async throws(VegaIOError) -> Int
}

/// What a stream channel writes: a socket's write half, or a pipe.
protocol ByteSink: ~Copyable, Sendable {
    func write(vectored parts: UnsafeBufferPointer<UnsafeRawBufferPointer>) async throws(VegaIOError)
    /// Send what goes at once, without waiting: the bytes sent.
    func tryWrite(vectored parts: UnsafeBufferPointer<UnsafeRawBufferPointer>) throws(VegaIOError) -> Int
    func shutdownWrite() throws(VegaIOError)
}

extension ReadHalf: ByteSource {}
extension WriteHalf: ByteSink {}
extension PipeReader: ByteSource {}

extension PipeWriter: ByteSink {
    func write(vectored parts: UnsafeBufferPointer<UnsafeRawBufferPointer>) async throws(VegaIOError) {
        for part in parts { try await write(part) }
    }

    /// A PipeWriter has no write that never waits, so the writer task
    /// sends all of a pipe channel's output.
    func tryWrite(vectored parts: UnsafeBufferPointer<UnsafeRawBufferPointer>) throws(VegaIOError) -> Int { 0 }

    /// Dropping the writer, which follows, closes the pipe: that is how its
    /// sending side shuts down.
    func shutdownWrite() throws(VegaIOError) {}
}

/// How a stream channel's bytes move. An enum rather than an existential,
/// so the calls on the hot path are direct.
enum ChannelIO {
    case socket(StreamIO<ReadHalf, WriteHalf>)
    case pipe(StreamIO<PipeReader, PipeWriter>)

    func wantRead() {
        switch self {
        case .socket(let io): io.wantRead()
        case .pipe(let io): io.wantRead()
        }
    }

    func send(_ buffers: [ByteBuffer]) -> Int {
        switch self {
        case .socket(let io): io.send(buffers)
        case .pipe(let io): io.send(buffers)
        }
    }

    func shutdownOutput() {
        switch self {
        case .socket(let io): io.shutdownOutput()
        case .pipe(let io): io.shutdownOutput()
        }
    }

    func shutdownInput() {
        switch self {
        case .socket(let io): io.shutdownInput()
        case .pipe(let io): io.shutdownInput()
        }
    }

    func close(linger: Duration, runtime: Runtime) {
        switch self {
        case .socket(let io): io.close(linger: linger, runtime: runtime)
        case .pipe(let io): io.close(linger: linger, runtime: runtime)
        }
    }
}

/// The write half, shared by the loop (sending at flush) and the writer
/// task: whoever set `writing` uses it, one at a time.
final class WriterBox<Sink: ByteSink & ~Copyable>: @unchecked Sendable {
    var half: Sink?
    init(_ half: consuming Sink?) { self.half = half }
}

/// What a connection's loop and its reader and writer share. A pipe
/// channel that only reads has no writer task, and one that only writes
/// no reader.
final class StreamIO<Source: ByteSource & ~Copyable, Sink: ByteSink & ~Copyable>: Sendable {
    private struct Shared {
        var wantRead = false
        var reader: UnsafeContinuation<Bool, Never>?
        /// Flushed and not sent, for the writer.
        var writes: [ByteBuffer] = []
        /// The write half is in use: by the writer, or by a flush.
        var writing = false
        var shutdownOutput = false
        var writer: UnsafeContinuation<Void, Never>?
        var closed = false
        /// The input alone is closed (a pipe's): the reader stops.
        var inputShut = false

        /// The writer has something to do and the half is free.
        var writerReady: Bool { !writing && (closed || shutdownOutput || !writes.isEmpty) }

        mutating func takeWriter() -> UnsafeContinuation<Void, Never>? {
            defer { writer = nil }
            return writer
        }
    }

    private let shared = NIOLockedValueBox(Shared())
    private let readerTask = NIOLockedValueBox<Task<Void, Never>?>(nil)
    private let writerTask = NIOLockedValueBox<Task<Void, Never>?>(nil)
    private let out: WriterBox<Sink>
    private let loop: VegaEventLoop
    /// The channel owns this; a back reference that costs no count.
    private unowned(unsafe) let channel: VegaSocketChannel

    init(reader input: consuming Source?, writer output: consuming Sink?, channel: VegaSocketChannel) {
        loop = channel.loop
        self.channel = channel
        let hasOutput = output != nil
        out = WriterBox(output)
        if let input = input.take() { startReader(input, channel: channel) }
        if hasOutput { startWriter(channel: channel) }
    }

    private func startReader(_ input: consuming Source, channel: VegaSocketChannel) {
        let loop = self.loop
        let reader = loop.runtime.spawn(with: input) { [self] half in
            var buffer = IOBuffer(capacity: 64 * 1024)
            while await waitToRead() {
                buffer.clear()
                let n: Int
                do throws(VegaIOError) {
                    n = try await half.read(into: &buffer)
                } catch {
                    if error == .cancelled { return }
                    await loop.run { channel.readFailed(nioError(error)) }
                    return
                }
                guard n > 0 else {
                    await loop.run { channel.didRead(nil) }
                    return
                }
                var bytes = channel.allocator.buffer(capacity: n)
                buffer.withUnsafeBytes { _ = bytes.writeBytes($0) }
                await loop.run { [bytes] in channel.didRead(bytes) }
            }
        }
        readerTask.withLockedValue { $0 = reader }
    }

    private func startWriter(channel: VegaSocketChannel) {
        let loop = self.loop, out = self.out
        let writer = loop.runtime.spawn { [self] in
            var parts = UnsafeMutableBufferPointer<UnsafeRawBufferPointer>.allocate(capacity: 16)
            defer { parts.deallocate() }
            while true {
                // The half is ours (`writing`) from here until doneWriting.
                let (batch, shutdown) = await waitToWrite()
                if !batch.isEmpty {
                    if parts.count < batch.count {
                        parts.deallocate()
                        parts = .allocate(capacity: batch.count)
                    }
                    // The buffers' storage stays put while `batch` holds them.
                    for (i, b) in batch.enumerated() { parts[i] = b.withUnsafeReadableBytes { $0 } }
                    do throws(VegaIOError) {
                        try await out.half?.write(vectored: UnsafeBufferPointer(rebasing: parts[..<batch.count]))
                    } catch {
                        out.half = nil
                        await loop.run { channel.writeFailed(nioError(error)) }
                        return
                    }
                    let count = batch.count
                    await loop.run { channel.didWrite(count) }
                }
                if shutdown {
                    let failure: VegaIOError?
                    do throws(VegaIOError) {
                        try out.half?.shutdownWrite()
                        failure = nil
                    } catch {
                        failure = error
                    }
                    out.half = nil
                    await loop.run {
                        if let failure { channel.writeFailed(nioError(failure)) } else { channel.didShutdownOutput() }
                    }
                    return
                }
                if batch.isEmpty {
                    // Closed with nothing left: drop the half (the socket
                    // closes once the reader's goes too).
                    out.half = nil
                    return
                }
                doneWriting()
            }
        }
        writerTask.withLockedValue { $0 = writer }
    }

    /// Wait for the loop to want a read: false once closed.
    // Not inlined: Swift 6.3.3's optimizer miscompiles a continuation stored
    // under a pthread lock (NIOLock) once this is inlined into a loop whose
    // body also awaits; resuming it then jumps to address 0 (release only).
    @inline(never)
    private func waitToRead() async -> Bool {
        await withUnsafeContinuation { (c: UnsafeContinuation<Bool, Never>) in
            let now: Bool? = shared.withLockedValue { s in
                if s.closed || s.inputShut { return false }
                if s.wantRead {
                    s.wantRead = false
                    return true
                }
                s.reader = c
                return nil
            }
            if let now { c.resume(returning: now) }
        }
    }

    /// Wait for writes to send, and take the half: an empty batch without
    /// `shutdown` once closed with nothing left to send.
    private func waitToWrite() async -> (batch: [ByteBuffer], shutdown: Bool) {
        while true {
            let taken = shared.withLockedValue { s -> (batch: [ByteBuffer], shutdown: Bool)? in
                guard s.writerReady else { return nil }
                s.writing = true
                let batch = s.writes
                s.writes.removeAll(keepingCapacity: true)
                let shutdown = s.shutdownOutput && !s.closed
                if shutdown { s.shutdownOutput = false }
                return (batch, shutdown)
            }
            if let taken { return taken }
            await parkWriter()
        }
    }

    // Not inlined: see waitToRead.
    @inline(never)
    private func parkWriter() async {
        await withUnsafeContinuation { (c: UnsafeContinuation<Void, Never>) in
            let ready = shared.withLockedValue { s -> Bool in
                if s.writerReady { return true }
                s.writer = c
                return false
            }
            if ready { c.resume() }
        }
    }

    private func doneWriting() {
        shared.withLockedValue { $0.writing = false }
    }

    func wantRead() {
        let c = shared.withLockedValue { s -> UnsafeContinuation<Bool, Never>? in
            if let r = s.reader {
                s.reader = nil
                return r
            }
            s.wantRead = true
            return nil
        }
        c?.resume(returning: true)
    }

    /// Send `buffers`, on the loop: what the socket takes now goes at once,
    /// the rest to the writer. Returns how many of them went whole.
    func send(_ buffers: [ByteBuffer]) -> Int {
        let mine = shared.withLockedValue { s -> Bool in
            guard !s.writing, s.writes.isEmpty, !s.closed, !s.shutdownOutput else { return false }
            s.writing = true
            return true
        }
        guard mine else {
            shared.withLockedValue { s in
                s.writes.append(contentsOf: buffers)
                return s.takeWriter()
            }?.resume()
            return 0
        }
        let sent: Int
        do throws(VegaIOError) {
            sent = try withUnsafeTemporaryAllocation(of: UnsafeRawBufferPointer.self, capacity: buffers.count) {
                parts throws(VegaIOError) -> Int in
                for (i, b) in buffers.enumerated() { parts[i] = b.withUnsafeReadableBytes { $0 } }
                return try out.half?.tryWrite(vectored: UnsafeBufferPointer(parts)) ?? 0
            }
        } catch {
            doneWriting()
            let channel = self.channel
            loop.execute { channel.writeFailed(nioError(error)) }
            return 0
        }
        var whole = 0, left = sent
        while whole < buffers.count && left >= buffers[whole].readableBytes {
            left -= buffers[whole].readableBytes
            whole += 1
        }
        var rest: [ByteBuffer] = []
        if whole < buffers.count {
            var first = buffers[whole]
            first.moveReaderIndex(forwardBy: left)
            rest.reserveCapacity(buffers.count - whole)
            rest.append(first)
            rest.append(contentsOf: buffers[(whole + 1)...])
        }
        shared.withLockedValue { s -> UnsafeContinuation<Void, Never>? in
            s.writing = false
            guard !rest.isEmpty else { return nil }
            s.writes.insert(contentsOf: rest, at: 0)
            return s.takeWriter()
        }?.resume()
        return whole
    }

    func shutdownOutput() {
        shared.withLockedValue { s in
            s.shutdownOutput = true
            return s.takeWriter()
        }?.resume()
    }

    /// Stop reading for good: the reader task ends, and drops a pipe's read
    /// end as it goes.
    func shutdownInput() {
        let r = shared.withLockedValue { s -> UnsafeContinuation<Bool, Never>? in
            s.inputShut = true
            defer { s.reader = nil }
            return s.reader
        }
        r?.resume(returning: false)
        readerTask.withLockedValue { $0?.cancel() }
    }

    /// Stop reading now; let the writer send what it has, for up to `linger`.
    func close(linger: Duration, runtime: Runtime) {
        let (r, w, pending) = shared.withLockedValue {
            s -> (UnsafeContinuation<Bool, Never>?, UnsafeContinuation<Void, Never>?, Bool) in
            s.closed = true
            defer { s.reader = nil }
            return (s.reader, s.takeWriter(), s.writing || !s.writes.isEmpty)
        }
        r?.resume(returning: false)
        w?.resume()
        readerTask.withLockedValue { $0?.cancel() }
        let writer = writerTask.withLockedValue { $0 }
        guard let writer, pending else { return }
        // The writer is mid-write, or has more to write: give it a while.
        runtime.spawn {
            try? await Runtime.sleep(for: linger)
            writer.cancel()
        }
    }
}

func setSocketOption(_ fd: Int32, _ option: ChannelOptions.Types.SocketOption, _ value: SocketOptionValue) throws {
    var v = value
    guard setsockopt(fd, option.optionLevel.rawValue, option.optionName.rawValue, &v, socklen_t(MemoryLayout<SocketOptionValue>.size)) == 0 else {
        throw NIOCore.IOError(errnoCode: errno, reason: "setsockopt")
    }
}

func getSocketOption(_ fd: Int32, _ option: ChannelOptions.Types.SocketOption) throws -> SocketOptionValue {
    var v: SocketOptionValue = 0
    var size = socklen_t(MemoryLayout<SocketOptionValue>.size)
    guard getsockopt(fd, option.optionLevel.rawValue, option.optionName.rawValue, &v, &size) == 0 else {
        throw NIOCore.IOError(errnoCode: errno, reason: "getsockopt")
    }
    return v
}

/// A Vega I/O error as NIO reports one: system errors as NIO's `IOError`.
func nioError(_ error: VegaIOError) -> Error {
    error.code > 0 ? NIOCore.IOError(errnoCode: error.code, reason: error.description) : error
}

/// Close a descriptor we own that never made it into a Vega type.
func closeDescriptor(_ descriptor: Int32) {
    _ = close(descriptor)
}

extension VegaAddress {
    init(_ address: NIOCore.SocketAddress) throws {
        guard let ip = address.ipAddress, let port = address.port,
              let converted = VegaAddress(numericHost: ip, port: port) else {
            throw ChannelError.operationUnsupported
        }
        self = converted
    }
}

extension NIOCore.SocketAddress {
    init(_ address: VegaAddress) throws {
        let host = address.host
        // Keep the text form as the host, as NIOPosix's addresses do.
        switch try NIOCore.SocketAddress(ipAddress: host, port: address.port ?? 0) {
        case .v4(let a): self.init(a.address, host: host)
        case .v6(let a): self.init(a.address, host: host)
        case let other: self = other
        }
    }
}
