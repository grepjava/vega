import NIOConcurrencyHelpers
import NIOCore
import Synchronization
import class Vega.Runtime
import struct Vega.TCPStream
import struct Vega.IOBuffer
import struct Vega.SplitStream
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// A TCP connection as a NIO `Channel`, over a Vega `TCPStream`.
///
/// Handlers run on the channel's loop, as NIO promises. The socket is read
/// and written by two Vega tasks, a reader and a writer, which are not tied
/// to the loop and can be stolen by any worker: the reader reads when the
/// pipeline asks (`read()`, which `autoRead` does after each delivery) and
/// hands what it read to the loop; the writer sends what `flush()` hands it
/// and tells the loop when it is out. A delivery runs on the reader's own
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
    private var io: StreamIO?
    private var fd: Int32 = -1

    private let active = Atomic<Bool>(false)
    private let writable = Atomic<Bool>(true)
    private let addresses = NIOLockedValueBox<(local: SocketAddress?, remote: SocketAddress?)>((nil, nil))

    init(loop: VegaEventLoop, parent: Channel? = nil, accepted stream: consuming TCPStream? = nil) {
        self.loop = loop
        self.parent = parent
        closePromise = loop.makePromise()
        if let stream = stream.take() { accepted = StreamBox(stream) }
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
        let target: VegaAddress
        do {
            target = try VegaAddress(address)
        } catch {
            promise?.fail(error)
            return
        }
        connect(promise: promise) { () async throws(VegaIOError) in try await TCPStream.connect(to: target) }
    }

    /// Connect to `host`, resolving it and racing its addresses (Happy
    /// Eyeballs). On the loop.
    func connect0(host: String, port: Int, promise: EventLoopPromise<Void>?) {
        connect(promise: promise) { () async throws(VegaIOError) in try await TCPStream.connect(host: host, port: port) }
    }

    private func connect(promise: EventLoopPromise<Void>?,
                         _ open: @escaping @Sendable () async throws(VegaIOError) -> TCPStream) {
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
                let box = StreamBox(try await open())
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
        let stream = box.stream.take()!
        fd = stream.fileDescriptor
        for (option, value) in options.socket where fd >= 0 {
            try? setSocketOption(fd, option, value)
        }
        let local = try? stream.localAddress, remote = try? stream.peerAddress
        addresses.withLockedValue {
            $0 = (local.flatMap { try? SocketAddress($0) }, remote.flatMap { try? SocketAddress($0) })
        }
        lifecycle = .active
        active.store(true, ordering: .relaxed)
        io = StreamIO(stream.split(), channel: self)
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
        io.send(buffers)
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
            promise?.fail(ChannelError.operationUnsupported)
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

/// A stream on its way between tasks.
final class StreamBox: @unchecked Sendable {
    var stream: TCPStream?
    init(_ stream: consuming TCPStream) { self.stream = .some(stream) }
}

/// What a connection's loop and its reader and writer share.
final class StreamIO: Sendable {
    private struct Shared {
        var wantRead = false
        var reader: UnsafeContinuation<Bool, Never>?
        var writes: [ByteBuffer] = []
        var shutdownOutput = false
        var writer: UnsafeContinuation<Bool, Never>?
        var closed = false
    }

    private let shared = NIOLockedValueBox(Shared())
    private let readerTask = NIOLockedValueBox<Task<Void, Never>?>(nil)
    private let writerTask = NIOLockedValueBox<Task<Void, Never>?>(nil)

    init(_ halves: consuming SplitStream, channel: VegaSocketChannel) {
        let loop = channel.loop
        let reader = loop.runtime.spawn(with: halves.reader) { [self] half in
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
        let writer = loop.runtime.spawn(with: halves.writer) { [self] half in
            var parts = UnsafeMutableBufferPointer<UnsafeRawBufferPointer>.allocate(capacity: 16)
            defer { parts.deallocate() }
            while true {
                let (batch, shutdown) = await waitToWrite()
                if !batch.isEmpty {
                    if parts.count < batch.count {
                        parts.deallocate()
                        parts = .allocate(capacity: batch.count)
                    }
                    // The buffers' storage stays put while `batch` holds them.
                    for (i, b) in batch.enumerated() { parts[i] = b.withUnsafeReadableBytes { $0 } }
                    do throws(VegaIOError) {
                        try await half.write(vectored: UnsafeBufferPointer(rebasing: parts[..<batch.count]))
                    } catch {
                        await loop.run { channel.writeFailed(nioError(error)) }
                        return
                    }
                    let count = batch.count
                    await loop.run { channel.didWrite(count) }
                }
                if shutdown {
                    let failure: VegaIOError?
                    do throws(VegaIOError) {
                        try half.shutdownWrite()
                        failure = nil
                    } catch {
                        failure = error
                    }
                    await loop.run {
                        if let failure { channel.writeFailed(nioError(failure)) } else { channel.didShutdownOutput() }
                    }
                    return
                }
                if batch.isEmpty { return }
            }
        }
        readerTask.withLockedValue { $0 = reader }
        writerTask.withLockedValue { $0 = writer }
    }

    /// Wait for the loop to want a read: false once closed.
    private func waitToRead() async -> Bool {
        await withUnsafeContinuation { (c: UnsafeContinuation<Bool, Never>) in
            let now: Bool? = shared.withLockedValue { s in
                if s.closed { return false }
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

    /// Wait for flushed writes: an empty batch without `shutdown` once
    /// closed with nothing left to send.
    private func waitToWrite() async -> (batch: [ByteBuffer], shutdown: Bool) {
        _ = await withUnsafeContinuation { (c: UnsafeContinuation<Bool, Never>) in
            let now: Bool = shared.withLockedValue { s in
                if s.closed || s.shutdownOutput || !s.writes.isEmpty { return true }
                s.writer = c
                return false
            }
            if now { c.resume(returning: true) }
        }
        return shared.withLockedValue { s in
            let batch = s.writes
            s.writes.removeAll(keepingCapacity: true)
            let shutdown = s.shutdownOutput && !s.closed
            if shutdown { s.shutdownOutput = false }
            return (batch, shutdown)
        }
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

    func send(_ buffers: [ByteBuffer]) {
        let c = shared.withLockedValue { s -> UnsafeContinuation<Bool, Never>? in
            s.writes.append(contentsOf: buffers)
            defer { s.writer = nil }
            return s.writer
        }
        c?.resume(returning: true)
    }

    func shutdownOutput() {
        let c = shared.withLockedValue { s -> UnsafeContinuation<Bool, Never>? in
            s.shutdownOutput = true
            defer { s.writer = nil }
            return s.writer
        }
        c?.resume(returning: true)
    }

    /// Stop reading now; let the writer send what it has, for up to `linger`.
    func close(linger: Duration, runtime: Runtime) {
        let (r, w, pending) = shared.withLockedValue { s -> (UnsafeContinuation<Bool, Never>?, UnsafeContinuation<Bool, Never>?, Bool) in
            s.closed = true
            defer {
                s.reader = nil
                s.writer = nil
            }
            return (s.reader, s.writer, !s.writes.isEmpty)
        }
        r?.resume(returning: false)
        w?.resume(returning: true)
        readerTask.withLockedValue { $0?.cancel() }
        let writer = writerTask.withLockedValue { $0 }
        guard let writer else { return }
        // The writer is mid-write, or has more to write: give it a while.
        if w == nil || pending {
            runtime.spawn {
                try? await Runtime.sleep(for: linger)
                writer.cancel()
            }
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
