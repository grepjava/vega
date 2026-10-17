#if !os(Windows)
import NIOConcurrencyHelpers
import NIOCore
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// NIO's `NIOPipeBootstrap`, for a `VegaEventLoopGroup`: a channel of
/// `ByteBuffer`s over descriptors you already have, such as a child
/// process's pipes, a terminal, or stdin and stdout.
///
/// ```swift
/// let channel = try await VegaPipeBootstrap(group: group)
///     .channelInitializer { channel in channel.pipeline.addHandler(LineHandler()) }
///     .takingOwnershipOfDescriptors(input: STDIN_FILENO, output: STDOUT_FILENO).get()
/// ```
///
/// The channel owns the descriptors from then on and closes them when it
/// closes. Regular files, directories, symbolic links and block devices are
/// refused (`ChannelError.operationUnsupported`), as on NIO, since they
/// can't be waited on; the descriptors then stay yours.
///
/// End of input closes the channel unless `allowRemoteHalfClosure` is set,
/// when it is a `ChannelEvent.inputClosed`. `close(mode: .output)` closes
/// the output descriptor once what was flushed has gone, and
/// `close(mode: .input)` the input one; with neither left, the channel
/// closes. POSIX only.
public final class VegaPipeBootstrap {
    private let group: VegaEventLoopGroup
    private var channelInit: (@Sendable (Channel) -> EventLoopFuture<Void>)?
    private var channelOptions = ChannelOptions.Storage()

    public init(group: VegaEventLoopGroup) {
        self.group = group
    }

    /// nil unless `group` is a `VegaEventLoopGroup`.
    public convenience init?(validatingGroup group: EventLoopGroup) {
        guard let group = group as? VegaEventLoopGroup else { return nil }
        self.init(group: group)
    }

    /// Set up the channel's pipeline, before it goes active.
    public func channelInitializer(_ handler: @escaping @Sendable (Channel) -> EventLoopFuture<Void>) -> Self {
        channelInit = handler
        return self
    }

    public func channelOption<Option: ChannelOption>(_ option: Option, value: Option.Value) -> Self {
        channelOptions.append(key: option, value: value)
        return self
    }

    /// Read and write one descriptor (a socket, say, or a terminal): it is
    /// duplicated so that each direction has its own.
    public func takingOwnershipOfDescriptor(inputOutput: CInt) -> EventLoopFuture<Channel> {
        takeInputOutput(inputOutput) { input, output in
            self.take(input: input, output: output, channelInitializer: Self.justChannel)
        }
    }

    /// Read `input`, write `output`. They must differ.
    public func takingOwnershipOfDescriptors(input: CInt, output: CInt) -> EventLoopFuture<Channel> {
        take(input: input, output: output, channelInitializer: Self.justChannel)
    }

    /// A channel that only reads: writes fail with `ChannelError.outputClosed`.
    public func takingOwnershipOfDescriptor(input: CInt) -> EventLoopFuture<Channel> {
        take(input: input, output: nil, channelInitializer: Self.justChannel)
    }

    /// A channel that only writes: it never reads.
    public func takingOwnershipOfDescriptor(output: CInt) -> EventLoopFuture<Channel> {
        take(input: nil, output: output, channelInitializer: Self.justChannel)
    }

    @available(*, deprecated, renamed: "takingOwnershipOfDescriptors(input:output:)")
    public func withPipes(inputDescriptor: CInt, outputDescriptor: CInt) -> EventLoopFuture<Channel> {
        takingOwnershipOfDescriptors(input: inputDescriptor, output: outputDescriptor)
    }

    @available(*, deprecated, renamed: "takingOwnershipOfDescriptor(inputOutput:)")
    public func withInputOutputDescriptor(_ fileDescriptor: CInt) -> EventLoopFuture<Channel> {
        takingOwnershipOfDescriptor(inputOutput: fileDescriptor)
    }

    // The async forms: the channel is wrapped as `channelInitializer` says
    // (in an `NIOAsyncChannel`, say) before it goes active, so no input
    // comes in ahead of it.

    public func takingOwnershipOfDescriptor<Output: Sendable>(
        inputOutput: CInt,
        channelInitializer: @escaping @Sendable (Channel) -> EventLoopFuture<Output>
    ) async throws -> Output {
        try await takeInputOutput(inputOutput) { input, output in
            self.take(input: input, output: output, channelInitializer: channelInitializer)
        }.get()
    }

    public func takingOwnershipOfDescriptors<Output: Sendable>(
        input: CInt,
        output: CInt,
        channelInitializer: @escaping @Sendable (Channel) -> EventLoopFuture<Output>
    ) async throws -> Output {
        try await take(input: input, output: output, channelInitializer: channelInitializer).get()
    }

    public func takingOwnershipOfDescriptor<Output: Sendable>(
        input: CInt,
        channelInitializer: @escaping @Sendable (Channel) -> EventLoopFuture<Output>
    ) async throws -> Output {
        try await take(input: input, output: nil, channelInitializer: channelInitializer).get()
    }

    public func takingOwnershipOfDescriptor<Output: Sendable>(
        output: CInt,
        channelInitializer: @escaping @Sendable (Channel) -> EventLoopFuture<Output>
    ) async throws -> Output {
        try await take(input: nil, output: output, channelInitializer: channelInitializer).get()
    }

    private static let justChannel: @Sendable (Channel) -> EventLoopFuture<Channel> = { channel in
        channel.eventLoop.makeSucceededFuture(channel)
    }

    /// Check `descriptor`, then hand it and a duplicate to `take`. A refused
    /// descriptor stays the caller's; the duplicate is ours either way.
    private func takeInputOutput<Output>(
        _ descriptor: CInt,
        _ take: (CInt, CInt) -> EventLoopFuture<Output>
    ) -> EventLoopFuture<Output> {
        do {
            try refuseFiles(descriptor)
        } catch {
            return group.next().makeFailedFuture(error)
        }
        let output = dup(descriptor)
        guard output >= 0 else {
            return group.next().makeFailedFuture(NIOCore.IOError(errnoCode: errno, reason: "dup"))
        }
        return take(descriptor, output)
    }

    /// Options, then both initializers, then register, then go active over
    /// the descriptors.
    private func take<Output: Sendable>(
        input: CInt?,
        output: CInt?,
        channelInitializer: @escaping @Sendable (Channel) -> EventLoopFuture<Output>
    ) -> EventLoopFuture<Output> {
        precondition(input != nil || output != nil, "a pipe channel needs an input or an output descriptor")
        precondition(input ?? 0 >= 0 && output ?? 0 >= 0 && input != output,
                     "the input and output descriptors must be distinct and not negative")
        let loop = group.next() as! VegaEventLoop
        do {
            if let input { try refuseFiles(input) }
            if let output { try refuseFiles(output) }
        } catch {
            return loop.makeFailedFuture(error)
        }
        let channel = VegaSocketChannel(loop: loop)
        let channelInit = self.channelInit
        let options = self.channelOptions
        // Ours from here: until the channel has them, a failure closes them.
        let handedOver = NIOLockedValueBox(false)
        return loop.flatSubmit {
            options.applyAllChannelOptions(to: channel).flatMap {
                channelInit?(channel) ?? loop.makeSucceededVoidFuture()
            }.flatMap {
                channelInitializer(channel)
            }.flatMap { result in
                channel.register().flatMap {
                    let promise = loop.makePromise(of: Void.self)
                    handedOver.withLockedValue { $0 = true }
                    channel.activatePipe(input: input, output: output, promise: promise)
                    return promise.futureResult
                }.map { result }
            }.flatMapError { error in
                if !handedOver.withLockedValue({ $0 }) {
                    if let input { closeDescriptor(input) }
                    if let output { closeDescriptor(output) }
                }
                channel.close(promise: nil)
                return loop.makeFailedFuture(error)
            }
        }
    }
}

@available(*, unavailable)
extension VegaPipeBootstrap: Sendable {}

/// NIO refuses what can't be waited on for readiness: regular files,
/// directories, symbolic links and block devices.
private func refuseFiles(_ descriptor: CInt) throws {
    var info = stat()
    guard fstat(descriptor, &info) == 0 else { throw NIOCore.IOError(errnoCode: errno, reason: "fstat") }
    switch info.st_mode & S_IFMT {
    case S_IFREG, S_IFDIR, S_IFLNK, S_IFBLK:
        throw ChannelError.operationUnsupported
    default:
        break
    }
}
#endif
