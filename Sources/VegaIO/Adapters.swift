import Vega

/// A stream that reads `prefix` first, then from `stream`: for bytes read
/// past a handshake (a proxy's reply, an HTTP upgrade) that belong to the
/// protocol after it.
///
/// ```swift
/// let leftover = try await HTTPProxy.connect(through: tcp, to: "example.com:443")
/// let tls = try await TLSStream.connect(PrefixedStream(tcp, prefix: leftover), ...)
/// ```
public struct PrefixedStream<Stream: AsyncReader & AsyncWriter & ~Copyable>: ~Copyable, AsyncReader, AsyncWriter {
    private let stream: Stream
    private let prefix: PrefixBytes

    public init(_ stream: consuming Stream, prefix: [UInt8]) {
        self.stream = stream
        self.prefix = PrefixBytes(prefix)
    }

    public func read(into buffer: inout IOBuffer) async throws(IOError) -> Int {
        let n = prefix.take(into: &buffer)
        if n > 0 { return n }
        return try await stream.read(into: &buffer)
    }

    public func write(_ bytes: UnsafeRawBufferPointer) async throws(IOError) {
        try await stream.write(bytes)
    }

    /// Give back the stream, with any of the prefix not yet read lost.
    public consuming func intoStream() -> Stream {
        stream
    }
}

extension PrefixedStream: Sendable where Stream: Sendable & ~Copyable {}

/// The unread part of a prefix. Reads are one task at a time, as for any
/// stream, so no lock.
private final class PrefixBytes: @unchecked Sendable {
    private var bytes: [UInt8]
    private var at = 0

    init(_ bytes: [UInt8]) { self.bytes = bytes }

    func take(into buffer: inout IOBuffer) -> Int {
        guard at < bytes.count, buffer.spareCapacity > 0 else { return 0 }
        let n = min(bytes.count - at, buffer.spareCapacity)
        let from = at
        _ = bytes.withUnsafeBytes { buffer.append(UnsafeRawBufferPointer(rebasing: $0[from..<from + n])) }
        at += n
        if at == bytes.count { bytes = [] }
        return n
    }
}

/// Copy both ways between two split streams until both directions end:
/// Tokio's `copy_bidirectional`. When one side's reads end, the other
/// side's writer is dropped, which shuts down its sending side (for TCP),
/// so the end passes through. Returns the bytes copied each way; the first
/// error on either side is thrown once both have stopped.
@discardableResult
public func copyBidirectional<R1: AsyncReader & ~Copyable & Sendable, W1: AsyncWriter & ~Copyable & Sendable,
                              R2: AsyncReader & ~Copyable & Sendable, W2: AsyncWriter & ~Copyable & Sendable>(
    _ a: consuming StreamHalves<R1, W1>, _ b: consuming StreamHalves<R2, W2>, bufferSize: Int = 16 * 1024
) async throws(IOError) -> (aToB: Int, bToA: Int) {
    let forward = Pass(a.reader, b.writer)
    let backward = Pass(b.reader, a.writer)
    let results = await withTaskGroup(of: (Bool, Result<Int, IOError>).self) { group in
        group.addTask { (true, await forward.run(bufferSize)) }
        group.addTask { (false, await backward.run(bufferSize)) }
        var aToB: Result<Int, IOError> = .success(0), bToA: Result<Int, IOError> = .success(0)
        for await (isForward, result) in group {
            if isForward { aToB = result } else { bToA = result }
        }
        return (aToB, bToA)
    }
    return (try results.0.get(), try results.1.get())
}

/// One direction of `copyBidirectional`: owns its reader and writer, and
/// drops the writer when done.
private final class Pass<R: AsyncReader & ~Copyable & Sendable, W: AsyncWriter & ~Copyable & Sendable>: @unchecked Sendable {
    private var reader: R?
    private var writer: W?

    init(_ reader: consuming R, _ writer: consuming W) {
        self.reader = consume reader
        self.writer = consume writer
    }

    func run(_ bufferSize: Int) async -> Result<Int, IOError> {
        let reader = self.reader.take()!
        let writer = self.writer.take()!
        do throws(IOError) {
            return .success(try await copy(from: reader, to: writer, bufferSize: bufferSize))
        } catch {
            return .failure(error)
        }
    }
}
