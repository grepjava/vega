import Vega

/// A byte stream that can be read: Tokio's `AsyncRead`. TCP and Unix
/// streams and their read halves conform, and so does VegaTest's in-memory
/// duplex stream.
public protocol AsyncReader: ~Copyable {
    /// Read into `buffer`'s spare capacity. Returns the bytes read: 0 means
    /// end of stream (or a full buffer).
    func read(into buffer: inout IOBuffer) async throws(IOError) -> Int
}

/// A byte stream that can be written: Tokio's `AsyncWrite`.
public protocol AsyncWriter: ~Copyable {
    /// Write all of `bytes`. They must stay valid until this returns.
    func write(_ bytes: UnsafeRawBufferPointer) async throws(IOError)
}

extension AsyncWriter where Self: ~Copyable {
    /// Write all of `buffer`'s readable bytes.
    @inlinable
    public func write(_ buffer: borrowing IOBuffer) async throws(IOError) {
        let bytes = buffer.withUnsafeBytes { $0 }
        try await write(bytes)
    }
}

/// A stream split into a read half and a write half, for two tasks to use
/// at once: what `halves()` returns on TCP, Unix, duplex and TLS streams.
@frozen
public struct StreamHalves<Reader: AsyncReader & ~Copyable, Writer: AsyncWriter & ~Copyable>: ~Copyable {
    public var reader: Reader
    public var writer: Writer

    public init(reader: consuming Reader, writer: consuming Writer) {
        self.reader = reader
        self.writer = writer
    }
}

#if os(Linux) || canImport(Darwin) || os(Windows)
extension TCPStream {
    /// `split()`, as `StreamHalves`.
    public consuming func halves() -> StreamHalves<ReadHalf, WriteHalf> {
        let split = split()
        return StreamHalves(reader: split.reader, writer: split.writer)
    }
}

extension UnixStream {
    /// `split()`, as `StreamHalves`.
    public consuming func halves() -> StreamHalves<ReadHalf, WriteHalf> {
        let split = split()
        return StreamHalves(reader: split.reader, writer: split.writer)
    }
}

extension TCPStream: AsyncReader, AsyncWriter {}
extension UnixStream: AsyncReader, AsyncWriter {}
extension ReadHalf: AsyncReader {}
extension WriteHalf: AsyncWriter {}
extension PipeReader: AsyncReader {}
extension PipeWriter: AsyncWriter {}
#endif

/// Read until `buffer` holds `n` bytes or the stream ends; returns the bytes
/// it holds. Grows the buffer if it can't take `n`.
public func readAtLeast<R: AsyncReader & ~Copyable>(
    _ n: Int, from reader: borrowing R, into buffer: inout IOBuffer
) async throws(IOError) -> Int {
    buffer.reserveCapacity(n)
    while buffer.count < n {
        if try await reader.read(into: &buffer) == 0 { break }
    }
    return buffer.count
}

/// Copy everything from `reader` to `writer` until end of stream: Tokio's
/// `io::copy`. Returns the bytes copied.
@discardableResult
public func copy<R: AsyncReader & ~Copyable, W: AsyncWriter & ~Copyable>(
    from reader: borrowing R, to writer: borrowing W, bufferSize: Int = 16 * 1024
) async throws(IOError) -> Int {
    var buffer = IOBuffer(capacity: bufferSize)
    var total = 0
    while true {
        buffer.clear()
        let n = try await reader.read(into: &buffer)
        if n == 0 { return total }
        try await writer.write(buffer)
        total += n
    }
}
