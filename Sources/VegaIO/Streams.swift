import Vega

/// A byte stream that can be read: Tokio's `AsyncRead`. TCP and Unix
/// streams and their read halves conform, and so does VegaTest's in-memory
/// duplex stream.
public protocol AsyncReader: ~Copyable {
    /// Read into `buffer`'s spare capacity. Returns the bytes read: 0 means
    /// end of stream. A buffer with no spare capacity throws
    /// `IOError.limitExceeded`: make room first (`reserveCapacity(_:)`,
    /// `consume(_:)`), so that 0 can only mean the end.
    func read(into buffer: inout IOBuffer) async throws(IOError) -> Int

    /// `read(into:)`, saying in `arrival` when the bytes read arrived where
    /// the stream can tell: a TCP stream with `receiveTimestamps` on (see
    /// `ReadArrival`). Any other stream reads as `read(into:)` does and
    /// clears `arrival`.
    func read(into buffer: inout IOBuffer, arrival: UnsafeMutablePointer<ReadArrival>) async throws(IOError) -> Int
}

extension AsyncReader where Self: ~Copyable {
    public func read(into buffer: inout IOBuffer,
                     arrival: UnsafeMutablePointer<ReadArrival>) async throws(IOError) -> Int {
        arrival.pointee.clear()
        return try await read(into: &buffer)
    }
}

/// A byte stream that can be written: Tokio's `AsyncWrite`.
public protocol AsyncWriter: ~Copyable {
    /// Write all of `bytes`. They must stay valid until this returns.
    func write(_ bytes: UnsafeRawBufferPointer) async throws(IOError)

    /// Tell the peer nothing more is coming, keeping the reading side open:
    /// a TCP FIN, a QUIC stream's FIN, TLS's close_notify and then the
    /// transport's. Writes after it fail. A wrapper sends what it holds
    /// first. Where the stream can't end one way (a pipe, Network.framework's
    /// TLS) it throws `IOError.unsupported`.
    func shutdownWrite() async throws(IOError)
}

extension AsyncWriter where Self: ~Copyable {
    /// Write all of `buffer`'s readable bytes.
    @inlinable
    public func write(_ buffer: borrowing IOBuffer) async throws(IOError) {
        let bytes = buffer.withUnsafeBytes { $0 }
        try await write(bytes)
    }
}

#if os(Linux) || canImport(Darwin) || os(Windows)
extension TCPStream: AsyncReader, AsyncWriter {}
extension UnixStream: AsyncReader, AsyncWriter {}
extension ReadHalf: AsyncReader {}
extension WriteHalf: AsyncWriter {}
extension PipeReader: AsyncReader {}
extension PipeWriter: AsyncWriter {}
#endif

#if os(Linux)
extension VsockStream: AsyncReader, AsyncWriter {}
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
