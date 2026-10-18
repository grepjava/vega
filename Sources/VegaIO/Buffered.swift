import Vega

/// A reader with a buffer in front: Tokio's `BufReader`. Small reads come
/// out of the buffer, and `readLine`, `read(until:)` and `readExactly` read
/// as much as they need from the stream under it, a buffer's worth at a
/// time.
///
/// ```swift
/// let input = BufferedReader(stream)
/// while let line = try await input.readLine() { ... }
/// ```
///
/// One task reads at a time, as for any stream.
public struct BufferedReader<Reader: AsyncReader & ~Copyable>: ~Copyable, AsyncReader {
    public let reader: Reader
    let storage: ReadBuffer

    public init(_ reader: consuming Reader, capacity: Int = 8 * 1024) {
        self.reader = reader
        storage = ReadBuffer(capacity: capacity)
    }

    /// Bytes buffered and not yet read.
    public var buffered: Int { storage.count }

    /// Read into `buffer`: from what is buffered, or, when nothing is and
    /// `buffer` has room for a buffer's worth, straight from the stream.
    public func read(into buffer: inout IOBuffer) async throws(IOError) -> Int {
        if storage.count == 0 && buffer.spareCapacity >= storage.capacity {
            return try await reader.read(into: &buffer)
        }
        if storage.count == 0, try await fill() == 0 { return 0 }
        return storage.take(into: &buffer)
    }

    /// Read more into the buffer: the bytes read, 0 at the end of the
    /// stream.
    @discardableResult
    public func fill() async throws(IOError) -> Int {
        storage.makeRoom()
        return try await reader.read(into: &storage.bytes)
    }

    /// The bytes up to and including `delimiter`; at the end of the stream
    /// what is left, or nil if nothing is. Throws if more than `limit`
    /// bytes come without one.
    public func read(until delimiter: UInt8, limit: Int = 1 << 20) async throws(IOError) -> [UInt8]? {
        var out: [UInt8] = []
        while true {
            if let found = storage.take(through: delimiter, appendingTo: &out) {
                return found
            }
            if out.count > limit { throw IOError(code: -6, message: "no delimiter in \(limit) bytes") }
            if try await fill() == 0 { return out.isEmpty ? nil : out }
        }
    }

    /// The next line, without its "\n" (or "\r\n"); nil at the end of the
    /// stream. A last line without a newline is returned too.
    public func readLine(limit: Int = 64 * 1024) async throws(IOError) -> String? {
        guard var line = try await read(until: 0x0A, limit: limit) else { return nil }
        if line.last == 0x0A { line.removeLast() }
        if line.last == 0x0D { line.removeLast() }
        return String(decoding: line, as: UTF8.self)
    }

    /// Exactly `count` bytes; throws `.connectionReset` if the stream ends
    /// first.
    public func readExactly(_ count: Int) async throws(IOError) -> [UInt8] {
        var out: [UInt8] = []
        out.reserveCapacity(count)
        while out.count < count {
            if storage.count == 0, try await fill() == 0 { throw .connectionReset }
            storage.take(upTo: count - out.count, appendingTo: &out)
        }
        return out
    }

    /// Give back the reader; what is buffered is lost (take it first with
    /// `read(into:)`).
    public consuming func intoReader() -> Reader {
        reader
    }
}

extension BufferedReader: Sendable where Reader: Sendable & ~Copyable {}

/// A writer with a buffer in front: Tokio's `BufWriter`. Writes collect in
/// the buffer and go to the stream under it a buffer's worth at a time, or
/// on `flush()`; a write bigger than the buffer goes straight through.
/// Flush before dropping it, or what is buffered is lost.
public struct BufferedWriter<Writer: AsyncWriter & ~Copyable>: ~Copyable, AsyncWriter {
    public let writer: Writer
    let storage: WriteBuffer

    public init(_ writer: consuming Writer, capacity: Int = 8 * 1024) {
        self.writer = writer
        storage = WriteBuffer(capacity: capacity)
    }

    /// Bytes buffered and not yet written.
    public var buffered: Int { storage.bytes.count }

    public func write(_ bytes: UnsafeRawBufferPointer) async throws(IOError) {
        if storage.bytes.count + bytes.count > storage.bytes.capacity {
            try await flush()
            if bytes.count >= storage.bytes.capacity {
                try await writer.write(bytes)
                return
            }
        }
        _ = storage.bytes.append(bytes)
    }

    /// Write `string`'s UTF-8.
    public func write(_ string: String) async throws(IOError) {
        var bytes = IOBuffer(capacity: string.utf8.count)
        _ = bytes.append(string)
        try await write(bytes)
    }

    /// Write out what is buffered.
    public func flush() async throws(IOError) {
        guard storage.bytes.count > 0 else { return }
        defer { storage.bytes.clear() }
        try await writer.write(storage.bytes)
    }

    /// Write out what is buffered, then end the writer's side.
    public func shutdownWrite() async throws(IOError) {
        try await flush()
        try await writer.shutdownWrite()
    }

    public consuming func intoWriter() -> Writer {
        writer
    }
}

extension BufferedWriter: Sendable where Writer: Sendable & ~Copyable {}

/// A `BufferedReader`'s bytes: `bytes[start...]` are unread. One reader at
/// a time, so no lock.
final class ReadBuffer: @unchecked Sendable {
    var bytes: IOBuffer
    var start = 0
    let capacity: Int

    init(capacity: Int) {
        self.capacity = max(capacity, 64)
        bytes = IOBuffer(capacity: self.capacity)
    }

    var count: Int { bytes.count - start }

    /// Drop what has been read, so a read has the spare capacity.
    func makeRoom() {
        if start > 0 {
            bytes.consume(start)
            start = 0
        }
        if bytes.spareCapacity == 0 { bytes.reserveCapacity(bytes.capacity * 2) }
    }

    func take(into buffer: inout IOBuffer) -> Int {
        let n = min(count, buffer.spareCapacity)
        let from = start
        _ = bytes.withUnsafeBytes { buffer.append(UnsafeRawBufferPointer(rebasing: $0[from..<(from + n)])) }
        start += n
        return n
    }

    func take(upTo n: Int, appendingTo out: inout [UInt8]) {
        let n = min(n, count)
        let from = start
        bytes.withUnsafeBytes { out.append(contentsOf: $0[from..<(from + n)]) }
        start += n
    }

    /// Everything through `delimiter`, appended to `out`, which is then
    /// returned; or all that is buffered appended and nil, if it isn't there.
    func take(through delimiter: UInt8, appendingTo out: inout [UInt8]) -> [UInt8]? {
        let from = start
        let end = bytes.count
        let found = bytes.withUnsafeBytes { b -> Int? in
            b[from..<end].firstIndex(of: delimiter)
        }
        let upTo = found.map { $0 + 1 } ?? end
        bytes.withUnsafeBytes { out.append(contentsOf: $0[from..<upTo]) }
        start = upTo
        return found != nil ? out : nil
    }
}

/// A `BufferedWriter`'s bytes. One writer at a time, so no lock.
final class WriteBuffer: @unchecked Sendable {
    var bytes: IOBuffer

    init(capacity: Int) {
        bytes = IOBuffer(capacity: max(capacity, 64))
    }
}
