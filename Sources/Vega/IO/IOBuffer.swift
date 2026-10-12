/// A fixed-capacity byte buffer with one owner: no reference counting, no
/// copy-on-write. Bytes `0..<count` are readable; reads append after them.
///
/// ```swift
/// var buf = IOBuffer(capacity: 4096)
/// while try await stream.read(into: &buf) > 0 {
///     try await stream.write(buf)
///     buf.clear()
/// }
/// ```
public struct IOBuffer: ~Copyable, @unchecked Sendable {
    @usableFromInline let base: UnsafeMutableRawPointer
    public let capacity: Int
    /// Readable bytes, at the start of the buffer.
    public var count: Int

    public init(capacity: Int) {
        precondition(capacity > 0, "IOBuffer capacity must be positive")
        base = .allocate(byteCount: capacity, alignment: 16)
        self.capacity = capacity
        count = 0
    }

    deinit { base.deallocate() }

    /// Room left after the readable bytes.
    @inlinable public var spareCapacity: Int { capacity - count }

    @inlinable public var isEmpty: Bool { count == 0 }

    /// Forget the readable bytes.
    @inlinable public mutating func clear() { count = 0 }

    /// Append `bytes`, up to the capacity. Returns how many fitted.
    @discardableResult
    public mutating func append(_ bytes: UnsafeRawBufferPointer) -> Int {
        let n = min(bytes.count, spareCapacity)
        if n > 0 { (base + count).copyMemory(from: bytes.baseAddress!, byteCount: n) }
        count += n
        return n
    }

    @discardableResult
    public mutating func append(_ string: String) -> Int {
        var s = string
        return s.withUTF8 { append(UnsafeRawBufferPointer($0)) }
    }

    /// Drop the first `n` readable bytes, moving the rest to the front.
    public mutating func consume(_ n: Int) {
        precondition(n >= 0 && n <= count, "consume past the readable bytes")
        if n < count { base.copyMemory(from: base + n, byteCount: count - n) }
        count -= n
    }

    /// The readable bytes.
    @inlinable
    public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
        try body(UnsafeRawBufferPointer(start: base, count: count))
    }

    /// The spare capacity, to fill by hand; return how many bytes were written.
    @inlinable
    public mutating func withUnsafeSpareCapacity<E: Error>(
        _ body: (UnsafeMutableRawBufferPointer) throws(E) -> Int
    ) throws(E) {
        let n = try body(UnsafeMutableRawBufferPointer(start: base + count, count: spareCapacity))
        precondition(n >= 0 && n <= spareCapacity, "wrote past the spare capacity")
        count += n
    }

    /// The readable bytes as a string (UTF-8, repaired).
    public var string: String {
        withUnsafeBytes { String(decoding: $0, as: UTF8.self) }
    }
}
