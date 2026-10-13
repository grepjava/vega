import Vega

/// Turns bytes from a stream into items: Tokio's `Decoder`, NIO's
/// `ByteToMessageDecoder`.
public protocol Decoder {
    associatedtype Item

    /// Decode one item from the start of `bytes`: the item and how many
    /// bytes it used, or nil if `bytes` doesn't hold a whole one yet. Throw
    /// on input that can never become one.
    mutating func decode(_ bytes: UnsafeRawBufferPointer) throws(CodecError) -> (item: Item, consumed: Int)?

    /// The stream ended with `bytes` left over (never empty). Return a last
    /// item from them, or nil to drop them. The default throws `.truncated`.
    mutating func decodeAtEnd(_ bytes: UnsafeRawBufferPointer) throws(CodecError) -> (item: Item, consumed: Int)?
}

extension Decoder {
    public mutating func decodeAtEnd(_ bytes: UnsafeRawBufferPointer) throws(CodecError) -> (item: Item, consumed: Int)? {
        if let whole = try decode(bytes) { return whole }
        throw .truncated(bytes.count)
    }
}

/// Turns items into bytes for a stream: Tokio's `Encoder`, NIO's
/// `MessageToByteEncoder`.
public protocol Encoder {
    associatedtype Item

    /// Append `item`'s bytes to `buffer` (grow it with `reserveCapacity`).
    mutating func encode(_ item: Item, into buffer: inout IOBuffer) throws(CodecError)
}

/// What a codec rejected.
public enum CodecError: Error, Sendable, Hashable {
    /// A frame longer than the codec allows.
    case frameTooLong(Int)
    /// The stream ended inside a frame; this many bytes were left.
    case truncated(Int)
    /// Bytes that aren't a valid frame.
    case malformed(String)
}

/// Why a framed read or write failed.
public enum FramedError: Error, Sendable, Hashable {
    case io(IOError)
    case codec(CodecError)
}

extension IOBuffer {
    /// Append `bytes`, growing the buffer if they don't fit.
    public mutating func write(_ bytes: UnsafeRawBufferPointer) {
        if bytes.count > spareCapacity { reserveCapacity(Swift.max(capacity * 2, count + bytes.count)) }
        append(bytes)
    }
}
