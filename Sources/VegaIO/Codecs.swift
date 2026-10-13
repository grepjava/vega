import Vega

/// Frames prefixed with their length: Tokio's `LengthDelimitedCodec`, NIO's
/// `LengthFieldBasedFrameDecoder` / `LengthFieldPrepender`.
///
/// Each frame is a length field (1, 2, 4 or 8 bytes, big-endian by default)
/// counting the payload bytes after it, then the payload.
public struct LengthDelimitedCodec: Decoder, Encoder, Sendable {
    public typealias Item = [UInt8]

    public var lengthFieldSize: Int
    public var bigEndian: Bool
    /// Longer frames are rejected (`.frameTooLong`) without buffering them.
    public var maxFrameLength: Int

    public init(lengthFieldSize: Int = 4, bigEndian: Bool = true, maxFrameLength: Int = 8 * 1024 * 1024) {
        precondition([1, 2, 4, 8].contains(lengthFieldSize), "length field of 1, 2, 4 or 8 bytes")
        self.lengthFieldSize = lengthFieldSize
        self.bigEndian = bigEndian
        self.maxFrameLength = maxFrameLength
    }

    public mutating func decode(_ bytes: UnsafeRawBufferPointer) throws(CodecError) -> (item: [UInt8], consumed: Int)? {
        guard bytes.count >= lengthFieldSize else { return nil }
        var length: UInt64 = 0
        for i in 0..<lengthFieldSize {
            let b = UInt64(bytes[bigEndian ? i : lengthFieldSize - 1 - i])
            length = length << 8 | b
        }
        guard length <= UInt64(maxFrameLength) else { throw .frameTooLong(Int(clamping: length)) }
        let total = lengthFieldSize + Int(length)
        guard bytes.count >= total else { return nil }
        return (Array(bytes[lengthFieldSize..<total]), total)
    }

    public mutating func encode(_ item: [UInt8], into buffer: inout IOBuffer) throws(CodecError) {
        guard item.count <= maxFrameLength else { throw .frameTooLong(item.count) }
        let maxField = lengthFieldSize == 8 ? UInt64.max : (UInt64(1) << (8 * lengthFieldSize)) - 1
        guard UInt64(item.count) <= maxField else { throw .frameTooLong(item.count) }
        withUnsafeTemporaryAllocation(byteCount: lengthFieldSize, alignment: 1) { field in
            let n = UInt64(item.count)
            for i in 0..<lengthFieldSize {
                let shift = 8 * (bigEndian ? lengthFieldSize - 1 - i : i)
                field[i] = UInt8(truncatingIfNeeded: n >> UInt64(shift))
            }
            buffer.write(UnsafeRawBufferPointer(field))
        }
        item.withUnsafeBytes { buffer.write($0) }
    }
}

/// Text lines: Tokio's `LinesCodec`, NIO's `LineBasedFrameDecoder`.
/// Decodes up to each `\n` (dropping a `\r` before it); encodes a line and a
/// `\n`. A last line without a newline is returned at end of stream.
public struct LinesCodec: Decoder, Encoder, Sendable {
    public typealias Item = String

    /// Longer lines are rejected (`.frameTooLong`).
    public var maxLength: Int

    public init(maxLength: Int = 64 * 1024) {
        self.maxLength = maxLength
    }

    public mutating func decode(_ bytes: UnsafeRawBufferPointer) throws(CodecError) -> (item: String, consumed: Int)? {
        guard let nl = bytes.firstIndex(of: UInt8(ascii: "\n")) else {
            if bytes.count > maxLength { throw .frameTooLong(bytes.count) }
            return nil
        }
        var end = nl
        if end > 0 && bytes[end - 1] == UInt8(ascii: "\r") { end -= 1 }
        if end > maxLength { throw .frameTooLong(end) }
        return (String(decoding: UnsafeRawBufferPointer(rebasing: bytes[0..<end]), as: UTF8.self), nl + 1)
    }

    public mutating func decodeAtEnd(_ bytes: UnsafeRawBufferPointer) throws(CodecError) -> (item: String, consumed: Int)? {
        if let line = try decode(bytes) { return line }
        if bytes.count > maxLength { throw .frameTooLong(bytes.count) }
        return (String(decoding: bytes, as: UTF8.self), bytes.count)
    }

    public mutating func encode(_ item: String, into buffer: inout IOBuffer) throws(CodecError) {
        var line = item
        guard line.utf8.count <= maxLength else { throw .frameTooLong(line.utf8.count) }
        line.withUTF8 { buffer.write(UnsafeRawBufferPointer($0)) }
        withUnsafeBytes(of: UInt8(ascii: "\n")) { buffer.write($0) }
    }
}

/// Whatever bytes arrive, as they arrive: Tokio's `BytesCodec`.
public struct BytesCodec: Decoder, Encoder, Sendable {
    public typealias Item = [UInt8]

    public init() {}

    public mutating func decode(_ bytes: UnsafeRawBufferPointer) throws(CodecError) -> (item: [UInt8], consumed: Int)? {
        bytes.isEmpty ? nil : (Array(bytes), bytes.count)
    }

    public mutating func encode(_ item: [UInt8], into buffer: inout IOBuffer) throws(CodecError) {
        item.withUnsafeBytes { buffer.write($0) }
    }
}
