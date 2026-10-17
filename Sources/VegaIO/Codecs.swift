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
        if bytes.isEmpty { return nil }
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

/// Messages framed by a `Content-Length` header and a blank line, as the
/// Language Server Protocol frames JSON-RPC (NIOExtras'
/// `ContentLengthHeaderFrameDecoder`): `Content-Length: 17\r\n\r\n` and then
/// the 17 bytes. Other header lines are allowed and ignored.
public struct ContentLengthCodec: Decoder, Encoder, Sendable {
    public typealias Item = [UInt8]

    /// A longer message, or a longer header, is an error.
    public var maxLength: Int

    public init(maxLength: Int = 16 << 20) {
        self.maxLength = maxLength
    }

    public mutating func decode(_ bytes: UnsafeRawBufferPointer) throws(CodecError) -> (item: [UInt8], consumed: Int)? {
        // The header ends at the first blank line.
        var headerEnd: Int?
        if bytes.count >= 4 {
            for i in 0...(bytes.count - 4)
            where bytes[i] == 0x0D && bytes[i + 1] == 0x0A && bytes[i + 2] == 0x0D && bytes[i + 3] == 0x0A {
                headerEnd = i
                break
            }
        }
        guard let headerEnd else {
            if bytes.count > 4096 { throw .malformed("no end to a Content-Length header in 4096 bytes") }
            return nil
        }
        var length: Int?
        for line in String(decoding: UnsafeRawBufferPointer(rebasing: bytes[..<headerEnd]), as: UTF8.self)
            .split(separator: "\r\n") {
            guard let colon = line.firstIndex(of: ":") else { throw .malformed("a header line without a colon") }
            if line[..<colon].lowercased() == "content-length" {
                guard let n = Int(line[line.index(after: colon)...].trimmingSpaces), n >= 0 else {
                    throw .malformed("a bad Content-Length")
                }
                length = n
            }
        }
        guard let length else { throw .malformed("no Content-Length") }
        guard length <= maxLength else { throw .malformed("a message of \(length) bytes") }
        let start = headerEnd + 4
        guard bytes.count - start >= length else { return nil }
        return (Array(UnsafeRawBufferPointer(rebasing: bytes[start..<(start + length)])), start + length)
    }

    public mutating func encode(_ item: [UInt8], into buffer: inout IOBuffer) throws(CodecError) {
        guard item.count <= maxLength else { throw .malformed("a message of \(item.count) bytes") }
        Array("Content-Length: \(item.count)\r\n\r\n".utf8).withUnsafeBytes { buffer.write($0) }
        item.withUnsafeBytes { buffer.write($0) }
    }
}

extension Substring {
    fileprivate var trimmingSpaces: Substring {
        var s = self
        while s.first == " " || s.first == "\t" { s.removeFirst() }
        while s.last == " " || s.last == "\t" { s.removeLast() }
        return s
    }
}
