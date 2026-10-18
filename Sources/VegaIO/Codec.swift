import Vega

/// Turns bytes from a stream into items: Tokio's `Decoder`, NIO's
/// `ByteToMessageDecoder`.
public protocol FrameDecoder {
    associatedtype Item

    /// Decode one item from the start of `bytes` (which may be empty): the
    /// item and how many bytes it used, or nil if `bytes` doesn't hold a whole
    /// one yet. Throw on input that can never become one. An item may use no
    /// bytes, as long as the decoder moves on to something else.
    mutating func decode(_ bytes: UnsafeRawBufferPointer) throws(CodecError) -> (item: Item, consumed: Int)?

    /// The stream ended with `bytes` left over (possibly none). Return a last
    /// item, or nil when there are no more. The default returns nil for no
    /// bytes, and otherwise decodes them or throws `.truncated`.
    mutating func decodeAtEnd(_ bytes: UnsafeRawBufferPointer) throws(CodecError) -> (item: Item, consumed: Int)?
}

extension FrameDecoder {
    public mutating func decodeAtEnd(_ bytes: UnsafeRawBufferPointer) throws(CodecError) -> (item: Item, consumed: Int)? {
        if let whole = try decode(bytes) { return whole }
        if bytes.isEmpty { return nil }
        throw .truncated(bytes.count)
    }
}

/// Turns items into bytes for a stream: Tokio's `Encoder`, NIO's
/// `MessageToByteEncoder`.
public protocol FrameEncoder {
    associatedtype Item

    /// Append `item`'s bytes to `buffer` (grow it with `reserveCapacity`).
    mutating func encode(_ item: Item, into buffer: inout IOBuffer) throws(CodecError)
}

/// What a codec rejected.
///
/// A struct rather than an enum, so that kinds of failure can be added
/// without breaking anyone's exhaustive `switch`: switch over `code`.
public struct CodecError: Error, Hashable, Sendable, CustomStringConvertible {
    /// What kind of failure this is.
    public let code: Code
    public let length: Int?
    public let message: String?

    /// The kinds of `CodecError`.
    public struct Code: Hashable, Sendable, CustomStringConvertible {
        let rawValue: UInt8

        /// A frame longer than the codec allows: `length` long.
        public static let frameTooLong = Code(rawValue: 0)
        /// The stream ended inside a frame, with `length` bytes of it left.
        public static let truncated = Code(rawValue: 1)
        /// Bytes that aren't a valid frame: `message` says why.
        public static let malformed = Code(rawValue: 2)

        public var description: String {
            let names = ["frameTooLong", "truncated", "malformed"]
            return Int(rawValue) < names.count ? names[Int(rawValue)] : "code \(rawValue)"
        }
    }

    init(_ code: Code, length: Int? = nil, message: String? = nil) {
        self.code = code
        self.length = length
        self.message = message
    }

    /// A frame longer than the codec allows: `length` long.
    public static func frameTooLong(_ length: Int) -> CodecError { CodecError(.frameTooLong, length: length) }
    /// The stream ended inside a frame, with `length` bytes of it left.
    public static func truncated(_ length: Int) -> CodecError { CodecError(.truncated, length: length) }
    /// Bytes that aren't a valid frame: `message` says why.
    public static func malformed(_ message: String) -> CodecError { CodecError(.malformed, message: message) }

    public var description: String {
        switch code {
        case .frameTooLong: "frame too long (\(length!) bytes)"
        case .truncated: "stream ended inside a frame (\(length!) bytes left)"
        case .malformed: "malformed frame: \(message ?? "")"
        default: "\(code)"
        }
    }
}

/// Why a framed read or write failed.
///
/// A struct rather than an enum, so that kinds of failure can be added
/// without breaking anyone's exhaustive `switch`: switch over `code`.
public struct FramedError: Error, Hashable, Sendable, CustomStringConvertible {
    /// What kind of failure this is.
    public let code: Code
    public let ioError: IOError?
    public let codecError: CodecError?

    /// The kinds of `FramedError`.
    public struct Code: Hashable, Sendable, CustomStringConvertible {
        let rawValue: UInt8

        /// The stream failed.
        public static let io = Code(rawValue: 0)
        /// The codec refused the bytes: `codecError` says why.
        public static let codec = Code(rawValue: 1)

        public var description: String {
            let names = ["io", "codec"]
            return Int(rawValue) < names.count ? names[Int(rawValue)] : "code \(rawValue)"
        }
    }

    init(_ code: Code, ioError: IOError? = nil, codecError: CodecError? = nil) {
        self.code = code
        self.ioError = ioError
        self.codecError = codecError
    }

    /// The stream failed.
    public static func io(_ ioError: IOError) -> FramedError { FramedError(.io, ioError: ioError) }
    /// The codec refused the bytes: `codecError` says why.
    public static func codec(_ codecError: CodecError) -> FramedError { FramedError(.codec, codecError: codecError) }

    public var description: String {
        switch code {
        case .io: "\(ioError!)"
        case .codec: "\(codecError!)"
        default: "\(code)"
        }
    }
}
