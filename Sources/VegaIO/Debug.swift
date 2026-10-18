import Vega

/// A stream that shows what passes through it, as NIOExtras'
/// `DebugInboundEventsHandler` and `DebugOutboundEventsHandler` do: each
/// read, write and end goes to `observe` before the caller sees it.
///
/// ```swift
/// let stream = DebugStream(tcp) { event in print(event) }
/// ```
public struct DebugStream<Stream: AsyncReader & AsyncWriter & ~Copyable>: ~Copyable, AsyncReader, AsyncWriter {
    /// What happened on the stream.
    public typealias Event = DebugStreamEvent

    public let stream: Stream
    let observe: @Sendable (Event) -> Void

    public init(_ stream: consuming Stream, observe: @escaping @Sendable (Event) -> Void) {
        self.stream = stream
        self.observe = observe
    }

    public func read(into buffer: inout IOBuffer) async throws(IOError) -> Int {
        let before = buffer.count
        do {
            let n = try await stream.read(into: &buffer)
            observe(n == 0 ? .end : .read(buffer.withUnsafeBytes { Array($0[before..<(before + n)]) }))
            return n
        } catch {
            observe(.readFailed(error))
            throw error
        }
    }

    public func write(_ bytes: UnsafeRawBufferPointer) async throws(IOError) {
        do {
            try await stream.write(bytes)
            observe(.wrote(Array(bytes)))
        } catch {
            observe(.writeFailed(error))
            throw error
        }
    }

    public func shutdownWrite() async throws(IOError) {
        try await stream.shutdownWrite()
    }

    public consuming func intoStream() -> Stream {
        stream
    }
}

/// The first bytes as text where they're printable, escaped where not.
func debugPreview(_ bytes: [UInt8], limit: Int = 64) -> String {
    var out = ""
    for b in bytes.prefix(limit) {
        switch b {
        case 0x0A: out += "\\n"
        case 0x0D: out += "\\r"
        case 0x20..<0x7F: out.unicodeScalars.append(Unicode.Scalar(b))
        default: out += "\\x" + String(b, radix: 16).leftPadded(2)
        }
    }
    return bytes.count > limit ? out + "..." : out
}

extension DebugStream: Sendable where Stream: Sendable & ~Copyable {}

extension String {
    fileprivate func leftPadded(_ width: Int) -> String {
        count >= width ? self : String(repeating: "0", count: width - count) + self
    }
}

/// What happened on the stream.
///
/// A struct rather than an enum, so that kinds can be added without
/// breaking anyone's exhaustive `switch`: switch over `kind`.
public struct DebugStreamEvent: Sendable, Hashable, CustomStringConvertible {
    /// What kind of event this is.
    public let kind: Kind
    public let bytes: [UInt8]?
    public let ioError: IOError?

    /// The kinds of `DebugStreamEvent`.
    public struct Kind: Hashable, Sendable, CustomStringConvertible {
        let rawValue: UInt8

        /// Bytes were read: `bytes`.
        public static let read = Kind(rawValue: 0)
        /// Bytes were written: `bytes`.
        public static let wrote = Kind(rawValue: 1)
        /// A read returned 0: the end of the stream.
        public static let end = Kind(rawValue: 2)
        /// A read failed with `ioError`.
        public static let readFailed = Kind(rawValue: 3)
        /// A write failed with `ioError`.
        public static let writeFailed = Kind(rawValue: 4)

        public var description: String {
            let names = ["read", "wrote", "end", "readFailed", "writeFailed"]
            return Int(rawValue) < names.count ? names[Int(rawValue)] : "code \(rawValue)"
        }
    }

    init(_ kind: Kind, bytes: [UInt8]? = nil, ioError: IOError? = nil) {
        self.kind = kind
        self.bytes = bytes
        self.ioError = ioError
    }

    /// Bytes were read: `bytes`.
    public static func read(_ bytes: [UInt8]) -> DebugStreamEvent { DebugStreamEvent(.read, bytes: bytes) }
    /// Bytes were written: `bytes`.
    public static func wrote(_ bytes: [UInt8]) -> DebugStreamEvent { DebugStreamEvent(.wrote, bytes: bytes) }
    /// A read returned 0: the end of the stream.
    public static let end = DebugStreamEvent(.end)
    /// A read failed with `ioError`.
    public static func readFailed(_ ioError: IOError) -> DebugStreamEvent { DebugStreamEvent(.readFailed, ioError: ioError) }
    /// A write failed with `ioError`.
    public static func writeFailed(_ ioError: IOError) -> DebugStreamEvent { DebugStreamEvent(.writeFailed, ioError: ioError) }

    public var description: String {
        switch kind {
        case .read: "read \(bytes!.count) bytes: \(debugPreview(bytes!))"
        case .wrote: "wrote \(bytes!.count) bytes: \(debugPreview(bytes!))"
        case .end: "end of stream"
        case .readFailed: "read failed: \(ioError!)"
        case .writeFailed: "write failed: \(ioError!)"
        default: "\(kind)"
        }
    }
}
