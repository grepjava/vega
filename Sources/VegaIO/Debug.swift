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
    public enum Event: Sendable, CustomStringConvertible {
        case read([UInt8])
        case wrote([UInt8])
        /// A read returned 0: the end of the stream.
        case end
        case readFailed(IOError)
        case writeFailed(IOError)

        public var description: String {
            switch self {
            case .read(let b): "read \(b.count) bytes: \(DebugStream.preview(b))"
            case .wrote(let b): "wrote \(b.count) bytes: \(DebugStream.preview(b))"
            case .end: "end of stream"
            case .readFailed(let e): "read failed: \(e)"
            case .writeFailed(let e): "write failed: \(e)"
            }
        }
    }

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

    public consuming func intoStream() -> Stream {
        stream
    }

    /// The first bytes as text where they're printable, escaped where not.
    static func preview(_ bytes: [UInt8], limit: Int = 64) -> String {
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
}

extension DebugStream: Sendable where Stream: Sendable & ~Copyable {}

extension String {
    fileprivate func leftPadded(_ width: Int) -> String {
        count >= width ? self : String(repeating: "0", count: width - count) + self
    }
}
