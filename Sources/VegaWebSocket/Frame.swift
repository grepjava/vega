// RFC 6455 framing, ported from aviancore. Strict wherever leniency would
// let a peer desynchronise the stream:
//   * a client's frames must be masked and a server's must not be
//   * a control frame is at most 125 bytes and never fragmented
//   * RSV bits must be clear, but RSV1 on a message's first frame once
//     permessage-deflate is agreed
//   * an unknown opcode is a protocol error, not something to skip
//   * lengths must use their shortest encoding

import Vega
import VegaIO

public enum WebSocketOpcode: UInt8, Sendable {
    case continuation = 0x0
    case text = 0x1
    case binary = 0x2
    case close = 0x8
    case ping = 0x9
    case pong = 0xA

    public var isControl: Bool { rawValue & 0x8 != 0 }
}

/// A close status code (RFC 6455 section 7.4).
public struct WebSocketCloseCode: RawRepresentable, Hashable, Sendable, CustomStringConvertible {
    public let rawValue: UInt16
    public init(rawValue: UInt16) { self.rawValue = rawValue }

    public static let normal = WebSocketCloseCode(rawValue: 1000)
    public static let goingAway = WebSocketCloseCode(rawValue: 1001)
    public static let protocolError = WebSocketCloseCode(rawValue: 1002)
    public static let unsupportedData = WebSocketCloseCode(rawValue: 1003)
    /// Reported, never sent: the peer's close frame had no code.
    public static let noStatus = WebSocketCloseCode(rawValue: 1005)
    /// Reported, never sent: the connection ended without a close frame.
    public static let abnormal = WebSocketCloseCode(rawValue: 1006)
    public static let invalidPayload = WebSocketCloseCode(rawValue: 1007)
    public static let policyViolation = WebSocketCloseCode(rawValue: 1008)
    public static let messageTooBig = WebSocketCloseCode(rawValue: 1009)
    public static let internalError = WebSocketCloseCode(rawValue: 1011)

    /// Whether the code may go on the wire: 1004 is reserved, and 1005,
    /// 1006 and 1015 are only for reporting.
    public var isSendable: Bool {
        switch rawValue {
        case 1004, 1005, 1006, 1015: false
        case 1000...1014, 3000...4999: true
        default: false
        }
    }

    public var description: String { String(rawValue) }
}

/// One frame, payload unmasked.
public struct WebSocketFrame: Sendable, Equatable {
    public var fin: Bool
    public var opcode: WebSocketOpcode
    public var payload: [UInt8]
    /// RSV1: the message this frame starts is compressed (permessage-deflate).
    public var compressed: Bool

    public init(fin: Bool = true, opcode: WebSocketOpcode, payload: [UInt8] = [], compressed: Bool = false) {
        self.fin = fin
        self.opcode = opcode
        self.payload = payload
        self.compressed = compressed
    }
}

/// Which end of the connection this is: a client masks what it sends and
/// the server requires it.
public enum WebSocketRole: Sendable {
    case client, server
}

/// Frames from and to a byte stream.
public struct WebSocketFrameCodec: Decoder, Encoder, Sendable {
    public typealias Item = WebSocketFrame

    public var role: WebSocketRole
    /// A longer frame fails with `.messageTooBig` before it's buffered.
    public var maxFrameSize: Int
    /// Whether RSV1 may mark a message's first frame compressed: once
    /// permessage-deflate is agreed.
    public var acceptsCompressed: Bool

    public init(role: WebSocketRole, maxFrameSize: Int = 16 << 20, acceptsCompressed: Bool = false) {
        self.role = role
        self.maxFrameSize = maxFrameSize
        self.acceptsCompressed = acceptsCompressed
    }

    /// The next frame, or nil if `b` doesn't hold all of it.
    public func decodeFrame(_ b: UnsafeRawBufferPointer) throws(WebSocketError) -> (item: WebSocketFrame, consumed: Int)? {
        guard b.count >= 2 else { return nil }
        let b0 = b[0], b1 = b[1]
        // RSV2 and RSV3 are no extension's; RSV1 is permessage-deflate's,
        // on the first frame of a data message.
        guard b0 & 0x30 == 0, let opcode = WebSocketOpcode(rawValue: b0 & 0x0F) else {
            throw .protocolViolation(.protocolError)
        }
        let compressed = b0 & 0x40 != 0
        if compressed && (!acceptsCompressed || opcode.isControl || opcode == .continuation) {
            throw .protocolViolation(.protocolError)
        }
        let fin = b0 & 0x80 != 0
        let masked = b1 & 0x80 != 0
        // The server needs masked frames; the client gets unmasked ones.
        guard masked == (role == .server) else { throw .protocolViolation(.protocolError) }
        var length = Int(b1 & 0x7F)
        var offset = 2
        if length == 126 {
            guard b.count >= 4 else { return nil }
            length = Int(b[2]) << 8 | Int(b[3])
            // Only the shortest encoding is valid (RFC 6455 section 5.2).
            guard length >= 126 else { throw .protocolViolation(.protocolError) }
            offset = 4
        } else if length == 127 {
            guard b.count >= 10 else { return nil }
            guard b[2] & 0x80 == 0 else { throw .protocolViolation(.protocolError) }
            length = (2..<10).reduce(0) { $0 << 8 | Int(b[$1]) }
            guard length > 0xFFFF else { throw .protocolViolation(.protocolError) }
            offset = 10
        }
        if opcode.isControl {
            // Short and whole, so no payload slips past the message limit.
            guard length <= 125, fin else { throw .protocolViolation(.protocolError) }
        } else if length > maxFrameSize {
            throw .protocolViolation(.messageTooBig)
        }
        var mask: (UInt8, UInt8, UInt8, UInt8) = (0, 0, 0, 0)
        if masked {
            guard b.count >= offset + 4 else { return nil }
            mask = (b[offset], b[offset + 1], b[offset + 2], b[offset + 3])
            offset += 4
        }
        guard b.count - offset >= length else { return nil }
        var payload = Array(b[offset..<offset + length])
        if masked { applyMask(mask, to: &payload) }
        return (WebSocketFrame(fin: fin, opcode: opcode, payload: payload, compressed: compressed), offset + length)
    }

    public mutating func decode(_ bytes: UnsafeRawBufferPointer) throws(CodecError) -> (item: WebSocketFrame, consumed: Int)? {
        do throws(WebSocketError) { return try decodeFrame(bytes) } catch { throw .malformed("\(error)") }
    }

    /// Append the frame, masked with a fresh key if this is a client.
    public mutating func encode(_ frame: WebSocketFrame, into buffer: inout IOBuffer) throws(CodecError) {
        write(frame, into: &buffer)
    }

    func write(_ frame: WebSocketFrame, into buffer: inout IOBuffer) {
        var header: [UInt8] = [(frame.fin ? 0x80 : 0) | (frame.compressed ? 0x40 : 0) | frame.opcode.rawValue]
        let n = frame.payload.count
        let maskBit: UInt8 = role == .client ? 0x80 : 0
        if n < 126 {
            header.append(maskBit | UInt8(n))
        } else if n <= 0xFFFF {
            header += [maskBit | 126, UInt8(n >> 8), UInt8(truncatingIfNeeded: n)]
        } else {
            header.append(maskBit | 127)
            for shift in stride(from: 56, through: 0, by: -8) { header.append(UInt8(truncatingIfNeeded: n >> shift)) }
        }
        if role == .client {
            var rng = SystemRandomNumberGenerator()
            let key = rng.next() as UInt32
            let mask = (UInt8(key >> 24), UInt8(truncatingIfNeeded: key >> 16),
                        UInt8(truncatingIfNeeded: key >> 8), UInt8(truncatingIfNeeded: key))
            header += [mask.0, mask.1, mask.2, mask.3]
            var payload = frame.payload
            applyMask(mask, to: &payload)
            header.withUnsafeBytes { buffer.write($0) }
            payload.withUnsafeBytes { buffer.write($0) }
        } else {
            header.withUnsafeBytes { buffer.write($0) }
            frame.payload.withUnsafeBytes { buffer.write($0) }
        }
    }
}

/// XOR with the four-byte key, which masking and unmasking both are.
func applyMask(_ mask: (UInt8, UInt8, UInt8, UInt8), to bytes: inout [UInt8]) {
    let key = [mask.0, mask.1, mask.2, mask.3]
    bytes.withUnsafeMutableBufferPointer { p in
        for i in p.indices { p[i] ^= key[i & 3] }
    }
}

/// UTF-8 checked a piece at a time, as a text message arrives in frames.
/// Overlong forms, surrogates and values past U+10FFFF all fail.
struct UTF8Validator {
    private var remaining = 0
    private var codepoint: UInt32 = 0
    private var minimum: UInt32 = 0

    /// Whether no sequence is left open.
    var isComplete: Bool { remaining == 0 }

    /// false as soon as the bytes can't be valid.
    mutating func feed(_ bytes: [UInt8]) -> Bool {
        for c in bytes {
            if remaining == 0 {
                switch c {
                case 0..<0x80: continue
                case 0xC2...0xDF: (remaining, minimum, codepoint) = (1, 0x80, UInt32(c & 0x1F))
                case 0xE0...0xEF: (remaining, minimum, codepoint) = (2, 0x800, UInt32(c & 0x0F))
                case 0xF0...0xF4: (remaining, minimum, codepoint) = (3, 0x10000, UInt32(c & 0x07))
                default: return false
                }
                continue
            }
            guard c & 0xC0 == 0x80 else { return false }
            codepoint = codepoint << 6 | UInt32(c & 0x3F)
            remaining -= 1
            // Fail as early as the prefix allows: a surrogate or an
            // out-of-range value is plain from its first two bytes.
            let bound = codepoint << (6 * UInt32(remaining))
            if bound > 0x10FFFF || (bound >= 0xD800 && bound <= 0xDFFF) { return false }
            if remaining == 0 && codepoint < minimum { return false }
        }
        return true
    }
}
