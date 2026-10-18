// RFC 6455 framing, on VegaWire's frame-header parser. Strict wherever
// leniency would let a peer desynchronise the stream:
//   * a client's frames must be masked and a server's must not be
//   * a control frame is at most 125 bytes and never fragmented
//   * RSV bits must be clear, but RSV1 on a message's first frame once
//     permessage-deflate is agreed
//   * an unknown opcode is a protocol error, not something to skip
//   * lengths must use their shortest encoding

import Vega
import VegaIO
import VegaWire
@_exported import VegaWebSocketCore

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

    /// The next frame, or nil if `b` doesn't hold all of it. The header is
    /// VegaWire's `WebSocketCodec.parseHeader`; this adds the role's masking
    /// rule and copies the payload out, unmasked.
    public func decodeFrame(_ b: UnsafeRawBufferPointer) throws(WebSocketError) -> (item: WebSocketFrame, consumed: Int)? {
        guard b.count >= 2 else { return nil }
        let base = b.baseAddress!.assumingMemoryBound(to: UInt8.self)
        let head: WebSocketFrameHeader
        switch WebSocketCodec.parseHeader(base, b.count, maxPayload: maxFrameSize, allowRSV1: acceptsCompressed) {
        case .needMore: return nil
        case .failure(.messageTooBig): throw .protocolViolation(.messageTooBig)
        case .failure: throw .protocolViolation(.protocolError)
        case .header(let h): head = h
        }
        // The server needs masked frames; the client gets unmasked ones.
        guard head.masked == (role == .server) else { throw .protocolViolation(.protocolError) }
        guard b.count >= head.totalLength else { return nil }
        let length = head.payloadLength
        let payload = [UInt8](unsafeUninitializedCapacity: length) { dst, n in
            if length > 0 {
                let src = base + head.headerLength
                if head.masked {
                    WebSocketCodec.unmask(dst.baseAddress!, src, length, head.mask)
                } else {
                    dst.baseAddress!.update(from: src, count: length)
                }
            }
            n = length
        }
        let opcode = WebSocketOpcode(rawValue: head.opcode.rawValue)!
        return (WebSocketFrame(fin: head.fin, opcode: opcode, payload: payload, compressed: head.rsv1), head.totalLength)
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
    bytes.withUnsafeMutableBufferPointer { p in
        guard let base = p.baseAddress else { return }
        WebSocketCodec.unmask(base, base, p.count, mask)
    }
}

extension UTF8Validator {
    /// VegaWire's validator over a frame's payload.
    mutating func feed(_ bytes: [UInt8]) -> Bool {
        bytes.withUnsafeBufferPointer { b in
            guard let base = b.baseAddress else { return true }
            return feed(base, b.count)
        }
    }
}
