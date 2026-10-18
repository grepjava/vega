import Vega
import VegaIO
import VegaHTTP2Core

/// One HTTP/2 frame. Padding is removed when reading and never added when
/// writing; PRIORITY information is read and ignored (RFC 9113 deprecates it).
package struct HTTP2Frame: Sendable, Equatable {
    package var streamID: UInt32
    package var payload: Payload

    package enum Payload: Sendable, Equatable {
        /// `flowLength` is what the frame counts against flow control: the
        /// data plus any padding.
        case data([UInt8], endStream: Bool, flowLength: Int)
        /// A header block fragment; CONTINUATION frames follow unless
        /// `endHeaders`.
        case headers([UInt8], endStream: Bool, endHeaders: Bool)
        case priority
        case rstStream(HTTP2ErrorCode)
        case settings([(HTTP2Setting, UInt32)])
        case settingsAck
        case pushPromise(promisedStreamID: UInt32, [UInt8], endHeaders: Bool)
        case ping(UInt64, ack: Bool)
        case goaway(lastStreamID: UInt32, HTTP2ErrorCode, debug: [UInt8])
        case windowUpdate(UInt32)
        case continuation([UInt8], endHeaders: Bool)
        /// A frame type this end doesn't know, which is ignored.
        case unknown(type: UInt8)

        package static func == (a: Payload, b: Payload) -> Bool {
            switch (a, b) {
            case let (.data(x, e1, _), .data(y, e2, _)): x == y && e1 == e2
            case let (.headers(x, s1, h1), .headers(y, s2, h2)): x == y && s1 == s2 && h1 == h2
            case (.priority, .priority), (.settingsAck, .settingsAck): true
            case let (.rstStream(x), .rstStream(y)): x == y
            case let (.settings(x), .settings(y)): x.elementsEqual(y) { $0.0 == $1.0 && $0.1 == $1.1 }
            case let (.pushPromise(i, x, h1), .pushPromise(j, y, h2)): i == j && x == y && h1 == h2
            case let (.ping(x, a1), .ping(y, a2)): x == y && a1 == a2
            case let (.goaway(i, c1, d1), .goaway(j, c2, d2)): i == j && c1 == c2 && d1 == d2
            case let (.windowUpdate(x), .windowUpdate(y)): x == y
            case let (.continuation(x, h1), .continuation(y, h2)): x == y && h1 == h2
            case let (.unknown(x), .unknown(y)): x == y
            default: false
            }
        }
    }

    package init(streamID: UInt32, payload: Payload) {
        self.streamID = streamID
        self.payload = payload
    }

    package static let headerSize = HTTP2FrameHeader.size
    package static let defaultMaxFrameSize = HTTP2FrameHeader.defaultMaxFrameSize
    package static let defaultWindowSize = HTTP2FrameHeader.defaultInitialWindowSize
    package static let maxWindowSize = HTTP2FrameHeader.maxWindowSize

    /// The client connection preface (RFC 9113 section 3.4).
    package static var preface: [UInt8] { HTTP2.preface }
}

/// Why a frame couldn't be read: a connection error with this code.
struct FrameError: Error {
    var code: HTTP2ErrorCode
}

/// HTTP/2 frames from and to a byte stream.
///
/// Decoding checks what can be checked of one frame alone: its size, its
/// padding, and the lengths and stream rules its type requires.
package struct HTTP2FrameCodec: Decoder, Encoder, Sendable {
    package typealias Item = HTTP2Frame

    /// Longer frames are a FRAME_SIZE_ERROR: the SETTINGS_MAX_FRAME_SIZE
    /// this end advertised.
    package var maxFrameSize: Int

    package init(maxFrameSize: Int = HTTP2Frame.defaultMaxFrameSize) {
        self.maxFrameSize = maxFrameSize
    }

    func decodeFrame(_ b: UnsafeRawBufferPointer) throws(FrameError) -> (item: HTTP2Frame, consumed: Int)? {
        guard b.count >= HTTP2Frame.headerSize else { return nil }
        let header = HTTP2FrameHeader.parse(b.baseAddress!.assumingMemoryBound(to: UInt8.self))
        let length = header.length, type = header.type, flags = header.flags.rawValue, stream = header.streamID
        guard length <= maxFrameSize else { throw FrameError(code: .frameSizeError) }
        let total = HTTP2Frame.headerSize + length
        guard b.count >= total else { return nil }
        let p = UnsafeRawBufferPointer(rebasing: b[HTTP2Frame.headerSize..<total])
        let payload = try Self.payload(type: type, flags: flags, stream: stream, p)
        return (HTTP2Frame(streamID: stream, payload: payload), total)
    }

    private static func payload(type: UInt8, flags: UInt8, stream: UInt32,
                                _ p: UnsafeRawBufferPointer) throws(FrameError) -> HTTP2Frame.Payload {
        let endStream = flags & 0x1 != 0, endHeaders = flags & 0x4 != 0
        let padded = flags & 0x8 != 0, ack = flags & 0x1 != 0
        func unpadded(_ p: UnsafeRawBufferPointer) throws(FrameError) -> UnsafeRawBufferPointer {
            guard padded else { return p }
            guard !p.isEmpty, Int(p[0]) < p.count else { throw FrameError(code: .protocolError) }
            return UnsafeRawBufferPointer(rebasing: p[1..<p.count - Int(p[0])])
        }
        func u32(_ p: UnsafeRawBufferPointer, _ i: Int) -> UInt32 {
            UInt32(p[i]) << 24 | UInt32(p[i + 1]) << 16 | UInt32(p[i + 2]) << 8 | UInt32(p[i + 3])
        }
        switch type {
        case 0x0:
            guard stream != 0 else { throw FrameError(code: .protocolError) }
            return .data(Array(try unpadded(p)), endStream: endStream, flowLength: p.count)
        case 0x1:
            guard stream != 0 else { throw FrameError(code: .protocolError) }
            var block = try unpadded(p)
            if flags & 0x20 != 0 {
                guard block.count >= 5 else { throw FrameError(code: .frameSizeError) }
                // A stream can't depend on itself (RFC 9113 section 5.3.1).
                guard u32(block, 0) & 0x7FFF_FFFF != stream else { throw FrameError(code: .protocolError) }
                block = UnsafeRawBufferPointer(rebasing: block[5...])
            }
            return .headers(Array(block), endStream: endStream, endHeaders: endHeaders)
        case 0x2:
            guard stream != 0 else { throw FrameError(code: .protocolError) }
            guard p.count == 5 else { throw FrameError(code: .frameSizeError) }
            guard u32(p, 0) & 0x7FFF_FFFF != stream else { throw FrameError(code: .protocolError) }
            return .priority
        case 0x3:
            guard stream != 0 else { throw FrameError(code: .protocolError) }
            guard p.count == 4 else { throw FrameError(code: .frameSizeError) }
            return .rstStream(HTTP2ErrorCode(rawValue: u32(p, 0)))
        case 0x4:
            guard stream == 0 else { throw FrameError(code: .protocolError) }
            if ack {
                guard p.isEmpty else { throw FrameError(code: .frameSizeError) }
                return .settingsAck
            }
            guard p.count % 6 == 0 else { throw FrameError(code: .frameSizeError) }
            var settings: [(HTTP2Setting, UInt32)] = []
            for i in stride(from: 0, to: p.count, by: 6) {
                settings.append((HTTP2Setting(rawValue: UInt16(p[i]) << 8 | UInt16(p[i + 1])), u32(p, i + 2)))
            }
            return .settings(settings)
        case 0x5:
            guard stream != 0 else { throw FrameError(code: .protocolError) }
            let rest = try unpadded(p)
            guard rest.count >= 4 else { throw FrameError(code: .frameSizeError) }
            return .pushPromise(promisedStreamID: u32(rest, 0) & 0x7FFF_FFFF,
                                Array(rest[4...]), endHeaders: endHeaders)
        case 0x6:
            guard stream == 0 else { throw FrameError(code: .protocolError) }
            guard p.count == 8 else { throw FrameError(code: .frameSizeError) }
            return .ping(UInt64(u32(p, 0)) << 32 | UInt64(u32(p, 4)), ack: ack)
        case 0x7:
            guard stream == 0 else { throw FrameError(code: .protocolError) }
            guard p.count >= 8 else { throw FrameError(code: .frameSizeError) }
            return .goaway(lastStreamID: u32(p, 0) & 0x7FFF_FFFF, HTTP2ErrorCode(rawValue: u32(p, 4)),
                           debug: Array(p[8...]))
        case 0x8:
            guard p.count == 4 else { throw FrameError(code: .frameSizeError) }
            return .windowUpdate(u32(p, 0) & 0x7FFF_FFFF)
        case 0x9:
            guard stream != 0 else { throw FrameError(code: .protocolError) }
            return .continuation(Array(p), endHeaders: endHeaders)
        default:
            return .unknown(type: type)
        }
    }

    package mutating func decode(_ bytes: UnsafeRawBufferPointer) throws(CodecError) -> (item: HTTP2Frame, consumed: Int)? {
        do throws(FrameError) { return try decodeFrame(bytes) } catch { throw .malformed("HTTP/2 \(error.code)") }
    }

    package mutating func encode(_ frame: HTTP2Frame, into buffer: inout IOBuffer) throws(CodecError) {
        frame.write(into: &buffer)
    }
}

extension HTTP2Frame {
    /// Append the frame's bytes to `buffer`.
    func write(into buffer: inout IOBuffer) {
        var type: UInt8 = 0, flags: UInt8 = 0
        var body: [UInt8] = []
        func u32(_ v: UInt32) { body += [UInt8(truncatingIfNeeded: v >> 24), UInt8(truncatingIfNeeded: v >> 16),
                                         UInt8(truncatingIfNeeded: v >> 8), UInt8(truncatingIfNeeded: v)] }
        switch payload {
        case .data(let bytes, let end, _):
            // The common case, without copying the payload into `body`.
            writeHeader(length: bytes.count, type: 0, flags: end ? 0x1 : 0, into: &buffer)
            bytes.withUnsafeBytes { buffer.write($0) }
            return
        case .headers(let block, let endStream, let endHeaders):
            type = 0x1
            flags = (endStream ? 0x1 : 0) | (endHeaders ? 0x4 : 0)
            body = block
        case .priority:
            type = 0x2
            body = [0, 0, 0, 0, 15]
        case .rstStream(let code):
            type = 0x3
            u32(code.rawValue)
        case .settings(let settings):
            type = 0x4
            for (id, value) in settings {
                body += [UInt8(id.rawValue >> 8), UInt8(truncatingIfNeeded: id.rawValue)]
                u32(value)
            }
        case .settingsAck:
            type = 0x4
            flags = 0x1
        case .pushPromise(let promised, let block, let endHeaders):
            type = 0x5
            flags = endHeaders ? 0x4 : 0
            u32(promised)
            body += block
        case .ping(let data, let ack):
            type = 0x6
            flags = ack ? 0x1 : 0
            u32(UInt32(truncatingIfNeeded: data >> 32))
            u32(UInt32(truncatingIfNeeded: data))
        case .goaway(let last, let code, let debug):
            type = 0x7
            u32(last)
            u32(code.rawValue)
            body += debug
        case .windowUpdate(let increment):
            type = 0x8
            u32(increment)
        case .continuation(let block, let endHeaders):
            type = 0x9
            flags = endHeaders ? 0x4 : 0
            body = block
        case .unknown(let t):
            type = t
        }
        writeHeader(length: body.count, type: type, flags: flags, into: &buffer)
        body.withUnsafeBytes { buffer.write($0) }
    }

    private func writeHeader(length: Int, type: UInt8, flags: UInt8, into buffer: inout IOBuffer) {
        let header: [UInt8] = [
            UInt8(truncatingIfNeeded: length >> 16), UInt8(truncatingIfNeeded: length >> 8),
            UInt8(truncatingIfNeeded: length), type, flags,
            UInt8(truncatingIfNeeded: streamID >> 24) & 0x7F, UInt8(truncatingIfNeeded: streamID >> 16),
            UInt8(truncatingIfNeeded: streamID >> 8), UInt8(truncatingIfNeeded: streamID),
        ]
        header.withUnsafeBytes { buffer.write($0) }
    }
}
