//===----------------------------------------------------------------------===//
// Frame codec and UTF-8 validation.
//
// These are the pieces where a wrong answer is a security or interoperability
// failure rather than a visible crash: a frame the peer can desynchronise, or
// a text message that is not valid UTF-8.
//===----------------------------------------------------------------------===//

import Testing

@testable import VegaWire
import VegaWebSocketCore

private func withBytes<R>(_ bytes: [UInt8], _ body: (UnsafePointer<UInt8>, Int) -> R) -> R {
    bytes.withUnsafeBufferPointer { body($0.baseAddress!, $0.count) }
}

@Suite("WebSocket framing")
struct WebSocketFramingTests {

    @Test("a short masked text frame parses")
    func shortFrame() {
        // FIN + text, masked, 5 bytes, key 01020304.
        let bytes: [UInt8] = [0x81, 0x85, 1, 2, 3, 4, 0, 0, 0, 0, 0]
        withBytes(bytes) { p, n in
            guard case .header(let h) = WebSocketCodec.parseHeader(p, n, maxPayload: 1 << 20) else {
                Issue.record("expected a header")
                return
            }
            #expect(h.fin)
            #expect(h.opcode == .text)
            #expect(h.masked)
            #expect(h.payloadLength == 5)
            #expect(h.headerLength == 6)
            #expect(h.totalLength == 11)
        }
    }

    @Test("a 16-bit extended length parses")
    func extendedLength16() {
        var bytes: [UInt8] = [0x82, 0xFE, 0x01, 0x00, 9, 9, 9, 9]
        bytes.append(contentsOf: [UInt8](repeating: 0, count: 256))
        withBytes(bytes) { p, n in
            guard case .header(let h) = WebSocketCodec.parseHeader(p, n, maxPayload: 1 << 20) else {
                Issue.record("expected a header")
                return
            }
            #expect(h.payloadLength == 256)
            #expect(h.headerLength == 8)
        }
    }

    @Test("a 64-bit extended length parses")
    func extendedLength64() {
        let bytes: [UInt8] = [0x82, 0xFF, 0, 0, 0, 0, 0, 1, 0, 0, 1, 2, 3, 4]
        withBytes(bytes) { p, n in
            guard case .header(let h) = WebSocketCodec.parseHeader(p, n, maxPayload: 1 << 24) else {
                Issue.record("expected a header")
                return
            }
            #expect(h.payloadLength == 65536)
            #expect(h.headerLength == 14)
        }
    }

    @Test("a length in a longer form than it needs is a protocol error")
    func nonMinimalLength() {
        // 125 fits in the seven bits of the first length byte.
        let short: [UInt8] = [0x82, 0xFE, 0x00, 0x7D, 1, 2, 3, 4]
        // 65535 fits in sixteen.
        let medium: [UInt8] = [0x82, 0xFF, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 1, 2, 3, 4]
        for bytes in [short, medium] {
            withBytes(bytes) { p, n in
                guard case .failure(.protocolError) = WebSocketCodec.parseHeader(p, n, maxPayload: 1 << 24) else {
                    Issue.record("expected a protocol error for \(bytes.prefix(10))")
                    return
                }
            }
        }
        // The smallest lengths that do need each form still parse.
        let least16: [UInt8] = [0x82, 0xFE, 0x00, 0x7E, 1, 2, 3, 4]
        withBytes(least16) { p, n in
            guard case .header(let h) = WebSocketCodec.parseHeader(p, n, maxPayload: 1 << 24) else {
                Issue.record("expected a header")
                return
            }
            #expect(h.payloadLength == 126)
        }
    }

    @Test("a truncated header asks for more rather than guessing")
    func truncated() {
        for prefix in 0..<6 {
            let bytes = [UInt8](repeating: 0x81, count: prefix)
            withBytes(bytes) { p, n in
                if case .needMore = WebSocketCodec.parseHeader(p, n, maxPayload: 1024) {
                    return
                }
                if n == 0 { return }
                Issue.record("expected needMore for a \(n)-byte header")
            }
        }
    }

    @Test("a reserved bit is a protocol error")
    func reservedBits() {
        let bytes: [UInt8] = [0xC1, 0x80, 0, 0, 0, 0]
        withBytes(bytes) { p, n in
            guard case .failure(.protocolError) = WebSocketCodec.parseHeader(
                p, n, maxPayload: 1024) else {
                Issue.record("a set RSV bit must be refused")
                return
            }
        }
    }

    @Test("an unknown opcode is a protocol error")
    func unknownOpcode() {
        let bytes: [UInt8] = [0x83, 0x80, 0, 0, 0, 0]
        withBytes(bytes) { p, n in
            guard case .failure(.protocolError) = WebSocketCodec.parseHeader(
                p, n, maxPayload: 1024) else {
                Issue.record("opcode 3 is not defined and must be refused")
                return
            }
        }
    }

    @Test("a fragmented control frame is refused")
    func fragmentedControl() {
        // Close, FIN clear.
        let bytes: [UInt8] = [0x08, 0x80, 0, 0, 0, 0]
        withBytes(bytes) { p, n in
            guard case .failure(.protocolError) = WebSocketCodec.parseHeader(
                p, n, maxPayload: 1024) else {
                Issue.record("a control frame may not be fragmented")
                return
            }
        }
    }

    @Test("an oversized control frame is refused")
    func oversizedControl() {
        // Ping with a 126-byte payload: control frames cap at 125.
        let bytes: [UInt8] = [0x89, 0xFE, 0x00, 0x7E, 0, 0, 0, 0]
        withBytes(bytes) { p, n in
            guard case .failure(.protocolError) = WebSocketCodec.parseHeader(
                p, n, maxPayload: 1 << 20) else {
                Issue.record("a control frame is limited to 125 bytes")
                return
            }
        }
    }

    @Test("a payload past the message limit is refused before it is buffered")
    func tooLarge() {
        let bytes: [UInt8] = [0x82, 0xFE, 0xFF, 0xFF, 0, 0, 0, 0]
        withBytes(bytes) { p, n in
            guard case .failure(.messageTooBig) = WebSocketCodec.parseHeader(
                p, n, maxPayload: 1024) else {
                Issue.record("the limit must be applied to the declared length")
                return
            }
        }
    }

    @Test("a 64-bit length with the high bit set is refused")
    func negativeLength() {
        let bytes: [UInt8] = [0x82, 0xFF, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        withBytes(bytes) { p, n in
            guard case .failure(.protocolError) = WebSocketCodec.parseHeader(
                p, n, maxPayload: Int.max) else {
                Issue.record("the most significant length bit must be zero")
                return
            }
        }
    }

    @Test("unmasking is its own inverse")
    func unmaskRoundTrip() {
        let plain: [UInt8] = Array("the quick brown fox".utf8)
        let mask: (UInt8, UInt8, UInt8, UInt8) = (0x37, 0xFA, 0x21, 0x3D)
        var masked = [UInt8](repeating: 0, count: plain.count)
        var back = [UInt8](repeating: 0, count: plain.count)
        plain.withUnsafeBufferPointer { src in
            masked.withUnsafeMutableBufferPointer { dst in
                WebSocketCodec.unmask(dst.baseAddress!, src.baseAddress!, src.count, mask)
            }
        }
        #expect(masked != plain)
        masked.withUnsafeBufferPointer { src in
            back.withUnsafeMutableBufferPointer { dst in
                WebSocketCodec.unmask(dst.baseAddress!, src.baseAddress!, src.count, mask)
            }
        }
        #expect(back == plain)
    }

    @Test("a written frame parses back to what went in")
    func writeThenParse() {
        var buf = ByteBuffer()
        defer { buf.destroy() }
        let payload: [UInt8] = Array(repeating: 0x41, count: 300)
        payload.withUnsafeBufferPointer {
            WebSocketCodec.writeFrame(&buf, opcode: .binary, fin: true,
                                      payload: $0.baseAddress!, length: $0.count)
        }
        let span = buf.readableSpan
        guard case .header(let h) = WebSocketCodec.parseHeader(
            span.base, span.count, maxPayload: 1 << 20) else {
            Issue.record("expected a header")
            return
        }
        #expect(h.fin)
        #expect(h.opcode == .binary)
        // A server frame must never be masked.
        #expect(!h.masked)
        #expect(h.payloadLength == 300)
        #expect(h.totalLength == span.count)
    }

    @Test("a close frame carries its code and reason")
    func closeFrame() {
        var buf = ByteBuffer()
        defer { buf.destroy() }
        let reason: [UInt8] = Array("bye".utf8)
        reason.withUnsafeBufferPointer {
            WebSocketCodec.writeClose(&buf, code: 1001,
                                      reason: $0.baseAddress!, reasonLength: $0.count)
        }
        let span = buf.readableSpan
        guard case .header(let h) = WebSocketCodec.parseHeader(
            span.base, span.count, maxPayload: 1024) else {
            Issue.record("expected a header")
            return
        }
        #expect(h.opcode == .close)
        #expect(h.payloadLength == 5)
        let body = span.base + h.headerLength
        #expect(Int(body[0]) << 8 | Int(body[1]) == 1001)
        #expect(body[2] == UInt8(ascii: "b"))
    }

    @Test("codes reserved for local reporting are never sent")
    func closeCodeFilter() {
        #expect(WebSocketCodec.isSendableCloseCode(1000))
        #expect(WebSocketCodec.isSendableCloseCode(1009))
        #expect(WebSocketCodec.isSendableCloseCode(4000))
        #expect(WebSocketCodec.isSendableCloseCode(1014))
        #expect(!WebSocketCodec.isSendableCloseCode(1004))
        #expect(!WebSocketCodec.isSendableCloseCode(1015))
        #expect(!WebSocketCodec.isSendableCloseCode(1016))
        #expect(!WebSocketCodec.isSendableCloseCode(1005))
        #expect(!WebSocketCodec.isSendableCloseCode(1006))
        #expect(!WebSocketCodec.isSendableCloseCode(999))
        #expect(!WebSocketCodec.isSendableCloseCode(2000))
        #expect(!WebSocketCodec.isSendableCloseCode(5000))
    }
}

@Suite("UTF-8 validation")
struct UTF8ValidatorTests {

    private func accepts(_ bytes: [UInt8]) -> Bool {
        var v = UTF8Validator()
        let ok = withBytes(bytes) { v.feed($0, $1) }
        return ok && v.isComplete
    }

    @Test("well-formed text is accepted")
    func valid() {
        #expect(accepts(Array("hello".utf8)))
        #expect(accepts(Array("héllo ☃ 𝄞".utf8)))
        #expect(accepts([]))
    }

    @Test("a truncated sequence is incomplete rather than valid")
    func truncated() {
        var v = UTF8Validator()
        let bytes: [UInt8] = [0xE2, 0x98]      // two thirds of a snowman
        #expect(withBytes(bytes) { v.feed($0, $1) })
        #expect(!v.isComplete)
    }

    @Test("a split sequence validates across feeds")
    func split() {
        var v = UTF8Validator()
        let all: [UInt8] = Array("☃".utf8)
        #expect(withBytes([all[0]]) { v.feed($0, $1) })
        #expect(withBytes([all[1], all[2]]) { v.feed($0, $1) })
        #expect(v.isComplete)
    }

    @Test("overlong encodings are refused")
    func overlong() {
        #expect(!accepts([0xC0, 0x80]))           // overlong NUL
        #expect(!accepts([0xC1, 0xBF]))
        #expect(!accepts([0xE0, 0x80, 0x80]))
        #expect(!accepts([0xF0, 0x80, 0x80, 0x80]))
    }

    @Test("surrogates and out-of-range code points are refused")
    func surrogates() {
        #expect(!accepts([0xED, 0xA0, 0x80]))     // U+D800
        #expect(!accepts([0xF4, 0x90, 0x80, 0x80]))   // beyond U+10FFFF
        #expect(!accepts([0xF5, 0x80, 0x80, 0x80]))
    }

    @Test("stray continuation bytes are refused")
    func strayContinuation() {
        #expect(!accepts([0x80]))
        #expect(!accepts([0xE2, 0x28, 0xA1]))
    }
}
