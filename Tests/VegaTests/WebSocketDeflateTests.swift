import Testing
import Vega
import VegaIO
import VegaHTTP1
@testable import VegaWebSocket
import VegaTest

private let zlib = WebSocketConfiguration(compression: true).compression

/// The server's answer to these Sec-WebSocket-Extensions values, or nil.
private func answer(_ values: String...) -> String? {
    PerMessageDeflate.negotiate(values)?.headerValue
}

/// A client and an echoing server, with these configurations; the client's
/// end runs `body`.
private func withPair<T: Sendable>(
    server serverConfiguration: WebSocketConfiguration,
    client clientConfiguration: WebSocketConfiguration,
    _ body: @escaping @Sendable (inout WebSocket<DuplexStream>) async throws -> T
) throws -> (T, PerMessageDeflate?, WebSocketError?) {
    let rt = Runtime(workers: 2)
    defer { rt.shutdown() }
    return try rt.block {
        let pair = duplex()
        let server = rt.spawn(with: pair.second) { stream async -> (PerMessageDeflate?, WebSocketError?) in
            guard var ws = try? await WebSocket.accept(stream, configuration: serverConfiguration) else { return (nil, nil) }
            do throws(WebSocketError) {
                while let m = try await ws.receive() { try await ws.send(m) }
                return (ws.deflate, nil)
            } catch {
                return (ws.deflate, error)
            }
        }
        var ws = try await WebSocket.connect(pair.first, host: "vega.test", target: "/", configuration: clientConfiguration)
        let result = try await body(&ws)
        try? await ws.close()
        let (deflate, error) = await server.value
        return (result, deflate, error)
    }
}

@Suite struct PerMessageDeflateNegotiationTests {
    @Test func plainOffer() {
        #expect(answer("permessage-deflate") == "permessage-deflate")
        #expect(answer("PerMessage-Deflate") == "permessage-deflate")
    }

    /// A client that may be told a window is told 12 bits, or less if it asked.
    @Test func clientWindow() {
        #expect(answer("permessage-deflate; client_max_window_bits") == "permessage-deflate; client_max_window_bits=12")
        #expect(answer("permessage-deflate; client_max_window_bits=15") == "permessage-deflate; client_max_window_bits=12")
        #expect(answer("permessage-deflate; client_max_window_bits=10") == "permessage-deflate; client_max_window_bits=10")
        #expect(answer("permessage-deflate; client_max_window_bits=\"9\"") == "permessage-deflate; client_max_window_bits=9")
    }

    /// A server window limit is agreed to, but not one zlib can't keep.
    @Test func serverWindow() {
        #expect(answer("permessage-deflate; server_max_window_bits=10") == "permessage-deflate; server_max_window_bits=10")
        #expect(answer("permessage-deflate; server_max_window_bits=8") == nil)
        #expect(answer("permessage-deflate; server_max_window_bits") == nil)
        #expect(answer("permessage-deflate; server_max_window_bits=16") == nil)
        #expect(answer("permessage-deflate; server_max_window_bits=09") == nil)
    }

    @Test func noContextTakeover() {
        #expect(answer("permessage-deflate; client_no_context_takeover; server_no_context_takeover")
                == "permessage-deflate; server_no_context_takeover; client_no_context_takeover")
        #expect(answer("permessage-deflate; server_no_context_takeover=1") == nil)
    }

    /// An offer that can't be honoured is passed over for the next.
    @Test func fallsThrough() {
        #expect(answer("permessage-deflate; x=1, permessage-deflate") == "permessage-deflate")
        #expect(answer("x-webkit-deflate-frame", "permessage-deflate; client_max_window_bits")
                == "permessage-deflate; client_max_window_bits=12")
        #expect(answer("permessage-deflate; server_no_context_takeover; server_no_context_takeover") == nil)
        #expect(answer("permessage-deflate;;") == nil)
        #expect(answer("x-webkit-deflate-frame") == nil)
        #expect(answer("") == nil)
    }

    /// What a client makes of the server's answer.
    @Test func clientReadsTheAnswer() throws {
        #expect(try PerMessageDeflate.accepted([]) == nil)
        var expected = PerMessageDeflate()
        expected.serverMaxWindowBits = 10
        expected.clientNoContextTakeover = true
        #expect(try PerMessageDeflate.accepted(["permessage-deflate; server_max_window_bits=10; client_no_context_takeover"]) == expected)
        #expect(throws: WebSocketError.self) { try PerMessageDeflate.accepted(["permessage-deflate; x=1"]) }
        #expect(throws: WebSocketError.self) { try PerMessageDeflate.accepted(["permessage-deflate", "permessage-deflate"]) }
        #expect(throws: WebSocketError.self) { try PerMessageDeflate.accepted(["x-webkit-deflate-frame"]) }
        #expect(throws: WebSocketError.self) { try PerMessageDeflate.accepted(["permessage-deflate; client_max_window_bits"]) }
    }
}

@Suite(.enabled(if: zlib, "no zlib here"))
struct PerMessageDeflateTests {
    /// RFC 7692 section 7.2.3's examples.
    @Test func rfcExamples() throws {
        let hello = Array("Hello".utf8)
        let context = try #require(DeflateContext(PerMessageDeflate(), role: .client))
        #expect(try context.decompress([0xF2, 0x48, 0xCD, 0xC9, 0xC9, 0x07, 0x00], limit: 100) == hello)
        // The same again, with the context taken over: a back-reference.
        #expect(try context.decompress([0xF2, 0x00, 0x11, 0x00, 0x00], limit: 100) == hello)
        // Sent with no compression (a stored block), and with a final block.
        let fresh = try #require(DeflateContext(PerMessageDeflate(), role: .client))
        #expect(try fresh.decompress([0x00, 0x05, 0x00, 0xFA, 0xFF, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x00], limit: 100) == hello)
        #expect(try fresh.decompress([0xF3, 0x48, 0xCD, 0xC9, 0xC9, 0x07, 0x00], limit: 100) == hello)
        #expect(try fresh.decompress([0xF2, 0x48, 0xCD, 0xC9, 0xC9, 0x07, 0x00], limit: 100) == hello)
        #expect(throws: WebSocketError.protocolViolation(.invalidPayload)) {
            try DeflateContext(PerMessageDeflate(), role: .client)!.decompress([0xFF, 0xFF, 0xFF], limit: 100)
        }

        // RSV1 marks a message's first frame, once agreed.
        let frame: [UInt8] = [0xC1, 0x07, 0xF2, 0x48, 0xCD, 0xC9, 0xC9, 0x07, 0x00]
        let decoded = try frame.withUnsafeBytes { b in
            try WebSocketFrameCodec(role: .client, acceptsCompressed: true).decodeFrame(b)
        }
        #expect(decoded?.item.compressed == true)
        #expect(decoded?.item.payload == Array(frame[2...]))
        for refused: ([UInt8], Bool) in [(frame, false), ([0xC0, 0x00], true), ([0xC9, 0x00], true), ([0xE1, 0x00], true)] {
            #expect(throws: WebSocketError.self) {
                try refused.0.withUnsafeBytes { b in
                    try WebSocketFrameCodec(role: .client, acceptsCompressed: refused.1).decodeFrame(b)
                }
            }
        }
    }

    /// Context carried between messages makes a repeat cheap; without it,
    /// each message stands alone.
    @Test func contextTakeover() throws {
        let message = Array(String(repeating: "the same thing, said again. ", count: 20).utf8)
        let carried = try #require(DeflateContext(PerMessageDeflate(), role: .server))
        let first = try #require(carried.compress(message))
        let second = try #require(carried.compress(message))
        #expect(first.count < message.count / 4)
        #expect(second.count < first.count / 2)
        let reader = try #require(DeflateContext(PerMessageDeflate(), role: .client))
        #expect(try reader.decompress(first, limit: 1 << 20) == message)
        #expect(try reader.decompress(second, limit: 1 << 20) == message)

        var none = PerMessageDeflate()
        none.serverNoContextTakeover = true
        let fresh = try #require(DeflateContext(none, role: .server))
        #expect(fresh.compress(message) == first)
        #expect(fresh.compress(message) == first)
        // Short messages go as they are.
        #expect(fresh.compress(Array("hi".utf8)) == nil)
    }

    @Test func echoCompressed() throws {
        let on = WebSocketConfiguration(compression: true)
        let messages: [WebSocketMessage] = [
            .text("short"),
            .text(String(repeating: "compressible text ", count: 1000)),
            .binary(Array(repeating: 7, count: 70_000)),
            .text(String(repeating: "é", count: 40_000)),
            .binary((0..<5000).map { UInt8(truncatingIfNeeded: $0 &* 131) }),
        ]
        let ((got, clientDeflate), serverDeflate, serverError) = try withPair(server: on, client: on) { ws in
            var got: [WebSocketMessage] = []
            for m in messages + messages {
                try await ws.send(m)
                got.append(try #require(try await ws.receive()))
            }
            return (got, ws.deflate)
        }
        #expect(got == messages + messages)
        #expect(clientDeflate?.clientMaxWindowBits == 12)
        #expect(serverDeflate == clientDeflate)
        #expect(serverError == nil)
    }

    /// Either end not wanting it means plain frames.
    @Test func oneSidedIsOff() throws {
        let on = WebSocketConfiguration(compression: true), off = WebSocketConfiguration()
        for (server, client) in [(on, off), (off, on)] {
            let ((got, deflate), serverDeflate, _) = try withPair(server: server, client: client) { ws in
                try await ws.send(.text(String(repeating: "x", count: 1000)))
                return (try await ws.receive(), ws.deflate)
            }
            #expect(got == .text(String(repeating: "x", count: 1000)))
            #expect(deflate == nil)
            #expect(serverDeflate == nil)
        }
    }

    /// A message that inflates past the limit closes with 1009.
    @Test func inflatedSizeIsLimited() throws {
        let server = WebSocketConfiguration(maxMessageSize: 10_000, compression: true)
        let client = WebSocketConfiguration(compression: true)
        let (_, _, serverError) = try withPair(server: server, client: client) { ws in
            try await ws.send(.binary(Array(repeating: 0, count: 1 << 20)))
            _ = try? await ws.receive()
            return ws.closeCode
        }
        #expect(serverError == .protocolViolation(.messageTooBig))
    }
}
