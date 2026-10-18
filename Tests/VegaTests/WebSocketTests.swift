import Testing
import Vega
import VegaIO
import VegaHTTP1
@_spi(Garuda) @testable import VegaWebSocket
@_spi(Garuda) import VegaWire
import VegaTest
@_spi(Garuda) import VegaWebSocketCore

private func hexString(_ bytes: [UInt8]) -> String {
    bytes.map { String($0, radix: 16).count == 1 ? "0" + String($0, radix: 16) : String($0, radix: 16) }.joined()
}

/// A frame's bytes as a peer in `role` would send them.
private func wire(_ frame: WebSocketFrame, from role: WebSocketRole) -> [UInt8] {
    var out = IOBuffer(capacity: 64)
    WebSocketFrameCodec(role: role).write(frame, into: &out)
    return out.withUnsafeBytes { Array($0) }
}

@Suite struct WebSocketFrameTests {
    @Test func handshakeKeys() {
        #expect(hexString(sha1(Array("abc".utf8))) == "a9993e364706816aba3e25717850c26c9cd0d89d")
        #expect(hexString(sha1([])) == "da39a3ee5e6b4b0d3255bfef95601890afd80709")
        #expect(hexString(sha1(Array(String(repeating: "a", count: 1000).utf8))) == "291e9a6c66994949b57ba5e650361e98fc36b1ba")
        // RFC 6455 section 1.3.
        #expect(WebSocketHandshake.acceptValue(for: "dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
        #expect(base64(Array("f".utf8)) == "Zg==")
        #expect(base64(Array("fo".utf8)) == "Zm8=")
        #expect(base64(Array("foo".utf8)) == "Zm9v")
        #expect(decodedBase64Count(WebSocketHandshake.makeKey()) == 16)
        #expect(decodedBase64Count("not base64!!") == nil)
    }

    @Test func roundTrip() throws {
        for size in [0, 1, 125, 126, 65_535, 65_536, 200_000] {
            let frame = WebSocketFrame(fin: size % 2 == 0, opcode: .binary, payload: (0..<size).map { UInt8(truncatingIfNeeded: $0) })
            for (sender, receiver) in [(WebSocketRole.client, WebSocketRole.server), (.server, .client)] {
                let bytes = wire(frame, from: sender)
                let decoded = try bytes.withUnsafeBytes { try WebSocketFrameCodec(role: receiver).decodeFrame($0) }
                #expect(decoded?.item == frame)
                #expect(decoded?.consumed == bytes.count)
                // Every prefix is just incomplete.
                if size < 200 {
                    for cut in 0..<bytes.count {
                        #expect(try Array(bytes[..<cut]).withUnsafeBytes { try WebSocketFrameCodec(role: receiver).decodeFrame($0) } == nil)
                    }
                }
            }
        }
    }

    @Test func refusals() {
        func error(_ bytes: [UInt8], role: WebSocketRole = .server, max: Int = 1 << 20) -> WebSocketError? {
            do {
                _ = try bytes.withUnsafeBytes { try WebSocketFrameCodec(role: role, maxFrameSize: max).decodeFrame($0) }
                return nil
            } catch {
                return error as? WebSocketError
            }
        }
        let violation = WebSocketError.protocolViolation(.protocolError)
        #expect(error([0x81, 0x00]) == violation) // unmasked to a server
        #expect(error([0x81, 0x80, 0, 0, 0, 0], role: .client) == violation) // masked to a client
        #expect(error([0xC1, 0x80, 0, 0, 0, 0]) == violation) // RSV1
        #expect(error([0x83, 0x80, 0, 0, 0, 0]) == violation) // opcode 3
        #expect(error([0x09, 0x80, 0, 0, 0, 0]) == violation) // fragmented ping
        #expect(error([0x89, 0xFE, 0, 126, 0, 0, 0, 0]) == violation) // ping over 125
        #expect(error([0x82, 0xFE, 0, 5, 0, 0, 0, 0]) == violation) // 16-bit length under 126
        #expect(error([0x82, 0xFF, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0]) == violation) // 64-bit under 65536
        #expect(error([0x82, 0xFF, 0x80, 0, 0, 0, 0, 0, 0, 0]) == violation) // high bit set
        #expect(error([0x82, 0xFE, 0x10, 0, 0, 0, 0, 0], max: 1000) == .protocolViolation(.messageTooBig))
    }

    @Test func utf8() {
        func valid(_ pieces: [[UInt8]]) -> Bool {
            var v = UTF8Validator()
            for p in pieces where !v.feed(p) { return false }
            return v.isComplete
        }
        let euro = Array("€😀é".utf8)
        #expect(valid([euro]))
        // Split anywhere, including inside sequences.
        for cut in 0...euro.count { #expect(valid([Array(euro[..<cut]), Array(euro[cut...])])) }
        #expect(!valid([[0xED, 0xA0, 0x80]])) // a surrogate
        #expect(!valid([[0xC0, 0xAF]])) // overlong
        #expect(!valid([[0xE0, 0x80, 0xAF]])) // overlong
        #expect(!valid([[0xF4, 0x90, 0x80, 0x80]])) // past U+10FFFF
        #expect(!valid([[0xE2, 0x82]])) // unfinished
        // A surrogate fails on its second byte, before the rest arrives.
        var early = UTF8Validator()
        let accepted = early.feed([0xED, 0xA0])
        #expect(!accepted)
    }
}

/// A server and a client WebSocket over an in-memory connection.
private func withPair<T: Sendable>(
    configuration: WebSocketConfiguration = .init(),
    server: @escaping @Sendable (inout WebSocket<DuplexStream>) async throws -> Void,
    client: @escaping @Sendable (inout WebSocket<DuplexStream>) async throws -> T
) throws -> T {
    let rt = Runtime(workers: 2)
    defer { rt.shutdown() }
    return try rt.block {
        let pair = duplex()
        rt.spawn(with: pair.second) { stream async in
            guard var ws = try? await WebSocket.accept(stream, configuration: configuration) else { return }
            try? await server(&ws)
        }
        var ws = try await WebSocket.connect(pair.first, host: "vega.test", target: "/chat")
        return try await client(&ws)
    }
}

private func echo(_ ws: inout WebSocket<DuplexStream>) async throws {
    while let m = try await ws.receive() { try await ws.send(m) }
}

@Suite struct WebSocketTests {
    @Test func echoAndClose() throws {
        let (messages, code) = try withPair(server: echo) { ws -> ([WebSocketMessage], WebSocketCloseCode?) in
            #expect(ws.response?.status == 101)
            let sent: [WebSocketMessage] = [.text("hello"), .binary([1, 2, 3]), .text(String(repeating: "é", count: 40_000)), .binary([])]
            var got: [WebSocketMessage] = []
            for m in sent {
                try await ws.send(m)
                try await ws.ping([9])
                let message = try await ws.receive()
                got.append(try #require(message))
            }
            try await ws.close(.goingAway, reason: "bye")
            return (got, ws.closeCode)
        }
        #expect(messages == [.text("hello"), .binary([1, 2, 3]), .text(String(repeating: "é", count: 40_000)), .binary([])])
        // The server echoed our code.
        #expect(code == .goingAway)
    }

    /// Fragments, interleaved control frames, and the peer closing first,
    /// written by hand.
    @Test func fragmentsAndPings() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (message, reply, closed) = try rt.block { () async throws -> (WebSocketMessage?, [UInt8], WebSocketCloseCode?) in
            let pair = duplex()
            let server = rt.spawn(with: pair.second) { stream async -> (WebSocketMessage?, WebSocketCloseCode?) in
                var ws = WebSocket(stream, role: .server)
                let m = try? await ws.receive()
                let end = try? await ws.receive()
                #expect(end == nil)
                return (m.flatMap { $0 }, ws.closeCode)
            }
            var bytes: [UInt8] = []
            bytes += wire(WebSocketFrame(fin: false, opcode: .text, payload: Array("frag".utf8)), from: .client)
            bytes += wire(WebSocketFrame(opcode: .ping, payload: [7, 7]), from: .client)
            bytes += wire(WebSocketFrame(fin: false, opcode: .continuation, payload: [0xE2, 0x82]), from: .client)
            bytes += wire(WebSocketFrame(fin: true, opcode: .continuation, payload: [0xAC, 0x21]), from: .client)
            bytes += wire(WebSocketFrame(opcode: .close, payload: [0x03, 0xE8] + Array("done".utf8)), from: .client)
            var out = IOBuffer(capacity: bytes.count)
            bytes.withUnsafeBytes { out.append($0) }
            try await pair.first.write(out)
            var reply = IOBuffer(capacity: 1024)
            while reply.count < 8, try await pair.first.read(into: &reply) > 0 {}
            let (m, code) = await server.value
            return (m, reply.withUnsafeBytes { Array($0) }, code)
        }
        #expect(message == .text("frag€!"))
        // The pong, then our close code echoed.
        #expect(reply == [0x8A, 0x02, 7, 7, 0x88, 0x02, 0x03, 0xE8])
        #expect(closed == .normal)
    }

    @Test func violationsCloseWithTheirCode() throws {
        let cases: [([UInt8], WebSocketCloseCode)] = [
            (wire(WebSocketFrame(opcode: .text, payload: [0xFF]), from: .client), .invalidPayload),
            (wire(WebSocketFrame(opcode: .continuation, payload: [1]), from: .client), .protocolError),
            (wire(WebSocketFrame(fin: false, opcode: .text, payload: [65]), from: .client)
                + wire(WebSocketFrame(opcode: .binary, payload: [1]), from: .client), .protocolError),
            (wire(WebSocketFrame(opcode: .binary, payload: Array(repeating: 0, count: 2000)), from: .client), .messageTooBig),
            (wire(WebSocketFrame(opcode: .close, payload: [0x03]), from: .client), .protocolError),
            (wire(WebSocketFrame(opcode: .close, payload: [0x03, 0xED]), from: .client), .protocolError), // 1005
            ([0x81, 0x01, 65], .protocolError), // unmasked
        ]
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        for (bytes, code) in cases {
            let (error, sent) = try rt.block { () async throws -> (WebSocketError?, [UInt8]) in
                let pair = duplex()
                let server = rt.spawn(with: pair.second) { stream async -> WebSocketError? in
                    var ws = WebSocket(stream, role: .server, configuration: WebSocketConfiguration(maxMessageSize: 1000))
                    do throws(WebSocketError) {
                        while try await ws.receive() != nil {}
                        return nil
                    } catch {
                        return error
                    }
                }
                var out = IOBuffer(capacity: bytes.count)
                bytes.withUnsafeBytes { out.append($0) }
                try await pair.first.write(out)
                let error = await server.value
                var reply = IOBuffer(capacity: 64)
                while try await pair.first.read(into: &reply) > 0 {}
                return (error, reply.withUnsafeBytes { Array($0) })
            }
            #expect(error == .protocolViolation(code), "\(bytes.prefix(4))")
            #expect(sent == [0x88, 0x02, UInt8(code.rawValue >> 8), UInt8(code.rawValue & 0xFF)], "\(code)")
        }
    }

    @Test func handshakeRefusals() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        func attempt(_ request: String, accept: @escaping @Sendable (HTTPRequestHead) async -> HTTPFields? = { _ in [:] }) throws -> (String, WebSocketError?) {
            try rt.block { () async throws -> (String, WebSocketError?) in
                let pair = duplex()
                let server = rt.spawn(with: pair.second) { stream async -> WebSocketError? in
                    do throws(WebSocketError) {
                        _ = try await WebSocket.accept(stream, accept: accept)
                        return nil
                    } catch {
                        return error
                    }
                }
                var out = IOBuffer(capacity: 1024)
                out.append(request)
                try await pair.first.write(out)
                let error = await server.value
                var reply = IOBuffer(capacity: 1024)
                while try await pair.first.read(into: &reply) > 0 {}
                return (reply.string, error)
            }
        }
        let good = "GET /chat HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\n"
            + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        let (ok, okError) = try attempt(good) { request in request.path == "/chat" ? ["sec-websocket-protocol": "chat"] : nil }
        #expect(okError == nil)
        #expect(ok.hasPrefix("HTTP/1.1 101 Switching Protocols\r\n"))
        #expect(ok.contains("sec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"))
        #expect(ok.contains("sec-websocket-protocol: chat\r\n"))

        let (old, _) = try attempt(good.replacing("Version: 13", with: "Version: 8"))
        #expect(old.hasPrefix("HTTP/1.1 426 "))
        #expect(old.contains("sec-websocket-version: 13"))
        let (plain, plainError) = try attempt("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        #expect(plain.hasPrefix("HTTP/1.1 400 "))
        #expect(plainError == .handshake("no Upgrade: websocket"))
        let (refused, _) = try attempt(good) { _ in nil }
        #expect(refused.hasPrefix("HTTP/1.1 403 "))
    }

    /// The upgrade request's bytes and the first frame arrive together.
    @Test func framesRightAfterTheHandshake() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let got = try rt.block { () async throws -> WebSocketMessage? in
            let pair = duplex()
            let server = rt.spawn(with: pair.second) { stream async -> WebSocketMessage? in
                guard var ws = try? await WebSocket.accept(stream) else { return nil }
                return try? await ws.receive()
            }
            let request = "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
            let bytes = Array(request.utf8) + wire(WebSocketFrame(opcode: .text, payload: Array("early".utf8)), from: .client)
            var out = IOBuffer(capacity: bytes.count)
            bytes.withUnsafeBytes { out.append($0) }
            try await pair.first.write(out)
            return await server.value
        }
        #expect(got == .text("early"))
    }

    @Test func overTCP() throws {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        let total = try rt.block { () async throws -> Int in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let port = listener.localPort
            rt.spawn(with: listener) { l async in
                while let conn = try? await l.accept() {
                    rt.spawn(with: conn) { conn async in
                        guard var ws = try? await WebSocket.accept(conn) else { return }
                        while let m = try? await ws.receive() { try? await ws.send(m) }
                    }
                }
            }
            var ws = try await WebSocket.connect(try await TCPStream.connect(host: "127.0.0.1", port: port), host: "localhost")
            var total = 0
            for i in 0..<50 {
                let payload = Array(repeating: UInt8(i), count: i * 3000)
                try await ws.send(.binary(payload))
                guard case .binary(let back)? = try await ws.receive(), back == payload else { return -1 }
                total += back.count
            }
            try await ws.close()
            return total
        }
        #expect(total == (0..<50).reduce(0) { $0 + $1 * 3000 })
    }
}
