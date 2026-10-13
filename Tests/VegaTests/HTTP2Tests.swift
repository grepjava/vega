import Testing
import Vega
import VegaIO
import VegaHTTP1
@testable import VegaHTTP2
import VegaTest

/// Bytes from hex, spaces and newlines ignored: RFC examples as printed.
private func hex(_ s: String) -> [UInt8] {
    var out: [UInt8] = []
    var high: UInt8?
    for c in s.utf8 {
        let v: UInt8
        switch c {
        case 0x30...0x39: v = c - 0x30
        case 0x61...0x66: v = c - 0x61 + 10
        default: continue
        }
        if let h = high {
            out.append(h << 4 | v)
            high = nil
        } else {
            high = v
        }
    }
    return out
}

private func decodeAll(_ decoder: inout HPACKDecoder, _ bytes: [UInt8]) throws -> [String] {
    var fields: [String] = []
    try bytes.withUnsafeBytes { b in
        try decoder.decode(b) { n, v in
            fields.append(String(decoding: n, as: UTF8.self) + ": " + String(decoding: v, as: UTF8.self))
        }
    }
    return fields
}

@Suite struct HPACKTests {
    @Test func huffmanTablesAreCanonical() {
        #expect(HPACKHuffman.tablesAreCanonical())
    }

    @Test func rfc7541C3Requests() throws {
        var d = HPACKDecoder()
        #expect(try decodeAll(&d, hex("8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d"))
                == [":method: GET", ":scheme: http", ":path: /", ":authority: www.example.com"])
        #expect(d.tableSize == 57)
        #expect(try decodeAll(&d, hex("8286 84be 5808 6e6f 2d63 6163 6865"))
                == [":method: GET", ":scheme: http", ":path: /", ":authority: www.example.com", "cache-control: no-cache"])
        #expect(d.tableSize == 110)
        #expect(try decodeAll(&d, hex("8287 85bf 400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65"))
                == [":method: GET", ":scheme: https", ":path: /index.html", ":authority: www.example.com", "custom-key: custom-value"])
        #expect(d.tableSize == 164)
    }

    @Test func rfc7541C4HuffmanRequests() throws {
        var d = HPACKDecoder()
        #expect(try decodeAll(&d, hex("8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff"))
                == [":method: GET", ":scheme: http", ":path: /", ":authority: www.example.com"])
        #expect(try decodeAll(&d, hex("8286 84be 5886 a8eb 1064 9cbf")).last == "cache-control: no-cache")
        #expect(try decodeAll(&d, hex("8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf")).last
                == "custom-key: custom-value")
    }

    @Test func rfc7541C5Eviction() throws {
        var d = HPACKDecoder(maxTableSize: 256)
        _ = try decodeAll(&d, hex("""
            4803 3330 3258 0770 7269 7661 7465 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133
            2032 303a 3133 3a32 3120 474d 546e 1768 7474 7073 3a2f 2f77 7777 2e65 7861 6d70
            6c65 2e63 6f6d
            """))
        #expect(d.tableSize == 222)
        #expect(try decodeAll(&d, hex("4803 3330 37c1 c0bf"))
                == [":status: 307", "cache-control: private", "date: Mon, 21 Oct 2013 20:13:21 GMT",
                    "location: https://www.example.com"])
        let third = try decodeAll(&d, hex("""
            88c1 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 2032 303a 3133 3a32 3220 474d
            54c0 5a04 677a 6970 7738 666f 6f3d 4153 444a 4b48 514b 425a 584f 5157 454f 5049
            5541 5851 5745 4f49 553b 206d 6178 2d61 6765 3d33 3630 303b 2076 6572 7369 6f6e
            3d31
            """))
        #expect(third.last == "set-cookie: foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1")
        #expect(d.dynamicEntryCount == 3)
    }

    @Test func roundTrip() throws {
        var block: [UInt8] = []
        let all = String(decoding: (0...255).map { UInt8($0) }.filter { $0 != 0x0A && $0 != 0x0D }, as: UTF8.self)
        let fields = [(":method", "GET"), (":path", "/"), (":status", "404"), (":method", "PATCH"),
                      ("content-type", "text/html; charset=utf-8"), ("x-custom", "aaaaaaaaaaaaaaaaaaaa"), ("x-all", all)]
        for (n, v) in fields { HPACKEncoder.encode(name: n, value: v, into: &block) }
        var d = HPACKDecoder()
        #expect(try decodeAll(&d, block) == fields.map { "\($0.0): \($0.1)" })
        #expect(d.dynamicEntryCount == 0) // nothing indexed
    }

    @Test func refusals() {
        func error(_ bytes: [UInt8]) -> HPACKError? {
            var d = HPACKDecoder()
            do {
                _ = try decodeAll(&d, bytes)
                return nil
            } catch {
                return error as? HPACKError
            }
        }
        #expect(error(hex("80")) == .badIndex)
        #expect(error(hex("be")) == .badIndex)
        #expect(error(hex("0004 6162")) == .truncated)
        #expect(error(hex("00")) == .truncated)
        #expect(error(hex("0000 8100")) == .badHuffman)
        #expect(error(hex("3fe2 1f")) == .badTableSize)
        #expect(error(hex("82 3f e1 1f")) == .badTableSize) // after a field
    }
}

@Suite struct HTTP2FrameTests {
    @Test func roundTrip() throws {
        let frames: [HTTP2Frame] = [
            .init(streamID: 1, payload: .data([1, 2, 3], endStream: true, flowLength: 3)),
            .init(streamID: 3, payload: .headers([0x82, 0x84], endStream: false, endHeaders: false)),
            .init(streamID: 3, payload: .continuation([0x86], endHeaders: true)),
            .init(streamID: 5, payload: .priority),
            .init(streamID: 5, payload: .rstStream(.cancel)),
            .init(streamID: 0, payload: .settings([(.initialWindowSize, 1 << 20), (.enablePush, 0)])),
            .init(streamID: 0, payload: .settingsAck),
            .init(streamID: 0, payload: .ping(0x0102030405060708, ack: true)),
            .init(streamID: 0, payload: .goaway(lastStreamID: 7, .enhanceYourCalm, debug: [9])),
            .init(streamID: 9, payload: .windowUpdate(12345)),
            .init(streamID: 0, payload: .windowUpdate(1)),
        ]
        var buffer = IOBuffer(capacity: 64)
        for f in frames { f.write(into: &buffer) }
        let codec = HTTP2FrameCodec()
        var got: [HTTP2Frame] = []
        try buffer.withUnsafeBytes { all in
            var at = 0
            while let (frame, used) = try codec.decodeFrame(UnsafeRawBufferPointer(rebasing: all[at...])) {
                got.append(frame)
                at += used
            }
            #expect(at == all.count)
        }
        #expect(got == frames)
    }

    @Test func paddingAndRefusals() {
        let codec = HTTP2FrameCodec()
        /// The frame, or the code it fails with.
        func decode(_ bytes: [UInt8]) -> (frame: HTTP2Frame?, error: HTTP2ErrorCode?) {
            do {
                return (try bytes.withUnsafeBytes { try codec.decodeFrame($0) }?.item, nil)
            } catch {
                return (nil, (error as! FrameError).code)
            }
        }
        // Padded DATA: pad length 2, "hi", two bytes of padding. Flow
        // control counts all five.
        let padded = decode([0, 0, 5, 0, 0x9, 0, 0, 0, 1, 2, 104, 105, 0, 0]).frame
        #expect(padded?.payload == .data([104, 105], endStream: true, flowLength: 5))
        if case .data(_, _, let flow)? = padded?.payload { #expect(flow == 5) }
        // Padding longer than the frame.
        #expect(decode([0, 0, 2, 0, 0x8, 0, 0, 0, 1, 5, 0]).error == .protocolError)
        // DATA on stream 0; SETTINGS on a stream; bad lengths.
        #expect(decode([0, 0, 0, 0, 0, 0, 0, 0, 0]).error == .protocolError)
        #expect(decode([0, 0, 0, 4, 0, 0, 0, 0, 1]).error == .protocolError)
        #expect(decode([0, 0, 5, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).error == .frameSizeError)
        #expect(decode([0, 0, 3, 6, 0, 0, 0, 0, 0, 0, 0, 0]).error == .frameSizeError)
        // Over the frame size limit.
        #expect(decode([0, 0x40, 1, 0, 0, 0, 0, 0, 1]).error == .frameSizeError)
        // Incomplete, and unknown types ignored.
        let partial = decode([0, 0, 4, 8, 0, 0, 0, 0])
        #expect(partial.frame == nil && partial.error == nil)
        #expect(decode([0, 0, 1, 0xEE, 0, 0, 0, 0, 0, 7]).frame?.payload == .unknown(type: 0xEE))
    }
}

/// Run a server on one end of an in-memory connection and `body` with a
/// client on the other.
private func withServer<T: Sendable>(
    configuration: HTTP2Configuration = .init(),
    handler: @escaping @Sendable (HTTPRequest) async throws -> HTTPResponse,
    _ body: @escaping @Sendable (HTTP2Client) async throws -> T
) throws -> T {
    let rt = Runtime(workers: 4)
    defer { rt.shutdown() }
    return try rt.block {
        let pair = duplex(capacity: 256 * 1024)
        let server = rt.spawn(with: pair.second) { stream async -> HTTP2Error? in
            let halves = stream.split()
            do throws(HTTP2Error) {
                try await HTTP2Server.serve(reader: halves.reader, writer: halves.writer,
                                            configuration: configuration, handler)
                return nil
            } catch {
                return error
            }
        }
        let halves = pair.first.split()
        let result = try await HTTP2Client.withConnection(reader: halves.reader, writer: halves.writer,
                                                          scheme: "http", authority: "vega.test", body)
        #expect(await server.value == nil)
        return result
    }
}

private func get(_ path: String) -> HTTPRequest {
    HTTPRequest(target: path)
}

@Suite struct HTTP2ConnectionTests {
    @Test func requestAndResponse() throws {
        let response = try withServer(handler: { request in
            HTTPResponse(fields: ["x-method": request.head.method.rawValue, "x-host": request.head.fields["host"] ?? "-"],
                         body: "hello \(request.head.target)")
        }) { client in
            try await client.send(get("/a?b=c"))
        }
        #expect(response.status == 200)
        #expect(response.text == "hello /a?b=c")
        #expect(response.head.version == .http2)
        #expect(response.head.fields["x-method"] == "GET")
        #expect(response.head.fields["x-host"] == "vega.test")
        #expect(response.head.fields["content-length"] == "12")
    }

    /// Many requests at once on one connection, each answered on its own.
    @Test func concurrentStreams() throws {
        let results = try withServer(handler: { request in
            // Later requests answer first, so responses come back out of order.
            let n = Int(request.head.path.dropFirst())!
            try await Task.sleep(for: .milliseconds(50 - n))
            return HTTPResponse(body: request.body + Array(request.head.target.utf8))
        }) { client in
            try await withThrowingTaskGroup(of: (Int, HTTPResponse).self) { group in
                for i in 0..<50 {
                    group.addTask {
                        (i, try await client.send(HTTPRequest(method: .post, target: "/\(i)", body: [UInt8(i)])))
                    }
                }
                var all: [Int: HTTPResponse] = [:]
                for try await (i, r) in group { all[i] = r }
                return all
            }
        }
        #expect(results.count == 50)
        for (i, r) in results { #expect(r.body == [UInt8(i)] + Array("/\(i)".utf8)) }
    }

    /// Bodies far larger than every flow-control window, both ways.
    @Test func bigBodies() throws {
        let size = 5 << 20
        let config = HTTP2Configuration(initialWindowSize: 65_535, connectionWindowSize: 65_535, maxBodySize: 16 << 20)
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        let echoed = try rt.block { () async throws -> [UInt8] in
            let pair = duplex(capacity: 32 * 1024)
            rt.spawn(with: pair.second) { stream async in
                let halves = stream.split()
                try? await HTTP2Server.serve(reader: halves.reader, writer: halves.writer, configuration: config) { request in
                    HTTPResponse(body: request.body.reversed())
                }
            }
            let halves = pair.first.split()
            let body = (0..<size).map { UInt8(truncatingIfNeeded: $0 * 7) }
            return try await HTTP2Client.withConnection(reader: halves.reader, writer: halves.writer, scheme: "http",
                                                        authority: "x", configuration: config) { client in
                let r = try await client.send(HTTPRequest(method: .put, target: "/", body: body))
                return Array(r.body.reversed())
            }
        }
        #expect(echoed.count == size)
        #expect(echoed == (0..<size).map { UInt8(truncatingIfNeeded: $0 * 7) })
    }

    @Test func headErrorsAndLimits() throws {
        let config = HTTP2Configuration(maxBodySize: 100)
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let (head, failed, large, after) = try rt.block { () async throws -> (HTTPResponse, HTTPResponse, Int, Int) in
            let pair = duplex()
            rt.spawn(with: pair.second) { stream async in
                let halves = stream.split()
                try? await HTTP2Server.serve(reader: halves.reader, writer: halves.writer, configuration: config) { request in
                    if request.head.path == "/fail" { throw CancellationError() }
                    return HTTPResponse(body: "body")
                }
            }
            let halves = pair.first.split()
            return try await HTTP2Client.withConnection(reader: halves.reader, writer: halves.writer, scheme: "http",
                                                        authority: "x") { client in
                let head = try await client.send(HTTPRequest(method: .head, target: "/"))
                let failed = try await client.send(get("/fail"))
                let large = try await client.send(HTTPRequest(method: .post, target: "/", body: Array(repeating: 1, count: 1000)))
                // The connection carries on after all of them.
                let after = try await client.send(get("/"))
                return (head, failed, large.status, after.status)
            }
        }
        #expect(head.body.isEmpty)
        #expect(head.head.fields["content-length"] == "4")
        #expect(failed.status == 500)
        #expect(large == 413)
        #expect(after == 200)
    }

    @Test func overTCP() throws {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        let bodies = try rt.block { () async throws -> [String] in
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let port = listener.localPort
            rt.spawn(with: listener) { l async in
                while let conn = try? await l.accept() {
                    rt.spawn(with: conn) { conn async in
                        try? await HTTP2Server.serve(conn) { request in HTTPResponse(body: "tcp \(request.head.target)") }
                    }
                }
            }
            let tcp = try await TCPStream.connect(host: "127.0.0.1", port: port)
            return try await HTTP2Client.withConnection(tcp.halves(), scheme: "http") { client in
                var out: [String] = []
                for i in 0..<20 {
                    out.append(try await client.send(HTTPRequest(target: "/\(i)", fields: ["host": "localhost"])).text)
                }
                return out
            }
        }
        #expect(bodies == (0..<20).map { "tcp /\($0)" })
    }
}

/// A raw peer: frames written by hand, frames read back.
private struct RawPeer: ~Copyable {
    var stream: DuplexStream
    var buffer = IOBuffer(capacity: 64 * 1024)
    let codec = HTTP2FrameCodec(maxFrameSize: 1 << 20)

    func send(_ frames: [HTTP2Frame], preface: Bool = false) async throws {
        var out = IOBuffer(capacity: 1024)
        if preface { HTTP2Frame.preface.withUnsafeBytes { out.write($0) } }
        for f in frames { f.write(into: &out) }
        try await stream.write(out)
    }

    func sendBytes(_ bytes: [UInt8]) async throws {
        var out = IOBuffer(capacity: max(bytes.count, 1))
        bytes.withUnsafeBytes { out.write($0) }
        try await stream.write(out)
    }

    /// Frames until one matches, or nil at end of stream.
    mutating func next(where match: (HTTP2Frame) -> Bool) async throws -> HTTP2Frame? {
        while true {
            while let (frame, used) = try buffer.withUnsafeBytes({ try codec.decodeFrame($0) }) {
                buffer.consume(used)
                if match(frame) { return frame }
            }
            if try await stream.read(into: &buffer) == 0 { return nil }
        }
    }
}

private func headerBlock(_ fields: [(String, String)]) -> [UInt8] {
    var block: [UInt8] = []
    for (n, v) in fields { HPACKEncoder.encode(name: n, value: v, into: &block) }
    return block
}

private let validRequest = [(":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", "x")]

@Suite struct HTTP2ProtocolTests {
    /// Run a server against a raw peer, which sends the preface and SETTINGS
    /// first.
    private func raw<T: Sendable>(_ body: @escaping @Sendable (inout RawPeer) async throws -> T) throws -> T {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        return try rt.block {
            let pair = duplex()
            rt.spawn(with: pair.second) { stream async in
                let halves = stream.split()
                try? await HTTP2Server.serve(reader: halves.reader, writer: halves.writer) { _ in HTTPResponse(body: "ok") }
            }
            var peer = RawPeer(stream: pair.first)
            return try await body(&peer)
        }
    }

    private func goawayCode(_ f: HTTP2Frame?) -> HTTP2ErrorCode? {
        if case .goaway(_, let code, _)? = f?.payload { return code }
        return nil
    }

    private func isGoaway(_ f: HTTP2Frame) -> Bool {
        if case .goaway = f.payload { return true }
        return false
    }

    @Test func badPreface() throws {
        let code = try raw { peer in
            try await peer.sendBytes(Array("GET / HTTP/1.1\r\nHost: x\r\n\r\n".utf8))
            return goawayCode(try await peer.next(where: isGoaway))
        }
        #expect(code == .protocolError)
    }

    @Test func pingIsAnswered() throws {
        let ack = try raw { peer -> HTTP2Frame? in
            try await peer.send([.init(streamID: 0, payload: .settings([])), .init(streamID: 0, payload: .ping(42, ack: false))],
                                preface: true)
            return try await peer.next {
                if case .ping = $0.payload { return true }
                return false
            }
        }
        #expect(ack?.payload == .ping(42, ack: true))
    }

    @Test func connectionErrors() throws {
        let cases: [([HTTP2Frame], HTTP2ErrorCode)] = [
            // A window past 2^31-1.
            ([.init(streamID: 0, payload: .windowUpdate(0x7FFF_FFFF))], .flowControlError),
            ([.init(streamID: 0, payload: .windowUpdate(0))], .protocolError),
            // CONTINUATION without HEADERS, and something else in between.
            ([.init(streamID: 1, payload: .continuation([], endHeaders: true))], .protocolError),
            ([.init(streamID: 1, payload: .headers(headerBlock(validRequest), endStream: true, endHeaders: false)),
              .init(streamID: 0, payload: .ping(1, ack: false))], .protocolError),
            // Even (server) stream ids, and going backwards.
            ([.init(streamID: 2, payload: .headers(headerBlock(validRequest), endStream: true, endHeaders: true))], .protocolError),
            // DATA on a stream never opened.
            ([.init(streamID: 9, payload: .data([1], endStream: true, flowLength: 1))], .protocolError),
            // A bad header block.
            ([.init(streamID: 1, payload: .headers([0x80], endStream: true, endHeaders: true))], .compressionError),
            ([.init(streamID: 0, payload: .settings([(.maxFrameSize, 100)]))], .protocolError),
            ([.init(streamID: 0, payload: .settings([(.initialWindowSize, 0x8000_0000)]))], .flowControlError),
            ([.init(streamID: 1, payload: .pushPromise(promisedStreamID: 2, [], endHeaders: true))], .protocolError),
        ]
        for (frames, expected) in cases {
            let code = try raw { peer in
                try await peer.send([.init(streamID: 0, payload: .settings([]))] + frames, preface: true)
                return goawayCode(try await peer.next(where: isGoaway))
            }
            #expect(code == expected, "\(frames)")
        }
    }

    /// Malformed requests reset their stream; the connection carries on.
    @Test func streamErrors() throws {
        let malformed: [[(String, String)]] = [
            validRequest + [("Upper", "x")],
            validRequest + [("connection", "keep-alive")],
            validRequest + [("te", "gzip")],
            validRequest + [("x", " padded")],
            [(":method", "GET"), (":path", "/"), (":authority", "x")], // no scheme
            [(":method", "GET"), (":scheme", "http"), (":path", ""), (":authority", "x")],
            [("x", "y"), (":method", "GET"), (":scheme", "http"), (":path", "/")], // pseudo after regular
            validRequest + [(":method", "POST")], // twice
            validRequest + [(":status", "200")], // a response field
        ]
        let codes = try raw { peer -> [HTTP2ErrorCode?] in
            var frames: [HTTP2Frame] = [.init(streamID: 0, payload: .settings([]))]
            for (i, fields) in malformed.enumerated() {
                frames.append(.init(streamID: UInt32(2 * i + 1),
                                    payload: .headers(headerBlock(fields), endStream: true, endHeaders: true)))
            }
            // A good request last, which is answered.
            let last = UInt32(2 * malformed.count + 1)
            frames.append(.init(streamID: last, payload: .headers(headerBlock(validRequest), endStream: true, endHeaders: true)))
            try await peer.send(frames, preface: true)
            var codes: [UInt32: HTTP2ErrorCode] = [:]
            while let f = try await peer.next(where: { _ in true }) {
                if case .rstStream(let code) = f.payload { codes[f.streamID] = code }
                if case .data(let body, true, _) = f.payload, f.streamID == last {
                    #expect(body == Array("ok".utf8))
                    break
                }
            }
            return (0..<malformed.count).map { codes[UInt32(2 * $0 + 1)] }
        }
        #expect(codes == Array(repeating: .protocolError, count: malformed.count))
    }

    /// Content-Length that disagrees with the body resets the stream.
    @Test func contentLengthMismatch() throws {
        let code = try raw { peer -> HTTP2ErrorCode? in
            try await peer.send([
                .init(streamID: 0, payload: .settings([])),
                .init(streamID: 1, payload: .headers(headerBlock([(":method", "POST"), (":scheme", "http"), (":path", "/"),
                                                                  (":authority", "x"), ("content-length", "5")]),
                                                     endStream: false, endHeaders: true)),
                .init(streamID: 1, payload: .data([1, 2], endStream: true, flowLength: 2)),
            ], preface: true)
            let f = try await peer.next {
                if case .rstStream = $0.payload { return true }
                return false
            }
            if case .rstStream(let code)? = f?.payload { return code }
            return nil
        }
        #expect(code == .protocolError)
    }

    @Test func tooManyStreamsAreRefused() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let refused = try rt.block { () async throws -> Bool in
            let pair = duplex()
            rt.spawn(with: pair.second) { stream async in
                let halves = stream.split()
                try? await HTTP2Server.serve(reader: halves.reader, writer: halves.writer,
                                             configuration: HTTP2Configuration(maxConcurrentStreams: 1)) { _ in
                    try await Task.sleep(for: .seconds(1))
                    return HTTPResponse()
                }
            }
            var peer = RawPeer(stream: pair.first)
            let block = headerBlock(validRequest)
            try await peer.send([.init(streamID: 0, payload: .settings([])),
                                 .init(streamID: 1, payload: .headers(block, endStream: true, endHeaders: true)),
                                 .init(streamID: 3, payload: .headers(block, endStream: true, endHeaders: true))],
                                preface: true)
            let f = try await peer.next {
                if case .rstStream = $0.payload { return true }
                return false
            }
            return f?.streamID == 3 && f?.payload == .rstStream(.refusedStream)
        }
        #expect(refused)
    }
}
