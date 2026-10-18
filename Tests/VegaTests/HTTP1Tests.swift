import Testing
import Vega
import VegaIO
import VegaHTTP1
import VegaTest

/// Decode `text` fed `step` bytes at a time, then end the stream; body parts
/// are merged so results compare whatever the step.
private func parts<D: FrameDecoder>(_ decoder: D, _ text: String, step: Int = .max) throws -> [D.Item] {
    var d = decoder
    let all = Array(text.utf8)
    var buffer: [UInt8] = []
    var fed = 0
    var out: [D.Item] = []
    while true {
        while let (item, used) = try buffer.withUnsafeBytes({ try d.decode($0) }) {
            out.append(item)
            buffer.removeFirst(used)
        }
        if fed == all.count { break }
        let n = min(step, all.count - fed)
        buffer += all[fed..<fed + n]
        fed += n
    }
    while let (item, used) = try buffer.withUnsafeBytes({ try d.decodeAtEnd($0) }) {
        out.append(item)
        buffer.removeFirst(used)
    }
    return merged(out)
}

private func merged<Head>(_ parts: [HTTPPart<Head>]) -> [HTTPPart<Head>] {
    var out: [HTTPPart<Head>] = []
    for part in parts {
        if case .body(let b) = part, case .body(let a)? = out.last {
            out[out.count - 1] = .body(a + b)
        } else {
            out.append(part)
        }
    }
    return out
}

private func merged<T>(_ items: [T]) -> [T] {
    if let parts = items as? [HTTPRequestPart] { return merged(parts) as! [T] }
    if let parts = items as? [HTTPResponsePart] { return merged(parts) as! [T] }
    return items
}

/// How a request head fails to parse, or nil if it parses.
private func requestError(_ text: String, limits: HTTP1Limits = .init()) -> HTTP1Error? {
    var d = HTTP1RequestDecoder(limits: limits)
    do {
        _ = try Array(text.utf8).withUnsafeBytes { try d.decodePart($0) }
        return nil
    } catch {
        return error as? HTTP1Error
    }
}

private func head(_ parts: [HTTPRequestPart]) -> HTTPRequestHead? {
    if case .head(let h)? = parts.first { return h }
    return nil
}

private func encoded(_ body: (inout IOBuffer) throws -> Void) rethrows -> String {
    var buffer = IOBuffer(capacity: 256)
    try body(&buffer)
    return buffer.string
}

@Suite struct HTTP1ParseTests {
    @Test func minimalGet() throws {
        let p = try parts(HTTP1RequestDecoder(), "GET /search?q=a%20b HTTP/1.1\r\nHost: example.com\r\nA:   1   \r\nB:2\r\n\r\n")
        #expect(p.count == 2)
        let h = try #require(head(p))
        #expect(h.method == .get)
        #expect(h.target == "/search?q=a%20b")
        #expect(h.path == "/search")
        #expect(h.query == "q=a%20b")
        #expect(h.version == .http1_1)
        #expect(h.fields == ["host": "example.com", "a": "1", "b": "2"])
        #expect(h.fields["HOST"] == "example.com")
        #expect(p.last == .end(nil))
    }

    @Test func keepAlive() throws {
        let cases: [(String, Bool)] = [
            ("GET / HTTP/1.1\r\nHost: x\r\n\r\n", true),
            ("GET / HTTP/1.0\r\n\r\n", false),
            ("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n", true),
            ("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", false),
            // A whole token, not a substring.
            ("GET / HTTP/1.1\r\nHost: x\r\nConnection: closely-related\r\n\r\n", true),
            ("GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive, close\r\n\r\n", false),
        ]
        for (text, alive) in cases {
            #expect(try head(parts(HTTP1RequestDecoder(), text))?.keepAlive == alive, "\(text)")
        }
    }

    /// The same parts however the bytes are split.
    @Test func splitAnywhere() throws {
        let messages = [
            "POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\nhello world",
            "POST /b HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-Sum: 1\r\nX-Other: 2\r\n\r\n",
            "PUT /c HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: Chunked\r\n\r\n1\r\na\r\n0\r\n\r\n",
        ]
        for text in messages {
            let whole = try parts(HTTP1RequestDecoder(), text)
            #expect(whole.count == 3)
            for step in 1...7 {
                #expect(try parts(HTTP1RequestDecoder(), text, step: step) == whole, "step \(step): \(text)")
            }
        }
        let chunked = try parts(HTTP1RequestDecoder(), messages[1])
        #expect(chunked[1] == .body(Array("hello world".utf8)))
        #expect(chunked[2] == .end(["x-sum": "1", "x-other": "2"]))
    }

    @Test func pipelined() throws {
        let text = "\r\nGET /a HTTP/1.1\r\nHost: x\r\n\r\nPOST /b HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhiGET /c HTTP/1.0\r\n\r\n"
        let p = try parts(HTTP1RequestDecoder(), text)
        let targets = p.compactMap { part -> String? in
            if case .head(let h) = part { return h.target }
            return nil
        }
        #expect(targets == ["/a", "/b", "/c"])
        #expect(p.count == 7)
        #expect(p[3] == .body([104, 105]))
    }

    /// The request-smuggling shapes, and other malformed heads.
    @Test func refusals() {
        let base = "POST / HTTP/1.1\r\nHost: x\r\n"
        let cases: [(String, HTTP1Error)] = [
            (base + "Foo : bar\r\n\r\n", .badHeader),
            (base + "Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n", .conflictingFraming),
            (base + "Content-Length: 5\r\nContent-Length: 6\r\n\r\n", .conflictingFraming),
            (base + "Transfer-Encoding: gzip\r\n\r\n", .conflictingFraming),
            (base + "Transfer-Encoding: xchunked\r\n\r\n", .conflictingFraming),
            (base + "Transfer-Encoding: chunked, gzip\r\n\r\n", .conflictingFraming),
            (base + "Transfer-Encoding: chunked;x=1\r\n\r\n", .conflictingFraming),
            (base + "Transfer-Encoding: \r\n\r\n", .conflictingFraming),
            (base + "Transfer-Encoding: gzip, chunked\r\n\r\n", .unsupportedTransferEncoding),
            (base + "Transfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n", .conflictingFraming),
            (base + "Content-Length: 1a\r\n\r\n", .badHeader),
            (base + "Content-Length: -1\r\n\r\n", .badHeader),
            (base + "A: 1\r\n  continued\r\n\r\n", .badHeader),
            (base + "A: b\u{0}c\r\n\r\n", .badHeader),
            (base + "A: b\rc\r\n\r\n", .badHeader),
            (base + "Host: x\r\n\r\n", .duplicateHost),
            (base + "hOsT: y\r\n\r\n", .duplicateHost),
            ("GET / HTTP/1.1\r\n\r\n", .missingHost),
            ("GET / HTTP/1.9\r\nHost: x\r\n\r\n", .badVersion),
            ("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", .badVersion),
            ("GET  / HTTP/1.1\r\nHost: x\r\n\r\n", .badRequestLine),
            ("GET /a\u{7F} HTTP/1.1\r\nHost: x\r\n\r\n", .badRequestLine),
            ("G(T / HTTP/1.1\r\nHost: x\r\n\r\n", .badRequestLine),
        ]
        for (text, error) in cases {
            #expect(requestError(text) == error, "\(text.debugDescription)")
        }
        // Agreeing Content-Lengths and any-case chunked are fine.
        #expect(requestError(base + "Content-Length: 5\r\nContent-Length: 5\r\n\r\n") == nil)
        #expect(requestError(base + "Transfer-Encoding:  CHUNKED \r\n\r\n") == nil)
        #expect(requestError(base + "Transfer-Encoding: ,chunked\r\n\r\n") == nil)
        #expect(requestError("GET / HTTP/1.1\r\nHost: x\r\n") == nil) // just incomplete
    }

    @Test func badChunks() {
        let base = "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
        for body in ["z\r\n", "\r\n", "5\nhello", "5\r\nhelloXX", "1234567890abcdef1\r\n", "5 \r\n"] {
            #expect(throws: CodecError.self, "\(body.debugDescription)") {
                try parts(HTTP1RequestDecoder(), base + body + "\r\n0\r\n\r\n")
            }
        }
    }

    @Test func limits() {
        let small = HTTP1Limits(maxHeaderSize: 64, maxHeaderCount: 3, maxTrailerSize: 16)
        #expect(requestError("GET /\(String(repeating: "a", count: 100))", limits: small) == .uriTooLong)
        #expect(requestError("GET / HTTP/1.1\r\nHost: x\r\nA: \(String(repeating: "a", count: 100))", limits: small) == .headTooLarge)
        #expect(requestError("GET / HTTP/1.1\r\nHost: x\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n", limits: small) == .tooManyFields)
        #expect(throws: CodecError.self) {
            try parts(HTTP1RequestDecoder(limits: small),
                      "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nA: \(String(repeating: "a", count: 40))\r\n\r\n")
        }
    }

    @Test func truncation() throws {
        #expect(throws: CodecError.truncated(0)) {
            try parts(HTTP1RequestDecoder(), "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nshort")
        }
        #expect(throws: CodecError.truncated(0)) {
            try parts(HTTP1RequestDecoder(), "GET / HTTP/1.1\r\nHo")
        }
        // A close between requests is a clean end.
        #expect(try parts(HTTP1RequestDecoder(), "GET / HTTP/1.1\r\nHost: x\r\n\r\n\r\n").count == 2)
    }

    @Test func responses() throws {
        // A body runs to the close without framing.
        let close = try parts(HTTP1ResponseDecoder(), "HTTP/1.0 200 OK\r\n\r\nall of it", step: 3)
        #expect(close.count == 3)
        #expect(close[1] == .body(Array("all of it".utf8)))
        // Interim responses come before the real one.
        let p = try parts(HTTP1ResponseDecoder(), "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok")
        #expect(p.count == 5)
        if case .head(let h) = p[2] {
            #expect(h.status == 201)
            #expect(h.reason == "Created")
        } else {
            Issue.record("no head")
        }
        // No body for HEAD, 204 and 304, whatever the fields say.
        var d = HTTP1ResponseDecoder()
        d.requestSent(.head)
        d.requestSent(.get)
        d.requestSent(.get)
        let three = try parts(d, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHTTP/1.1 204 No Content\r\n\r\nHTTP/1.1 304 Not Modified\r\nContent-Length: 9\r\n\r\n")
        #expect(three.count == 6)
        // Chunked, with an empty reason.
        let chunked = try parts(HTTP1ResponseDecoder(), "HTTP/1.1 200 \r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n", step: 2)
        #expect(chunked.count == 3)
        #expect(chunked[1] == .body(Array("abc".utf8)))
        // A truncated fixed body.
        #expect(throws: CodecError.truncated(0)) {
            try parts(HTTP1ResponseDecoder(), "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nab")
        }
        #expect(throws: CodecError.self) { try parts(HTTP1ResponseDecoder(), "HTTP/1.1 2x0 OK\r\n\r\n") }
        #expect(throws: CodecError.self) { try parts(HTTP1ResponseDecoder(), "ICY 200 OK\r\n\r\n") }
    }

    @Test func upgradeStopsDecoding() throws {
        var d = HTTP1ResponseDecoder()
        let text = Array("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n\u{81}\u{05}hello".utf8)
        let (first, used) = try #require(try text.withUnsafeBytes { try d.decode($0) })
        guard case .head(let h) = first else { Issue.record("no head"); return }
        #expect(h.status == 101)
        let rest = Array(text[used...])
        let (end, none) = try #require(try rest.withUnsafeBytes { try d.decode($0) })
        #expect(end == .end(nil))
        #expect(none == 0)
        #expect(try rest.withUnsafeBytes { try d.decode($0) } == nil)
        #expect(!d.isReusable)
    }
}

@Suite struct HTTP1EncodeTests {
    @Test func responseFraming() throws {
        var e = HTTP1ResponseEncoder()
        // No length given: chunked.
        let chunked = try encoded { b in
            try e.encodePart(.head(HTTPResponseHead(status: 200, fields: ["content-type": "text/plain"])), into: &b)
            try e.encodePart(.body(Array("hello".utf8)), into: &b)
            try e.encodePart(.body([]), into: &b)
            try e.encodePart(.end(["x-sum": "1"]), into: &b)
        }
        #expect(chunked == "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nx-sum: 1\r\n\r\n")
        // And it decodes back.
        let back = try parts(HTTP1ResponseDecoder(), chunked)
        #expect(back[1] == .body(Array("hello".utf8)))
        #expect(back[2] == .end(["x-sum": "1"]))

        let fixed = try encoded { b in
            try e.encodePart(.head(HTTPResponseHead(status: 404, fields: ["content-length": "2"])), into: &b)
            try e.encodePart(.body(Array("no".utf8)), into: &b)
            try e.encodePart(.end(nil), into: &b)
        }
        #expect(fixed == "HTTP/1.1 404 Not Found\r\ncontent-length: 2\r\n\r\nno")

        // HTTP/1.0 has no chunked: the close ends the body.
        let old = try encoded { b in
            try e.encodePart(.head(HTTPResponseHead(status: 200, version: .http1_0)), into: &b)
            try e.encodePart(.body(Array("x".utf8)), into: &b)
            try e.encodePart(.end(nil), into: &b)
        }
        #expect(old == "HTTP/1.0 200 OK\r\nconnection: close\r\n\r\nx")
    }

    @Test func responseRefusals() {
        var e = HTTP1ResponseEncoder()
        var b = IOBuffer(capacity: 256)
        // Too many or too few bytes for the Content-Length.
        #expect(throws: HTTP1Error.contentLengthMismatch) {
            try e.encodePart(.head(HTTPResponseHead(status: 200, fields: ["content-length": "1"])), into: &b)
            try e.encodePart(.body([1, 2]), into: &b)
        }
        #expect(throws: HTTP1Error.contentLengthMismatch) {
            try e.encodePart(.head(HTTPResponseHead(status: 200, fields: ["content-length": "3"])), into: &b)
            try e.encodePart(.body([1, 2]), into: &b)
            try e.encodePart(.end(nil), into: &b)
        }
        // A field can't smuggle in another field or a body.
        #expect(throws: HTTP1Error.invalidField) {
            try e.encodePart(.head(HTTPResponseHead(status: 200, fields: ["x": "a\r\nset-cookie: evil"])), into: &b)
        }
        #expect(throws: HTTP1Error.invalidField) {
            try e.encodePart(.head(HTTPResponseHead(status: 200, fields: ["bad name": "a"])), into: &b)
        }
        // No body after HEAD, 204 or 304.
        e.requestReceived(.head)
        #expect(throws: HTTP1Error.bodyNotAllowed) {
            try e.encodePart(.head(HTTPResponseHead(status: 200, fields: ["content-length": "5"])), into: &b)
            try e.encodePart(.body([1]), into: &b)
        }
        #expect(throws: HTTP1Error.bodyNotAllowed) {
            try e.encodePart(.head(HTTPResponseHead(status: 204)), into: &b)
            try e.encodePart(.body([1]), into: &b)
        }
    }

    @Test func requests() throws {
        var e = HTTP1RequestEncoder()
        let get = try encoded { b in
            try e.encodePart(.head(HTTPRequestHead(target: "/x?y=1", fields: ["host": "h"])), into: &b)
            try e.encodePart(.end(nil), into: &b)
        }
        #expect(get == "GET /x?y=1 HTTP/1.1\r\nhost: h\r\n\r\n")
        let post = try encoded { b in
            try e.encodePart(.head(HTTPRequestHead(method: .post, target: "/", fields: ["host": "h"])), into: &b)
            try e.encodePart(.body(Array("abc".utf8)), into: &b)
            try e.encodePart(.end(nil), into: &b)
        }
        #expect(post == "POST / HTTP/1.1\r\nhost: h\r\ntransfer-encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n")
        // And the server's decoder reads it back.
        #expect(try parts(HTTP1RequestDecoder(), post)[1] == .body(Array("abc".utf8)))
        var b = IOBuffer(capacity: 64)
        #expect(throws: HTTP1Error.invalidField) {
            try e.encodePart(.head(HTTPRequestHead(target: "/a b")), into: &b)
        }
        #expect(throws: HTTP1Error.bodyNotAllowed) {
            try e.encodePart(.head(HTTPRequestHead(target: "/")), into: &b)
            try e.encodePart(.body([1]), into: &b)
        }
        #expect(throws: HTTP1Error.lengthRequired) {
            try e.encodePart(.head(HTTPRequestHead(method: .post, target: "/", version: .http1_0)), into: &b)
        }
    }

    @Test func fields() {
        var f: HTTPFields = ["Accept": "a", "X-Y": "1"]
        f.append(name: "accept", value: "b")
        #expect(f.values(for: "ACCEPT") == ["a", "b"])
        f["accept"] = "c"
        #expect(f.values(for: "accept") == ["c"])
        #expect(f.map(\.name) == ["X-Y", "accept"])
        f["x-y"] = nil
        #expect(f.count == 1)
        f.append(name: "Connection", value: "keep-alive, Upgrade")
        #expect(f.containsToken("upgrade", in: "connection"))
        #expect(!f.containsToken("up", in: "connection"))
        #expect(f == ["ACCEPT": "c", "connection": "keep-alive, Upgrade"])
    }
}

@Suite struct HTTP1ServerTests {
    /// Keep-alive, bodies both ways, HEAD, then a close.
    @Test func serveAndSend() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        try rt.block {
            let pair = duplex()
            let server = rt.spawn(with: pair.second) { stream async -> Int in
                var served = 0
                try? await HTTP1Server.serve(stream) { request in
                    served += 1
                    switch request.head.path {
                    case "/echo": return HTTPResponse(fields: ["content-type": "application/octet-stream"], body: request.body)
                    case "/fail": throw CancellationError()
                    default: return HTTPResponse(body: "\(request.head.method) \(request.head.target)")
                    }
                }
                return served
            }
            var client = HTTP1Client(pair.first)
            let hello = try await client.send(HTTPRequest(target: "/hello?x=1", fields: ["host": "vega.test"]))
            #expect(hello.status == 200)
            #expect(hello.text == "GET /hello?x=1")
            #expect(hello.head.fields["content-length"] == "14")

            let big = (0..<100_000).map { UInt8(truncatingIfNeeded: $0) }
            let echo = try await client.send(HTTPRequest(method: .post, target: "/echo", fields: ["host": "vega.test"], body: big))
            #expect(echo.body == big)

            let head = try await client.send(HTTPRequest(method: .head, target: "/hello", fields: ["host": "vega.test"]))
            #expect(head.body.isEmpty)
            #expect(head.head.fields["content-length"] == "11")

            let failed = try await client.send(HTTPRequest(target: "/fail", fields: ["host": "vega.test"]))
            #expect(failed.status == 500)

            let reusable = client.isReusable
            #expect(reusable)
            let last = try await client.send(HTTPRequest(target: "/bye", fields: ["host": "vega.test", "connection": "close"]))
            #expect(last.text == "GET /bye")
            #expect(last.head.fields["connection"] == "close")
            let done = !client.isReusable
            #expect(done)
            #expect(await server.value == 5)
        }
    }

    /// Bad requests get their status and a close; Expect gets a 100 first.
    @Test func refusalsAndContinue() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let configuration = HTTP1Configuration(maxBodySize: 10)
        func exchange(_ text: String) async throws -> String {
            let pair = duplex()
            rt.spawn(with: pair.second) { stream async in
                try? await HTTP1Server.serve(stream, configuration: configuration) { request in
                    HTTPResponse(body: request.body)
                }
            }
            var request = IOBuffer(capacity: 1024)
            request.append(text)
            try await pair.first.write(request)
            var reply = IOBuffer(capacity: 4096)
            while try await pair.first.read(into: &reply) > 0 {}
            return reply.string
        }
        try rt.block {
            let smuggled = try await exchange("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n")
            #expect(smuggled == "HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            let large = try await exchange("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\n")
            #expect(large.hasPrefix("HTTP/1.1 413 "))
            let chunkedLarge = try await exchange("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nabcdef\r\n6\r\nabcdef\r\n0\r\n\r\n")
            #expect(chunkedLarge.hasPrefix("HTTP/1.1 413 "))
            let continued = try await exchange("POST / HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            #expect(continued == "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
            let old = try await exchange("GET / HTTP/1.0\r\n\r\n")
            #expect(old == "HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
        }
    }

    /// The codecs through `FramedRead`, which must offer a decoder an
    /// empty buffer for the end of a message without a body.
    @Test func framedRead() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let got = try rt.block { () async throws -> [HTTPRequestPart] in
            let pair = duplex()
            var text = IOBuffer(capacity: 256)
            text.append("GET /a HTTP/1.1\r\nHost: x\r\n\r\n")
            try await pair.first.write(text)
            var framed = FramedRead(reading: pair.second, decoder: HTTP1RequestDecoder())
            var got: [HTTPRequestPart] = []
            while got.count < 2, let part = try await framed.next() { got.append(part) }
            return got
        }
        #expect(got.count == 2)
        #expect(got.last == .end(nil))
    }

    /// On shutdown a request in progress is answered with a close, and an
    /// idle keep-alive connection ends at once.
    @Test func gracefulShutdown() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let signal = ShutdownToken()
        let entered = Notify(), release = Notify()
        try rt.block {
            let handler: @Sendable (HTTPRequest) async throws -> HTTPResponse = { request in
                if request.head.path == "/slow" {
                    entered.notifyOne()
                    await release.notifiedIgnoringCancellation()
                }
                return HTTPResponse(body: "ok")
            }
            let idle = duplex()
            let idleServer = rt.spawn(with: idle.second) { stream async -> Bool in
                (try? await HTTP1Server.serve(stream, shutdown: signal, handler)) != nil
            }
            let busy = duplex()
            let busyServer = rt.spawn(with: busy.second) { stream async -> Bool in
                (try? await HTTP1Server.serve(stream, shutdown: signal, handler)) != nil
            }
            var idleClient = HTTP1Client(idle.first)
            let first = try await idleClient.send(HTTPRequest(target: "/", fields: ["host": "x"]))
            #expect(first.text == "ok")
            #expect(first.head.fields["connection"] == nil)

            rt.spawn {
                try? await entered.notified()
                signal.trigger()
                release.notifyOne()
            }
            var busyClient = HTTP1Client(busy.first)
            let slow = try await busyClient.send(HTTPRequest(target: "/slow", fields: ["host": "x"]))
            #expect(slow.text == "ok")
            #expect(slow.head.fields["connection"] == "close")
            let reusable = busyClient.isReusable
            #expect(!reusable)
            #expect(await busyServer.value)
            #expect(await idleServer.value)
            let after = try? await idleClient.send(HTTPRequest(target: "/", fields: ["host": "x"]))
            #expect(after == nil)
        }
    }

    /// TCPServer's shutdown triggers the signal it was given, so an idle
    /// keep-alive client doesn't hold shutdown for the grace period.
    @Test func serverShutdownClosesIdleConnections() throws {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        let (elapsed, after) = try rt.block { () async throws -> (Duration, HTTPResponse?) in
            let signal = ShutdownToken()
            let server = try TCPServer.bind(host: "127.0.0.1", port: 0,
                                            configuration: .init(shutdownToken: signal)) { conn in
                try? await HTTP1Server.serve(conn, shutdown: signal) { _ in HTTPResponse(body: "ok") }
            }
            var client = HTTP1Client(try await TCPStream.connect(host: "127.0.0.1", port: server.port))
            let first = try await client.send(HTTPRequest(target: "/", fields: ["host": "x"]))
            #expect(first.text == "ok")
            let start = ContinuousClock.now
            await server.shutdown(gracePeriod: .seconds(10))
            let elapsed = start.duration(to: .now)
            return (elapsed, try? await client.send(HTTPRequest(target: "/", fields: ["host": "x"])))
        }
        #expect(elapsed < .seconds(5))
        #expect(after == nil)
    }

    @Test func overTCP() throws {
        let rt = Runtime(workers: 4)
        defer { rt.shutdown() }
        try rt.block {
            let listener = try TCPListener.bind(host: "127.0.0.1", port: 0)
            let port = listener.localPort
            rt.spawn(with: listener) { l async in
                while let conn = try? await l.accept() {
                    rt.spawn(with: conn) { conn async in
                        try? await HTTP1Server.serve(conn) { request in
                            HTTPResponse(body: Array(request.body.reversed()))
                        }
                    }
                }
            }
            for _ in 0..<3 {
                var client = HTTP1Client(try await TCPStream.connect(host: "127.0.0.1", port: port))
                for i in 0..<20 {
                    let body = Array(repeating: UInt8(i), count: i * 1000) + [1, 2, 3]
                    let r = try await client.send(HTTPRequest(method: .put, target: "/\(i)", fields: ["host": "local"], body: body))
                    #expect(r.body == body.reversed())
                }
            }
        }
    }
}
