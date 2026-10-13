import Testing
import Vega
import VegaIO
import VegaHTTP1
import VegaHTTP2
import VegaExtras
import VegaTest

private let text = Array(String(repeating: "vega compresses what the client asked for. ", count: 400).utf8)

private func request(_ acceptEncoding: String?) -> HTTPRequestHead {
    var fields: HTTPFields = ["host": "x"]
    if let acceptEncoding { fields["accept-encoding"] = acceptEncoding }
    return HTTPRequestHead(method: .get, target: "/", fields: fields)
}

private func page(_ fields: HTTPFields = ["content-type": "text/html; charset=utf-8"],
                  body: [UInt8] = text) -> HTTPResponse {
    HTTPResponse(fields: fields, body: body)
}

@Suite(.enabled(if: ContentCoding.gzip.canCompress, "no zlib here"))
struct CompressorTests {
    @Test func everyCodingRoundTrips() throws {
        for coding in ContentCoding.allCases where coding.canCompress {
            let packed = try Compressor.compress(text, coding)
            #expect(packed.count < text.count / 10, "\(coding)")
            #expect(try Decompressor.decompress(packed, coding) == text, "\(coding)")
        }
    }

    /// Streamed in pieces with flushes, read back in pieces of other sizes.
    @Test func streamsAndFlushes() throws {
        for coding in ContentCoding.allCases where coding.canCompress {
            var c = try Compressor(coding)
            var d = try Decompressor(coding)
            var packed: [UInt8] = []
            var seen: [UInt8] = []
            for start in stride(from: 0, to: text.count, by: 1000) {
                let piece = Array(text[start..<min(start + 1000, text.count)])
                let out = try c.compress(piece, flush: true)
                packed += out
                // A flush makes everything so far readable.
                seen += try d.decompress(out)
                #expect(seen == Array(text[0..<min(start + 1000, text.count)]), "\(coding)")
            }
            let tail = try c.finish()
            packed += tail
            seen += try d.decompress(tail)
            try d.finish()
            #expect(seen == text)

            var bytewise = try Decompressor(coding)
            var again: [UInt8] = []
            for b in packed { again += try bytewise.decompress([b]) }
            try bytewise.finish()
            #expect(again == text, "\(coding)")
        }
    }

    @Test func deflateIsZlibOrRaw() throws {
        let hello = Array("hello".utf8)
        let zlib: [UInt8] = [0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x06, 0x2c, 0x02, 0x15]
        let raw: [UInt8] = [0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00]
        #expect(try Decompressor.decompress(zlib, .deflate) == hello)
        #expect(try Decompressor.decompress(raw, .deflate) == hello)
        // Our own deflate is the zlib format.
        #expect(try Compressor.compress(hello, .deflate).first == 0x78)
    }

    @Test func gzipMembersFollowOneAnother() throws {
        let first = Array("first ".utf8), second = Array("second".utf8)
        let joined = try Compressor.compress(first, .gzip) + Compressor.compress(second, .gzip)
        #expect(try Decompressor.decompress(joined, .gzip) == first + second)
    }

    @Test func limitsAndBadInput() throws {
        let zeros = [UInt8](repeating: 0, count: 1 << 20)
        let bomb = try Compressor.compress(zeros, .gzip)
        #expect(bomb.count < 4096)
        #expect(throws: CompressionError.tooLarge) { try Decompressor.decompress(bomb, .gzip, limit: 64 * 1024) }
        #expect(try Decompressor.decompress(bomb, .gzip, limit: 1 << 20).count == 1 << 20)

        let packed = try Compressor.compress(text, .gzip)
        #expect(throws: CompressionError.invalidData) { try Decompressor.decompress(Array(packed.dropLast(10)), .gzip) }
        var corrupt = packed
        corrupt[20] ^= 0xff
        corrupt[21] ^= 0xff
        #expect(throws: CompressionError.invalidData) { try Decompressor.decompress(corrupt, .gzip) }
        #expect(throws: CompressionError.invalidData) { try Decompressor.decompress(packed + [1, 2, 3], .gzip) }
        #expect(throws: CompressionError.invalidData) { try Decompressor.decompress([0x78], .deflate) }
        #expect(throws: CompressionError.invalidData) { try Decompressor.decompress(Array("not gzip".utf8), .gzip) }
    }
}

@Suite(.enabled(if: ContentCoding.gzip.canCompress, "no zlib here"))
struct HTTPCompressionTests {
    @Test func negotiation() {
        let all = HTTPCompression(codings: [.br, .zstd, .gzip, .deflate])
        let gzipOnly = HTTPCompression(codings: [.gzip])
        // Unrated codings go by the server's order.
        let first = [ContentCoding.br, .zstd, .gzip].first { $0.canCompress }
        #expect(all.coding(for: request("gzip, br, zstd")) == first)
        // Weights beat the order; zero refuses.
        #expect(all.coding(for: request("br;q=0.5, gzip")) == .gzip)
        #expect(all.coding(for: request("gzip;q=0, deflate;q=0.1")) == .deflate)
        #expect(all.coding(for: request("br;q=0.000")) == nil)
        // The wildcard covers what isn't named.
        #expect(gzipOnly.coding(for: request("*;q=0.3")) == .gzip)
        #expect(gzipOnly.coding(for: request("*, gzip;q=0")) == nil)
        // Absent, empty, identity, malformed.
        #expect(all.coding(for: request(nil)) == nil)
        #expect(all.coding(for: request("")) == nil)
        #expect(all.coding(for: request("identity")) == nil)
        #expect(gzipOnly.coding(for: request("gzip;q=high")) == nil)
        #expect(gzipOnly.coding(for: request("gzip;q=2")) == nil)
        // Case, whitespace, aliases.
        #expect(gzipOnly.coding(for: request(" GZIP ; Q=0.7 ")) == .gzip)
        #expect(gzipOnly.coding(for: request("x-gzip")) == .gzip)
    }

    @Test func compressibleTypes() {
        #expect(HTTPCompression.isCompressible(contentType: "text/html; charset=utf-8"))
        #expect(HTTPCompression.isCompressible(contentType: "application/json"))
        #expect(HTTPCompression.isCompressible(contentType: "application/problem+json"))
        #expect(HTTPCompression.isCompressible(contentType: "image/svg+xml"))
        #expect(HTTPCompression.isCompressible(contentType: "TEXT/CSS"))
        #expect(!HTTPCompression.isCompressible(contentType: "text/event-stream"))
        #expect(!HTTPCompression.isCompressible(contentType: "image/png"))
        #expect(!HTTPCompression.isCompressible(contentType: "application/octet-stream"))
        #expect(!HTTPCompression.isCompressible(contentType: ""))
    }

    @Test func whatGetsCompressed() throws {
        let compression = HTTPCompression(codings: [.gzip])
        var r = page(["content-type": "text/html", "etag": "\"v1\"", "content-length": "\(text.count)"])
        compression.compress(&r, for: request("gzip"))
        #expect(r.head.fields["content-encoding"] == "gzip")
        #expect(r.head.fields["vary"] == "accept-encoding")
        #expect(r.head.fields["etag"] == "W/\"v1\"")
        #expect(r.head.fields["content-length"] == nil)
        #expect(try Decompressor.decompress(r.body, .gzip) == text)

        // Not asked for: as it was, but still Vary.
        var plain = page()
        compression.compress(&plain, for: request(nil))
        #expect(plain.body == text)
        #expect(plain.head.fields["content-encoding"] == nil)
        #expect(plain.head.fields["vary"] == "accept-encoding")

        // Left alone: too small, the wrong type, already encoded, no-transform, partial.
        let untouched: [HTTPResponse] = [
            page(body: Array("short".utf8)),
            page(["content-type": "image/png"]),
            page(["content-type": "text/plain", "content-encoding": "br"]),
            page(["content-type": "text/plain", "cache-control": "public, no-transform"]),
            HTTPResponse(status: 206, fields: ["content-type": "text/plain", "content-range": "bytes 0-9/100"], body: text),
        ]
        for var response in untouched {
            let before = response.body
            compression.compress(&response, for: request("gzip"))
            #expect(response.body == before)
            #expect(response.head.fields.values(for: "content-encoding").count <= 1)
        }
        // A Vary that covers it already isn't repeated.
        var varied = page(["content-type": "text/plain", "vary": "Accept-Encoding, Origin"])
        compression.compress(&varied, for: request("gzip"))
        #expect(varied.head.fields.values(for: "vary") == ["Accept-Encoding, Origin"])
    }

    @Test func clientSideDecoding() throws {
        var r = HTTPResponse(fields: ["content-encoding": "gzip, gzip", "content-length": "1"],
                             body: try Compressor.compress(Compressor.compress(text, .gzip), .gzip))
        try HTTPCompression.decompress(&r)
        #expect(r.body == text)
        #expect(r.head.fields["content-encoding"] == nil)
        #expect(r.head.fields["content-length"] == String(text.count))

        var unknown = HTTPResponse(fields: ["content-encoding": "compress"], body: [1, 2])
        #expect(throws: CompressionError.unavailable("compress")) { try HTTPCompression.decompress(&unknown) }

        #expect(HTTPCompression.acceptEncoding.hasSuffix("gzip, deflate"))
        #expect(HTTPCompression.acceptEncoding.contains("br") == ContentCoding.br.canDecompress)
    }

    /// End to end: HTTP/1 and HTTP/2 servers with a compressing handler.
    @Test func overBothServers() throws {
        let rt = Runtime(workers: 2)
        defer { rt.shutdown() }
        let handler = HTTPCompression(codings: [.gzip]).wrap { _ in page() }
        try rt.block {
            let one = duplex()
            rt.spawn(with: one.second) { stream async in try? await HTTP1Server.serve(stream, handler) }
            var client = HTTP1Connection(one.first)
            var r1 = try await client.send(HTTPRequest(target: "/", fields: ["host": "x", "accept-encoding": "gzip"]))
            #expect(r1.head.fields["content-encoding"] == "gzip")
            #expect(Int(r1.head.fields["content-length"] ?? "") == r1.body.count)
            try HTTPCompression.decompress(&r1)
            #expect(r1.body == text)

            let two = duplex(capacity: 256 * 1024)
            rt.spawn(with: two.second) { stream async in
                let halves = stream.split()
                try? await HTTP2Server.serve(reader: halves.reader, writer: halves.writer, handler)
            }
            let halves = two.first.split()
            var r2 = try await HTTP2Client.withConnection(reader: halves.reader, writer: halves.writer,
                                                          scheme: "http", authority: "x") { client in
                try await client.send(HTTPRequest(target: "/", fields: ["accept-encoding": "gzip"]))
            }
            #expect(r2.head.fields["content-encoding"] == "gzip")
            try HTTPCompression.decompress(&r2)
            #expect(r2.body == text)
        }
    }
}
