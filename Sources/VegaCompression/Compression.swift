import CVegaCompress
import VegaHTTP

/// A content coding (RFC 9110 section 8.4.1). gzip and deflate come from
/// zlib (the system's; on Windows, a vendored copy), so they are always
/// there; brotli and zstd from the system's shared libraries, when it has
/// them (not on Windows yet).
public enum ContentCoding: String, Sendable, CaseIterable {
    case gzip
    /// The zlib format. Decoding also takes raw deflate, which some servers
    /// send under this name.
    case deflate
    case br
    case zstd

    /// The coding a Content-Encoding or Accept-Encoding token names
    /// (`x-gzip` is gzip), ignoring case.
    public init?(token: some StringProtocol) {
        switch token.lowercased() {
        case "gzip", "x-gzip": self = .gzip
        case "deflate": self = .deflate
        case "br": self = .br
        case "zstd": self = .zstd
        default: return nil
        }
    }

    var codec: Int32 {
        switch self {
        case .gzip: CV_CODEC_GZIP
        case .deflate: CV_CODEC_DEFLATE
        case .br: CV_CODEC_BR
        case .zstd: CV_CODEC_ZSTD
        }
    }

    /// Whether this process can compress into it.
    public var canCompress: Bool { cv_enc_available(codec) == 1 }
    /// Whether this process can decompress it.
    public var canDecompress: Bool { cv_dec_available(codec) == 1 }
}

/// Why compressing or decompressing failed.
public enum CompressionError: Error, Hashable, Sendable, CustomStringConvertible {
    /// No codec for this coding in this process.
    case unavailable(String)
    /// The bytes aren't what the coding produces, or stop before its end.
    case invalidData
    /// The decompressed bytes would pass the limit.
    case tooLarge
    /// The codec failed (out of memory).
    case failed

    public var description: String {
        switch self {
        case .unavailable(let coding): "no codec for \(coding)"
        case .invalidData: "invalid compressed data"
        case .tooLarge: "decompressed data over the limit"
        case .failed: "compression failed"
        }
    }
}

/// Size of the scratch space codecs write into, before it's appended.
private let chunkSize = 16 * 1024

/// Compresses a stream of bytes into one coding: feed it pieces, flush
/// when the peer must be able to read everything so far, and finish.
///
/// ```swift
/// var gzip = try Compressor(.gzip)
/// var out = try gzip.compress(part1)
/// out += try gzip.compress(part2)
/// out += try gzip.finish()
/// ```
public struct Compressor: ~Copyable {
    public let coding: ContentCoding
    private let raw: UnsafeMutableRawPointer
    private let scratch = UnsafeMutableRawPointer.allocate(byteCount: chunkSize, alignment: 16)

    /// `level` is the codec's own scale (gzip 1-9, brotli 1-11, zstd 1-19);
    /// nil picks one for compressing while a client waits: gzip 5,
    /// brotli 4, zstd 3.
    public init(_ coding: ContentCoding, level: Int? = nil) throws(CompressionError) {
        guard let raw = cv_enc_new(coding.codec, Int32(clamping: level ?? 0)) else {
            scratch.deallocate()
            throw coding.canCompress ? .failed : .unavailable(coding.rawValue)
        }
        self.coding = coding
        self.raw = raw
    }

    deinit {
        cv_enc_free(raw)
        scratch.deallocate()
    }

    /// Compress `input`, appending what comes out to `output`. With
    /// `flush`, everything so far is written out decodable.
    public mutating func compress(_ input: UnsafeRawBufferPointer, flush: Bool = false,
                                  into output: inout [UInt8]) throws(CompressionError) {
        try run(input, flush ? CV_ENC_FLUSH : CV_ENC_CONTINUE, into: &output)
    }

    public mutating func compress(_ input: [UInt8], flush: Bool = false) throws(CompressionError) -> [UInt8] {
        var output: [UInt8] = []
        try input.withBytes { b throws(CompressionError) in try compress(b, flush: flush, into: &output) }
        return output
    }

    /// End the stream, appending its last bytes to `output`.
    public mutating func finish(into output: inout [UInt8]) throws(CompressionError) {
        try run(UnsafeRawBufferPointer(start: nil, count: 0), CV_ENC_FINISH, into: &output)
    }

    public mutating func finish() throws(CompressionError) -> [UInt8] {
        var output: [UInt8] = []
        try finish(into: &output)
        return output
    }

    /// `input` compressed whole.
    public static func compress(_ input: [UInt8], _ coding: ContentCoding,
                                level: Int? = nil) throws(CompressionError) -> [UInt8] {
        var c = try Compressor(coding, level: level)
        var output: [UInt8] = []
        output.reserveCapacity(input.count / 4 + 64)
        try input.withBytes { b throws(CompressionError) in
            try c.run(b, CV_ENC_FINISH, into: &output)
        }
        return output
    }

    private mutating func run(_ input: UnsafeRawBufferPointer, _ mode: Int32,
                              into output: inout [UInt8]) throws(CompressionError) {
        let base = input.baseAddress?.assumingMemoryBound(to: UInt8.self)
        var offset = 0
        while true {
            var consumed = 0, produced = 0
            let rc = cv_enc_run(raw, base.map { $0 + offset }, input.count - offset, mode,
                                scratch.assumingMemoryBound(to: UInt8.self), chunkSize, &consumed, &produced)
            offset += consumed
            if produced > 0 { output.append(contentsOf: UnsafeRawBufferPointer(start: scratch, count: produced)) }
            if rc < 0 { throw .failed }
            if rc == 0 && offset == input.count { return }
        }
    }
}

/// Decompresses a stream of bytes in one coding, holding the output to a
/// limit as it grows: a few kilobytes of gzip can inflate to gigabytes.
///
/// ```swift
/// var gunzip = try Decompressor(.gzip, limit: 64 << 20)
/// var body = try gunzip.decompress(part1)
/// body += try gunzip.decompress(part2)
/// try gunzip.finish()   // throws if the stream stopped short
/// ```
public struct Decompressor: ~Copyable {
    public let coding: ContentCoding
    /// The most bytes it will produce in all. There is no default: pass
    /// what the caller can hold (`.max` only for trusted input).
    public let limit: Int
    /// Whether the compressed stream has ended.
    public private(set) var isFinished = false
    private var produced = 0
    /// Input the codec couldn't take yet (deflate's first byte alone).
    private var held: [UInt8] = []
    private let raw: UnsafeMutableRawPointer
    private let scratch = UnsafeMutableRawPointer.allocate(byteCount: chunkSize, alignment: 16)

    public init(_ coding: ContentCoding, limit: Int) throws(CompressionError) {
        guard let raw = cv_dec_new(coding.codec) else {
            scratch.deallocate()
            throw coding.canDecompress ? .failed : .unavailable(coding.rawValue)
        }
        self.coding = coding
        self.limit = limit
        self.raw = raw
    }

    deinit {
        cv_dec_free(raw)
        scratch.deallocate()
    }

    /// Decompress `input`, appending what comes out to `output`. Bytes
    /// after the end of the compressed stream are invalid.
    public mutating func decompress(_ input: UnsafeRawBufferPointer,
                                    into output: inout [UInt8]) throws(CompressionError) {
        if held.isEmpty {
            try run(input, into: &output)
        } else {
            let joined = held + Array(input)
            held = []
            try joined.withBytes { b throws(CompressionError) in try run(b, into: &output) }
        }
    }

    public mutating func decompress(_ input: [UInt8]) throws(CompressionError) -> [UInt8] {
        var output: [UInt8] = []
        try input.withBytes { b throws(CompressionError) in try decompress(b, into: &output) }
        return output
    }

    /// Check the stream came to its end: throws `.invalidData` if it stopped
    /// short.
    public func finish() throws(CompressionError) {
        guard isFinished else { throw .invalidData }
    }

    /// `input` decompressed whole: it must hold the stream, end and all.
    public static func decompress(_ input: [UInt8], _ coding: ContentCoding,
                                  limit: Int) throws(CompressionError) -> [UInt8] {
        var d = try Decompressor(coding, limit: limit)
        let output = try d.decompress(input)
        try d.finish()
        return output
    }

    private mutating func run(_ input: UnsafeRawBufferPointer, into output: inout [UInt8]) throws(CompressionError) {
        guard !isFinished else {
            if input.isEmpty { return }
            throw .invalidData
        }
        let base = input.baseAddress?.assumingMemoryBound(to: UInt8.self)
        var offset = 0
        while true {
            var consumed = 0, made = 0
            let rc = cv_dec_run(raw, base.map { $0 + offset }, input.count - offset,
                                scratch.assumingMemoryBound(to: UInt8.self), chunkSize, &consumed, &made)
            offset += consumed
            if made > 0 {
                guard made <= limit - produced else { throw .tooLarge }
                produced += made
                output.append(contentsOf: UnsafeRawBufferPointer(start: scratch, count: made))
            }
            switch rc {
            case 2:
                isFinished = true
                guard offset == input.count else { throw .invalidData }
                return
            case 1:
                continue
            case 0:
                if offset < input.count {
                    if consumed == 0 && made == 0 {
                        // Taken later, with more after it.
                        held = Array(UnsafeRawBufferPointer(rebasing: input[offset...]))
                        return
                    }
                    continue
                }
                return
            default:
                throw .invalidData
            }
        }
    }
}

/// Content codings for whole HTTP messages: compressing responses for the
/// clients that accept it, and undoing a response's coding for a client.
///
/// ```swift
/// let compression = HTTPCompression()
/// try await HTTP1Server.serve(conn, compression.wrap { request in
///     HTTPResponse(fields: ["content-type": "text/html"], body: page)
/// })
/// ```
///
/// A response is compressed only when it's text-like (by Content-Type),
/// at least `minimumSize` long, not already encoded, not partial, and not
/// marked `Cache-Control: no-transform`. Such a response says
/// `Vary: Accept-Encoding` whether or not this client got it compressed,
/// so caches keep the copies apart; a strong ETag on a compressed body is
/// sent weak (RFC 9110 section 8.8.3.3).
public struct HTTPCompression: Sendable {
    /// The codings to offer, best first; ones this process lacks are skipped.
    /// A client's weights decide first, this order breaks ties.
    public var codings: [ContentCoding]
    /// Shorter bodies go out as they are: the coding's framing would be
    /// most of them.
    public var minimumSize: Int

    public init(codings: [ContentCoding] = [.br, .zstd, .gzip], minimumSize: Int = 1024) {
        self.codings = codings
        self.minimumSize = minimumSize
    }

    /// The coding to answer `request` with: the one its Accept-Encoding
    /// weighs highest among `codings`, or nil for none.
    public func coding(for request: HTTPRequestHead) -> ContentCoding? {
        let header = request.fields.values(for: "accept-encoding")
        guard !header.isEmpty else { return nil }
        let weights = Self.weights(header.joined(separator: ","))
        var best: ContentCoding?
        var bestWeight = 0
        for coding in codings where coding.canCompress {
            let w = weights[coding.rawValue] ?? weights["*"] ?? 0
            if w > bestWeight {
                best = coding
                bestWeight = w
            }
        }
        return best
    }

    /// Compress `response`'s body for `request`, if both allow it.
    public func compress(_ response: inout HTTPResponse, for request: HTTPRequestHead) {
        let status = response.head.status
        let fields = response.head.fields
        guard status >= 200, status != 204, status != 206, status != 304,
              !fields.contains("content-range"), !fields.contains("content-encoding"),
              !fields.containsToken("no-transform", in: "cache-control"),
              let type = fields["content-type"], Self.isCompressible(contentType: type) else { return }
        // Compressible: the answer depends on Accept-Encoding from here on.
        if !fields.containsToken("accept-encoding", in: "vary") && !fields.containsToken("*", in: "vary") {
            response.head.fields.append(name: "vary", value: "accept-encoding")
        }
        guard response.body.count >= minimumSize, let coding = coding(for: request),
              let body = try? Compressor.compress(response.body, coding),
              body.count < response.body.count else { return }
        response.body = body
        response.head.fields["content-encoding"] = coding.rawValue
        // The server frames the new body.
        response.head.fields.remove("content-length")
        if let etag = fields["etag"], etag.hasPrefix("\"") {
            response.head.fields["etag"] = "W/" + etag
        }
    }

    /// `handler` with its responses compressed as `compress` does: for
    /// `HTTP1Server.serve` and `HTTP2Server.serve`.
    public func wrap(
        _ handler: @escaping @Sendable (HTTPRequest) async throws -> HTTPResponse
    ) -> @Sendable (HTTPRequest) async throws -> HTTPResponse {
        { [self] request in
            var response = try await handler(request)
            compress(&response, for: request.head)
            return response
        }
    }

    /// Whether a body of this media type is worth compressing: text, and the
    /// formats that are text in all but name. A list of what compresses, not
    /// of what doesn't, because compressing a JPEG spends CPU to grow it.
    /// `text/event-stream` is left out: an open stream of small writes,
    /// where a compressor holding them back is a delay the client sees.
    public static func isCompressible(contentType: String) -> Bool {
        let type = contentType.prefix { $0 != ";" && $0 != " " && $0 != "\t" }.lowercased()
        if type.hasPrefix("text/") { return type != "text/event-stream" }
        if type.hasSuffix("+json") || type.hasSuffix("+xml") { return true }
        return compressibleTypes.contains(type)
    }

    private static let compressibleTypes: Set<String> = [
        "application/json", "application/javascript", "application/x-javascript", "application/ecmascript",
        "application/xml", "application/wasm", "application/x-ndjson", "application/vnd.ms-fontobject",
        "font/ttf", "font/otf", "image/svg+xml", "image/x-icon", "image/bmp",
    ]

    /// Each coding's weight in thousandths (`q=0.5` is 500), by lowercased
    /// name; a malformed weight is 0, refusing the coding.
    static func weights(_ header: String) -> [String: Int] {
        var out: [String: Int] = [:]
        for item in header.split(separator: ",") {
            let parts = item.split(separator: ";")
            guard let first = parts.first else { continue }
            var name = first.trimmingCharacters(in: " \t").lowercased()
            if name == "x-gzip" {
                // An alias: the real name wins if both are given.
                if out["gzip"] != nil { continue }
                name = "gzip"
            }
            guard !name.isEmpty else { continue }
            var weight = 1000
            for param in parts.dropFirst() {
                let p = param.trimmingCharacters(in: " \t")
                if p.lowercased().hasPrefix("q=") { weight = qvalue(p.dropFirst(2)) }
            }
            out[name] = weight
        }
        return out
    }

    /// `0`, `0.5`, `1`, `1.000` in thousandths; anything else is 0.
    static func qvalue(_ s: Substring) -> Int {
        let chars = Array(s.utf8)
        guard let lead = chars.first, lead == UInt8(ascii: "0") || lead == UInt8(ascii: "1") else { return 0 }
        var value = lead == UInt8(ascii: "1") ? 1000 : 0
        if chars.count > 1 {
            guard chars[1] == UInt8(ascii: "."), chars.count <= 5 else { return 0 }
            var scale = 100
            for c in chars.dropFirst(2) {
                guard c >= UInt8(ascii: "0") && c <= UInt8(ascii: "9") else { return 0 }
                value += Int(c - UInt8(ascii: "0")) * scale
                scale /= 10
            }
        }
        return min(value, 1000)
    }

    // MARK: - Decoding, for clients

    /// An Accept-Encoding value naming what this process can decode.
    public static var acceptEncoding: String {
        [ContentCoding.zstd, .br, .gzip, .deflate].filter(\.canDecompress).map(\.rawValue).joined(separator: ", ")
    }

    /// Undo `response`'s Content-Encoding, last applied first, holding the
    /// body to `limit` bytes. The field goes, and a Content-Length is
    /// corrected.
    public static func decompress(_ response: inout HTTPResponse, limit: Int = 64 << 20) throws(CompressionError) {
        try decode(&response.head.fields, &response.body, limit: limit)
    }

    /// Undo a request's Content-Encoding (a server taking compressed
    /// uploads), as `decompress(_:limit:)` does for a response.
    public static func decompress(_ request: inout HTTPRequest, limit: Int = 64 << 20) throws(CompressionError) {
        try decode(&request.head.fields, &request.body, limit: limit)
    }

    private static func decode(_ fields: inout HTTPFields, _ body: inout [UInt8], limit: Int) throws(CompressionError) {
        let names = fields.values(for: "content-encoding")
            .flatMap { $0.split(separator: ",") }
            .map { $0.trimmingCharacters(in: " \t").lowercased() }
            .filter { !$0.isEmpty && $0 != "identity" }
        guard !names.isEmpty, !body.isEmpty else { return }
        var bytes = body
        for name in names.reversed() {
            guard let coding = ContentCoding(token: name), coding.canDecompress else { throw .unavailable(name) }
            bytes = try Decompressor.decompress(bytes, coding, limit: limit)
        }
        body = bytes
        fields.remove("content-encoding")
        if fields.contains("content-length") { fields["content-length"] = String(bytes.count) }
    }
}

extension Array where Element == UInt8 {
    /// `withUnsafeBytes`, keeping the error's type.
    fileprivate func withBytes<R>(_ body: (UnsafeRawBufferPointer) throws(CompressionError) -> R) throws(CompressionError) -> R {
        do {
            return try withUnsafeBytes { try body($0) }
        } catch {
            throw error as! CompressionError
        }
    }
}

extension StringProtocol {
    fileprivate func trimmingCharacters(in set: String) -> String {
        var s = Substring(self)
        while let c = s.first, set.contains(c) { s.removeFirst() }
        while let c = s.last, set.contains(c) { s.removeLast() }
        return String(s)
    }
}
